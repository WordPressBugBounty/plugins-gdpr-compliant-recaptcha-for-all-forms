<?php
/**
 * One-off migration of the LEGACY blocklist lines out of POW_PARAMETER_PATTERN
 * into the standalone POW_BLOCKED_VALUES option (PLAN-BLOCKLIST-TRENNUNG.md §3.3/
 * §3.4, AP5).
 *
 * Until this release, one option carried two different powers: field patterns
 * ({"_wpcf7":null} — "check submissions that look like this") and value lines
 * ({"*":"spammer@x.tld"} — "treat submissions carrying this value as spam right
 * away"). The blocklist is now its own option, in plain text, one value per line.
 * This class moves what is already stored, exactly once per installation.
 *
 * WHY IT RUNS OUTSIDE THE VERSION GATE, on every load, like
 * Credential_Cleanup::maybe_run(): the POW_VERSION gate in RCM_Main::activate()
 * fires only when RCM_Main::VERSION exceeds the stored version — i.e. once per
 * release, in exactly ONE request. That misses every installation whose gate has
 * already fired (the code below would then never run at all), and it cannot be
 * exercised locally either, because a dev container's stored version is already
 * current. An unconditional call with its own done-flag has neither problem. Once
 * finished, maybe_run() costs exactly one get_option() on an autoloaded option and
 * nothing else — no second read, no write, no query.
 *
 * WHAT "LOSS-FREE" MEANS HERE, and why the two halves are separated:
 *
 *  - WHICH LINE IS A BLOCK LINE is not decided here. blocked_value_of_line() asks
 *    Echo_Values::wildcard_values_from_lines() — the very function that has been
 *    READING these lines as blocklist entries all along. A second, "equivalent"
 *    rule would be the one construction error this migration cannot afford: judge
 *    one line too eagerly and the admin loses a monitoring pattern; judge one too
 *    conservatively and he loses a block. Only the raw VALUE is taken from the
 *    line directly (json_decode), because the reader returns it normalized and the
 *    stored line has to keep the admin's own spelling — normalization is a
 *    property of reading (Echo_Values::values_from_plaintext_lines()), not of
 *    storage.
 *  - EVERYTHING ELSE SURVIVES BYTE FOR BYTE. split_legacy_lines() returns the
 *    non-block lines unchanged, in their original order, with their original
 *    whitespace, including lines that are not valid JSON at all (they may well be
 *    an admin's notes) and including {"*":null} / {"*":123} / {"*":""}, which were
 *    never block lines to begin with. The rewritten option is the original minus
 *    the migrated lines, nothing else.
 *
 * The partitioning is a pure static function on purpose, so both properties are
 * directly unit-testable without WordPress — including the no-op proof for the
 * large majority of installations that never clicked a block button
 * (tests/unit/BlockedValuesMigrationTest.php). The WordPress glue below (three
 * options) is covered by tests/integration/cases/blocked-values-migration.mjs.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/detection.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Moves legacy {"*":"value"} lines from POW_PARAMETER_PATTERN to POW_BLOCKED_VALUES.
 */
final class Blocked_Values_Migration {

	/**
	 * Run the migration if it has not run yet.
	 *
	 * Called unconditionally from RCM_Main::activate() (i.e. on every load) and
	 * DELIBERATELY OUTSIDE its POW_VERSION gate — see the head docblock. After the
	 * first completed run this is one get_option() on an autoloaded option.
	 */
	public static function maybe_run(): void {
		if ( get_option( Option::POW_BLOCKED_VALUES_MIGRATED ) ) {
			return;
		}

		// (a) Read and partition.
		$pattern = (string) get_option( Option::POW_PARAMETER_PATTERN, '' );
		$split   = self::split_legacy_lines( $pattern );

		if ( count( $split['blocked'] ) > 0 ) {
			// THE ORDER OF THE NEXT TWO WRITES IS NOT NEGOTIABLE, and it is not a
			// style choice — do not "tidy" it into one step or swap it around.
			//
			// (b) The blocklist is written FIRST, (c) the pattern option loses the
			// migrated lines only afterwards. If the process dies between the two,
			// the value exists in BOTH options: harmless under the new semantics
			// (the blocklist blocks, the pattern line only monitors), and the next
			// load repeats the migration and cleans it up, because the done flag is
			// set last of all. The reverse order would have a window in which the
			// line is gone from the patterns and not yet in the blocklist — i.e. a
			// crash during that window would silently DELETE a block the operator
			// configured. There must be no code path on which a block disappears.
			self::append_blocked_values( $split['blocked'] );

			// (c) Now, and only now, the pattern option without the migrated lines.
			// Byte-identical to the original apart from those lines (see
			// split_legacy_lines()).
			update_option( Option::POW_PARAMETER_PATTERN, implode( "\n", $split['remaining'] ) );
		}
		// NO blocked lines: the pattern option is NOT touched at all — no
		// update_option(), no rewrite, not even an identical one. This is the normal
		// case on most installations, and a no-op has to be a real no-op (it must
		// not create an option row, bump an autoload flag, or invalidate a cache).

		// (d) Done last, so an interrupted run repeats instead of being lost.
		update_option( Option::POW_BLOCKED_VALUES_MIGRATED, 1, true );
	}

	/**
	 * Partition a raw POW_PARAMETER_PATTERN value into the blocklist values to
	 * migrate and the lines that stay behind.
	 *
	 * Pure — no options, no WordPress — and therefore the part that is directly
	 * unit-tested. Splitting on "\n" (and never re-joining anything but the
	 * untouched pieces) is what makes the "byte for byte" promise of the head
	 * docblock hold, CRLF included: a "\r" belongs to the line it terminates and
	 * travels with it into `remaining`.
	 *
	 * @param string $option_value Raw option value.
	 * @return array{blocked: string[], remaining: string[]} Migrated values (trimmed,
	 *         original spelling, de-duplicated) and the surviving lines, unchanged
	 *         and in order.
	 */
	public static function split_legacy_lines( string $option_value ): array {
		$blocked   = array();
		$seen      = array();
		$remaining = array();

		foreach ( explode( "\n", $option_value ) as $line ) {
			$value = self::blocked_value_of_line( $line );
			if ( null === $value ) {
				$remaining[] = $line;
				continue;
			}
			// De-duplicated on the NORMALIZED value, which is how both options are
			// read at runtime (Echo_Values::normalize_wildcard() = trim + lowercase).
			// Two lines differing only in case block exactly the same submissions, so
			// collapsing them loses nothing; the FIRST spelling is the one kept.
			$key = Echo_Values::normalize_wildcard( $value );
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;
			$blocked[]    = $value;
		}

		return array(
			'blocked'   => $blocked,
			'remaining' => $remaining,
		);
	}

	/**
	 * The blocklist value a single legacy line carries, or null when the line is
	 * not a block line and must stay in the pattern option.
	 *
	 * THE DECISION IS NOT MADE HERE. It is delegated verbatim to
	 * Echo_Values::wildcard_values_from_lines(), the function that has been reading
	 * these lines as blocklist entries since the feature existed: a single-entry
	 * JSON object under the key "*" with a STRING value that is non-empty after
	 * normalization. Everything that function ignores — field patterns, {"*":null},
	 * {"*":123}, {"*":""}, a two-key line like {"_wpcf7":null,"*":"x"}, broken JSON,
	 * free text — is by construction ignored here too, and stays.
	 *
	 * json_decode() is used only to take the value BACK OUT in the admin's own
	 * spelling: the reader above returns it lower-cased, and the stored line must
	 * not be. It runs on a line the reader has already accepted, so the shape is
	 * known; the emptiness guard is belt and braces (a value that normalizes to
	 * non-empty cannot trim to empty).
	 *
	 * @param string $line One raw line of the pattern option.
	 * @return string|null Trimmed value in its original spelling, or null.
	 */
	private static function blocked_value_of_line( string $line ): ?string {
		if ( 1 !== count( Echo_Values::wildcard_values_from_lines( array( $line ) ) ) ) {
			return null;
		}

		$decoded = json_decode( trim( $line ), true );
		if ( ! is_array( $decoded ) || ! isset( $decoded['*'] ) || ! is_string( $decoded['*'] ) ) {
			return null;
		}

		$value = trim( $decoded['*'] );
		return '' === $value ? null : $value;
	}

	/**
	 * Append migrated values to POW_BLOCKED_VALUES, skipping what is already there.
	 *
	 * APPEND, never replace: the option may already carry entries written by the
	 * one-click block buttons (Message_Page::block_value_callback()) or by hand, and
	 * this migration exists to add to that list, not to define it.
	 *
	 * The duplicate check uses Echo_Values::normalize_wildcard(), the same trim +
	 * lowercase the reader applies, so an entry that is already effective is not
	 * written a second time in a different spelling.
	 *
	 * @param string[] $values Values to append, in order.
	 */
	private static function append_blocked_values( array $values ): void {
		$stored = (string) get_option( Option::POW_BLOCKED_VALUES, '' );
		$lines  = '' === $stored ? array() : explode( "\n", $stored );

		$seen = array();
		foreach ( $lines as $line ) {
			$key = Echo_Values::normalize_wildcard( $line );
			if ( '' !== $key ) {
				$seen[ $key ] = true;
			}
		}

		$appended = false;
		foreach ( $values as $value ) {
			$key = Echo_Values::normalize_wildcard( $value );
			if ( '' === $key || isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;
			$lines[]      = $value;
			$appended     = true;
		}

		if ( $appended ) {
			update_option( Option::POW_BLOCKED_VALUES, implode( "\n", $lines ) );
		}
	}
}
