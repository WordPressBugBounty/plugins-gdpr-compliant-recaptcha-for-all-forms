<?php
/**
 * The admin-maintained list of LEARNED credential field names — pure logic.
 *
 * Why it exists: `Credential_Fields::is_password_key()` is a name heuristic, so a
 * password input whose name looks like nothing (`geheim`) is invisible to it. As
 * long as the plugin's JS runs, the `hashPWFields` marker still covers such a
 * field; posted WITHOUT the JS (no-JS login, hand-built body, minimal POST) the
 * value used to be stored in cleartext. This list is the third line: names the
 * admin has CONFIRMED denote a credential, checked ADDITIVELY next to the
 * heuristic — never mixed into its constants, so the JS-twin pinning of
 * `is_password_key()` (CredentialFieldsTest::test_heuristic_matches_js_twin)
 * keeps holding unchanged. The list deliberately has NO JS twin: on the JS path
 * the `input[type=password]` marker already covers the very same fields.
 *
 * Format decisions, each one a failure mode that was ruled out on purpose:
 *
 *  - EXACT PATH SEGMENT, case-insensitive — never a substring. A substring rule
 *    would turn a learned `pass` into a match for `passenger`: the error class
 *    the heuristic already avoids, and one that silently blanks real content.
 *  - NO `site:` PREFIX. A password field name is one everywhere, and the
 *    site-scoped syntax of POW_SKIP_FIELDS is a known silent failure source
 *    (entry typed, site string does not match, the protection never fires and
 *    nobody notices). Not site-scoping cannot fail silently — it can only be too
 *    broad, which is visible in the inbox as a `[redacted]` value.
 *  - PURELY NUMERIC NAMES REJECTED. `a[0]` is an array index, not a field name;
 *    learning `0` would redact every first element of every nested field.
 *
 * Also here (still pure, therefore unit-testable):
 *
 *  - the DISCREPANCY DETECTOR `candidates_from_marker_paths()`, which turns
 *    "the client marked a password field whose name neither the heuristic nor
 *    the list knows" into a suggestion — the name only, never a value;
 *  - `list_hash()` / `arm()`, the bookkeeping that lets Credential_Cleanup
 *    re-arm itself for the NEWLY learned names only (see that class).
 *
 * No WordPress dependencies → tests/unit/LearnedCredentialFieldsTest.php.
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
 * Parsing, matching and bookkeeping for the learned credential-field names.
 */
final class Learned_Credential_Fields {

	/** Separator used in persisted `rgd_attribute` paths (Stamp::generate_paths()). */
	private const PATH_SEPARATOR = '->';

	/** Longest accepted name. Matches the 191-char index prefix used on the table. */
	private const MAX_NAME_LENGTH = 190;

	/**
	 * Hard cap on the stored list. It is admin-maintained, so this is not a
	 * defence but a sanity bound: every entry costs one LIKE term in the
	 * retroactive cleanup and one lookup per persisted field.
	 */
	public const MAX_LIST_SIZE = 200;

	/**
	 * Names that carry the plugin's own diagnostics and must NEVER be proposed
	 * for learning.
	 *
	 * The proposal channel is fed from UNAUTHENTICATED request data: anybody can
	 * post a forged `hashPWFields` claiming `email` is a password field. An admin
	 * confirming that out of notice fatigue would blind their own inbox — the
	 * sender address would read `[redacted]`, which also kills the one-click
	 * block buttons and every false-positive diagnosis. Suppressed entirely
	 * rather than "shown cautiously": a name that must not be clicked has no
	 * business being rendered as a button.
	 *
	 * @var string[]
	 */
	private const DIAGNOSTIC_NAMES = array( 'email', 'name', 'subject', 'message' );

	/**
	 * Normalise one candidate name, or reject it.
	 *
	 * Total: any input shape is accepted and answered with null when it is not a
	 * usable field name.
	 *
	 * @param mixed $name Candidate name.
	 * @return string|null Lower-cased name, or null when unusable.
	 */
	public static function normalize_name( $name ): ?string {
		if ( ! is_scalar( $name ) ) {
			return null;
		}
		$value = strtolower( trim( (string) $name ) );
		if ( '' === $value || strlen( $value ) > self::MAX_NAME_LENGTH ) {
			return null;
		}
		// Line breaks would split one entry into two in the stored option; the path
		// separator would make a "name" that can never equal a single segment.
		if ( preg_match( '/[\r\n\t]/', $value ) || false !== strpos( $value, self::PATH_SEPARATOR ) ) {
			return null;
		}
		// Array index, not a field name — see the class docblock.
		if ( preg_match( '/^\d+$/', $value ) ) {
			return null;
		}
		return $value;
	}

	/**
	 * Parse the stored option value (one name per line) into normalised names.
	 *
	 * @param mixed $raw Raw option value.
	 * @return string[]
	 */
	public static function parse_list( $raw ): array {
		if ( ! is_string( $raw ) || '' === $raw ) {
			return array();
		}
		$names = array();
		$lines = preg_split( '/\r\n|\n|\r/', $raw, -1, PREG_SPLIT_NO_EMPTY );
		foreach ( (array) $lines as $line ) {
			$name = self::normalize_name( $line );
			if ( null !== $name && ! in_array( $name, $names, true ) ) {
				$names[] = $name;
			}
			if ( count( $names ) >= self::MAX_LIST_SIZE ) {
				break;
			}
		}
		return $names;
	}

	/**
	 * Serialise a name list back into the stored option value.
	 *
	 * @param string[] $names Names.
	 * @return string
	 */
	public static function to_lines( array $names ): string {
		return implode( "\n", $names );
	}

	/**
	 * Lookup set over normalised names (values are irrelevant, presence is not).
	 *
	 * @param string[] $names Names.
	 * @return array<string,bool>
	 */
	public static function index( array $names ): array {
		$out = array();
		foreach ( $names as $name ) {
			$normalized = self::normalize_name( $name );
			if ( null !== $normalized ) {
				$out[ $normalized ] = true;
			}
		}
		return $out;
	}

	/**
	 * Is this ONE path segment a learned credential name?
	 *
	 * Exact, case-insensitive, never a substring (see the class docblock).
	 *
	 * @param mixed              $segment Path segment / field key.
	 * @param array<string,bool> $index   Lookup set from index().
	 * @return bool
	 */
	public static function matches_segment( $segment, array $index ): bool {
		if ( 0 === count( $index ) ) {
			return false;
		}
		$normalized = self::normalize_name( $segment );
		return null !== $normalized && isset( $index[ $normalized ] );
	}

	/**
	 * Does a persisted `rgd_attribute` path contain a learned name?
	 *
	 * ANY segment matching makes the row a credential row — same rule as
	 * Credential_Fields::is_password_path(), because the stored attribute is the
	 * `->`-joined key chain of a nested field.
	 *
	 * @param string   $path  Persisted attribute path.
	 * @param string[] $names Learned names.
	 * @return bool
	 */
	public static function is_learned_path( string $path, array $names ): bool {
		$index = self::index( $names );
		if ( 0 === count( $index ) ) {
			return false;
		}
		foreach ( explode( self::PATH_SEPARATOR, $path ) as $segment ) {
			if ( self::matches_segment( $segment, $index ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Is this a name the plugin's own diagnostics depend on?
	 *
	 * @param mixed $name Candidate name.
	 * @return bool
	 */
	public static function is_diagnostic_name( $name ): bool {
		$normalized = self::normalize_name( $name );
		return null !== $normalized && in_array( $normalized, self::DIAGNOSTIC_NAMES, true );
	}

	/** @return string[] The diagnostic names, for UI copy and tests. */
	public static function diagnostic_names(): array {
		return self::DIAGNOSTIC_NAMES;
	}

	/**
	 * THE SIGNAL: marker paths whose segments no known rule recognises.
	 *
	 * `hashPWFields` names every `input[type=password]` the client found. A marker
	 * path that neither Credential_Fields::is_password_key() nor the learned list
	 * matches is the evidence "this form has a password field with an
	 * inconspicuous name" — derived from the NAME alone, never from a value. The
	 * submissions WITH JS thus supply the knowledge for the later ones WITHOUT it.
	 *
	 * The proposed name is the LEAF segment: for `user[account][geheim]` the outer
	 * segments are containers, only the leaf is the input's own name.
	 *
	 * @param array    $marker_paths Paths from Credential_Fields::marker_paths_from_raw().
	 *                               Shape-checked here, not assumed: the raw value is
	 *                               unauthenticated request data.
	 * @param string[] $learned      Currently learned names.
	 * @return string[] Candidate names, de-duplicated, never a diagnostic name.
	 */
	public static function candidates_from_marker_paths( array $marker_paths, array $learned ): array {
		$index      = self::index( $learned );
		$candidates = array();

		foreach ( $marker_paths as $segments ) {
			if ( ! is_array( $segments ) || 0 === count( $segments ) ) {
				continue;
			}

			$covered = false;
			foreach ( $segments as $segment ) {
				if ( Credential_Fields::is_password_key( $segment ) || self::matches_segment( $segment, $index ) ) {
					$covered = true;
					break;
				}
			}
			if ( $covered ) {
				continue;
			}

			$leaf = self::normalize_name( $segments[ count( $segments ) - 1 ] );
			if ( null === $leaf || self::is_diagnostic_name( $leaf ) ) {
				continue;
			}
			if ( ! in_array( $leaf, $candidates, true ) ) {
				$candidates[] = $leaf;
			}
		}

		return $candidates;
	}

	/**
	 * Fingerprint of a name list, order-independent.
	 *
	 * Credential_Cleanup stores this for the set it has already swept; a
	 * difference against the current list is what re-arms the retroactive run.
	 * The empty list hashes to '' so a ledger written before this feature existed
	 * (no hash key at all) compares equal and is not restarted.
	 *
	 * @param string[] $names Names.
	 * @return string
	 */
	public static function list_hash( array $names ): string {
		$normalized = array_values( array_unique( self::parse_list( self::to_lines( $names ) ) ) );
		if ( 0 === count( $normalized ) ) {
			return '';
		}
		sort( $normalized );
		return md5( implode( "\n", $normalized ) );
	}

	/**
	 * Decide which names a re-armed cleanup run has to sweep.
	 *
	 * Returns [ names-to-scan, new-seen-list ]:
	 *  - names-to-scan is the (chunk-limited) set of names present in the list but
	 *    NOT yet swept — a confirmation must not re-scan the whole table for names
	 *    that were already handled;
	 *  - new-seen-list is what the ledger records as swept afterwards. When there
	 *    is nothing new it becomes the current list verbatim, so REMOVING a name
	 *    settles the hash without triggering any scan at all.
	 *
	 * Termination: every call either returns an empty scan set (and then
	 * seen === learned as a set, i.e. the hashes match and no further arming
	 * happens) or consumes at least one new name from a finite list.
	 *
	 * @param string[] $learned   Current list.
	 * @param string[] $seen      Names already swept.
	 * @param int      $max_names Chunk size (bounds the LIKE terms of one query).
	 * @return array{0:string[],1:string[]}
	 */
	public static function arm( array $learned, array $seen, int $max_names ): array {
		$learned = self::parse_list( self::to_lines( $learned ) );
		$seen    = self::parse_list( self::to_lines( $seen ) );

		$seen_index = self::index( $seen );
		$delta      = array();
		foreach ( $learned as $name ) {
			if ( ! isset( $seen_index[ $name ] ) && ! in_array( $name, $delta, true ) ) {
				$delta[] = $name;
			}
		}

		if ( 0 === count( $delta ) ) {
			// Nothing new. Adopting the current list also drops names the admin has
			// removed, which is what makes the hash settle.
			return array( array(), $learned );
		}

		$chunk = array_slice( $delta, 0, max( 1, $max_names ) );
		$kept  = array();
		foreach ( $learned as $name ) {
			if ( isset( $seen_index[ $name ] ) ) {
				$kept[] = $name;
			}
		}

		return array( $chunk, array_values( array_unique( array_merge( $kept, $chunk ) ) ) );
	}
}
