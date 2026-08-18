<?php
/**
 * WHICH configured line is to blame for a verdict — the pure diagnosis half of
 * Overbroad_Pattern_Guard.
 *
 * SCHNITTLINIE (Welle 4, PLAN-DATEIGROESSE.md): class-overbroad-pattern-guard.php was
 * one file of 862 lines. It is split along the two audiences it serves:
 *   - class-overbroad-pattern-guard.php — the constants, the hooks, the pure screen
 *                                         classifiers, and the NOTICE half (record the
 *                                         marker, render it, dismiss it).
 *   - trait-overbroad-blame.php         — THIS file: blaming_lines() and the two helpers
 *                                         only it uses. Pure, no WordPress.
 *   - trait-overbroad-save-warning.php  — the SAVE ROUND TRIP on the settings page
 *                                         (confirmation, the two warning texts, the two
 *                                         confirmation blocks).
 *
 * TRAITS, NOT SECOND CLASSES. Every caller writes Overbroad_Pattern_Guard::… — the
 * settings save, the notice, Stamp — and tests/unit/OverbroadPatternMarkerWiringTest.php
 * pins the guard's members BY NAME against class-stamp.php. A trait is compiled into the
 * class, so the public surface, the visibilities and every one of those pins are exactly
 * what they were; the split is a move, not a rebuild.
 *
 * WHAT MUST NOT MOVE, and why it is worth saying out loud: the marker's ONE writer
 * (record_backend_block), ONE reader (render_notice) and ONE dismisser (handle_dismiss)
 * stay together in class-overbroad-pattern-guard.php. OverbroadPatternMarkerWiringTest
 * counts exactly one set_transient()/get_transient()/delete_transient() IN THAT FILE and
 * asserts the read sits inside render_notice(). Splitting those apart would leave that
 * guard counting a file that no longer holds the thing it guards.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse (Traits
// bekommen keine eigene Indexzeile; sie sind Teil ihrer Klasse).

/**
 * Deciding which configured line caused a backend block. Composed into
 * Overbroad_Pattern_Guard.
 */
trait Overbroad_Blame {

	/**
	 * Which configured pattern lines match this request — i.e. which of them is to blame
	 * for the verdict that just discarded a backend save.
	 *
	 * Deliberately NOT filtered through Pattern_Matcher::overbroad_lines() first: that one
	 * answers "would this line hit a WordPress CORE screen", and the case this marker is
	 * for explicitly includes a third-party plugin's admin form that carries a generic
	 * field. Blame is therefore decided against the request that actually happened, using
	 * the same line interpretation the live gate uses.
	 *
	 * BOTH SOURCES, because the gate has two. A field pattern (`{"email":null}`, from
	 * POW_PARAMETER_PATTERN) is answered by Pattern_Matcher::line_matches(); a BLOCKED
	 * VALUE (`@gmail.com`, from POW_BLOCKED_VALUES) is not, and cannot be — it is not a
	 * pattern at all. Asking only the field matcher left this half of the configuration
	 * invisible here: a profile save that a blocked sender domain really discards returned
	 * an EMPTY result, so no marker was written and the notice stayed silent on precisely
	 * the kind of entry a one-click "block this domain" writes. Measured before the fix.
	 *
	 * The value half is answered by asking the SAME functions that classify live —
	 * Echo_Values::partition_blocklist_lines() to read the line, then
	 * matches_wildcard_values() for a plain value or Pattern_Matcher::line_matches_blocked()
	 * for a RULE (see blocked_value_matches()) — never by a second rendering here. That is
	 * the construction
	 * principle spelled out in the Pattern_Matcher class docblock: a diagnosis built on a
	 * lookalike implementation is worse than none, because it eventually names the wrong
	 * line, and nothing exercises the two side by side.
	 *
	 * THE RESULT SAYS WHICH SOURCE, not just which text. Since the blocklist moved into
	 * its own option and its own settings group (PLAN-BLOCKLIST-TRENNUNG.md), "a pattern
	 * you configured" would be the wrong sentence for half the cases and would send the
	 * operator to a box that does not contain the named line.
	 *
	 * PURE DIAGNOSIS. This decides who is NAMED, never what is blocked — the cap, the
	 * de-duplication and the option order are unchanged, and no caller may turn the result
	 * into an input of the spam decision (pinned in OverbroadPatternMarkerWiringTest).
	 *
	 * @param string   $option_value   POW_PARAMETER_PATTERN, exactly as stored.
	 * @param mixed    $request        The field map the gate matched against.
	 * @param string[] $own_domains    Registrable domains of the site itself, as the live
	 *                                 matcher receives them. OPTIONAL ONLY so existing
	 *                                 callers keep working: left out, a blocked value on
	 *                                 the site's OWN domain is judged differently here than
	 *                                 by the live matcher (which excludes own domains from
	 *                                 URL extraction and from the sender-domain rule, see
	 *                                 Echo_Values::is_blockable_sender_domain()), so blame
	 *                                 can name an entry the gate did not act on. Callers
	 *                                 should pass it.
	 * @param string   $blocked_values POW_BLOCKED_VALUES, exactly as stored. Its own
	 *                                 parameter rather than a second reading of
	 *                                 $option_value: they are two different options with
	 *                                 two different formats, and one string cannot carry
	 *                                 both without the ambiguity this whole change removed.
	 * @return array<string, string> Trimmed offending line => BLAME_PATTERN|BLAME_VALUE,
	 *                               pattern lines first, each in its own option's order,
	 *                               capped at MARKER_MAX_LINES in total.
	 */
	public static function blaming_lines( string $option_value, $request, array $own_domains = array(), string $blocked_values = '' ): array {
		$blamed = array();

		foreach ( self::split_lines( $option_value ) as $line ) {
			if ( count( $blamed ) >= self::MARKER_MAX_LINES ) {
				return $blamed;
			}
			if ( isset( $blamed[ $line ] ) ) {
				continue;
			}
			if ( Pattern_Matcher::line_matches( $line, $request ) ) {
				$blamed[ $line ] = self::BLAME_PATTERN;
			}
		}

		foreach ( self::split_lines( $blocked_values ) as $line ) {
			if ( count( $blamed ) >= self::MARKER_MAX_LINES ) {
				return $blamed;
			}
			if ( isset( $blamed[ $line ] ) ) {
				continue;
			}
			if ( self::blocked_value_matches( $line, $request, $own_domains ) ) {
				$blamed[ $line ] = self::BLAME_VALUE;
			}
		}

		return $blamed;
	}

	/**
	 * One option value into its trimmed, non-empty lines.
	 *
	 * @param string $option_value Raw option value.
	 * @return string[]
	 */
	private static function split_lines( string $option_value ): array {
		$lines = preg_split( "/\r\n|\n|\r/", $option_value );
		if ( false === $lines ) {
			return array();
		}
		$out = array();
		foreach ( $lines as $raw_line ) {
			$line = trim( $raw_line );
			if ( '' !== $line ) {
				$out[] = $line;
			}
		}
		return $out;
	}

	/**
	 * Does this ONE blocklist entry match the request?
	 *
	 * Nothing is decided here beyond "which of the two shapes is this line" — and even that
	 * is asked of Echo_Values::partition_blocklist_lines(), the same reader the live
	 * blocklist uses (Stamp::blocklist_matches()). A plain value is judged by
	 * matches_wildcard_values(), a field-bound RULE by Pattern_Matcher::line_matches_blocked();
	 * a line that is neither carries no rule at all and can blame nothing.
	 *
	 * This mirrors the live evaluation deliberately down to the order of the two branches:
	 * a notice that named a line the gate did not act on — or stayed silent on one it did —
	 * is the failure mode the whole construction principle of Pattern_Matcher exists to
	 * prevent, and the rule half would have been exactly such a blind spot on the day it
	 * shipped.
	 *
	 * @param string   $line        One trimmed blocklist line.
	 * @param mixed    $request     The field map the gate matched against.
	 * @param string[] $own_domains Registrable domains of the site itself.
	 * @return bool
	 */
	private static function blocked_value_matches( string $line, $request, array $own_domains ): bool {
		$partition = Echo_Values::partition_blocklist_lines( array( $line ) );
		if ( ! empty( $partition['values'] )
			&& Echo_Values::matches_wildcard_values( $request, $partition['values'], $own_domains ) ) {
			return true;
		}
		foreach ( $partition['rules'] as $rule ) {
			if ( Pattern_Matcher::line_matches_blocked( $rule, $request, $own_domains ) ) {
				return true;
			}
		}
		return false;
	}
}
