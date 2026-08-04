<?php
/**
 * Pure, WordPress-independent classification-reason taxonomy (T1 of the trust-
 * instrumentation plan, see loop/docs/impl-plan.md).
 *
 * A "reason" is a short, machine-readable string naming WHY a submission was
 * classified as spam. It is meant to be stored verbatim with the message (as the
 * technical field `_gdpr_reason`) so the site owner can see the cause in the UI,
 * and so an exported message corpus carries a stable label per entry.
 *
 * Format: `code` or `code:detail`, both lower-case ASCII. The full taxonomy:
 *
 *   no_pow:no_token        Submission carried no proof-of-work token at all.
 *   no_pow:invalid_token   A token was posted but failed StampToken/ChainToken verification.
 *   no_pow:token_no_row    Valid token, but no solved-PoW row landed within the poll window.
 *   no_pow:chain_no_row    Valid chain token, but its row never landed (extended window).
 *   simulation             POW_SIMULATE_SPAM is on — everything is "spam" by configuration.
 *   echo_lock              A core value matched an auto-recorded recent spam value.
 *   wildcard               A user-content field matched an admin-configured {"*":"…"} pattern.
 *   quarantine             Under-attack quarantine held an otherwise-clean submission.
 *   gibberish:letters=<n>,alnum=<n>,solo=<0|1>
 *                          Gibberish detection fired; the detail carries the scoring
 *                          components from Gibberish_Detector::analyze_message().
 *
 * There is deliberately NO reason for a clean message: absence of a reason means
 * clean. Callers must therefore store null/nothing rather than inventing an "ok"
 * code — a code for cleanliness would be indistinguishable from an unlabelled
 * legacy row in the corpus.
 *
 * These strings are CORPUS LABELS: they end up in stored message rows and in
 * exported training data, so their stability matters more than their elegance.
 * Add new codes rather than renaming existing ones.
 *
 * No WordPress dependencies (no options, no $wpdb, no translation functions) →
 * unit-testable in isolation, see tests/unit/ClassificationReasonTest.php.
 * label() therefore returns plain English; the plugin UI is English throughout, and
 * a caller that wants escaping/translation applies it at the render site.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Stateless classification-reason strings and their UI labels.
 */
final class Classification_Reason {

	// Codes. A code that carries no detail IS the complete reason string
	// (CODE_SIMULATION === 'simulation'); the two codes that do carry a detail have
	// their own constants/builder below (NO_POW_* and gibberish()).

	/** No usable proof of work — see the four NO_POW_* constants for the sub-cases. */
	const CODE_NO_POW = 'no_pow';

	/** Spam simulation mode (POW_SIMULATE_SPAM) classified the submission. */
	const CODE_SIMULATION = 'simulation';

	/** Auto-echo lock: a core value matched a recently recorded spam value. */
	const CODE_ECHO_LOCK = 'echo_lock';

	/** Admin-configured wildcard value pattern matched. */
	const CODE_WILDCARD = 'wildcard';

	/** Under-attack quarantine held an otherwise-clean submission. */
	const CODE_QUARANTINE = 'quarantine';

	/** Gibberish detection fired — detail carries the scoring components. */
	const CODE_GIBBERISH = 'gibberish';

	/** No proof-of-work token was posted at all (the protocol-blind mass). */
	const NO_POW_NO_TOKEN = 'no_pow:no_token';

	/** A token was posted but failed verification (forged, expired, wrong IP). */
	const NO_POW_INVALID_TOKEN = 'no_pow:invalid_token';

	/** Token verified, but no solved-PoW row was found within the poll window. */
	const NO_POW_TOKEN_NO_ROW = 'no_pow:token_no_row';

	/** Chain token verified, but its row never landed within the extended window. */
	const NO_POW_CHAIN_NO_ROW = 'no_pow:chain_no_row';

	/**
	 * Short English UI label per CODE, keyed by the code part of a reason string.
	 * Intentionally code-level (not detail-level): the detail is diagnostic data for
	 * the corpus, the label answers "what kind of block was this?" at a glance.
	 *
	 * @var array<string,string>
	 */
	const CODE_LABELS = array(
		self::CODE_NO_POW     => 'No proof of work',
		self::CODE_SIMULATION => 'Simulation mode',
		self::CODE_ECHO_LOCK  => 'Known spam value',
		self::CODE_WILDCARD   => 'Blocked value pattern',
		self::CODE_QUARANTINE => 'Under-attack quarantine',
		self::CODE_GIBBERISH  => 'Gibberish content',
	);

	/** Fallback label for an unknown, empty or malformed reason string. */
	const UNKNOWN_LABEL = 'Unknown reason';

	/**
	 * Build the gibberish reason string from the scoring components reported by
	 * Gibberish_Detector::analyze_message().
	 *
	 * Detail format (stable): `letters=<n>,alnum=<n>,solo=<0|1>` — the number of
	 * gibberish tokens found on the pure-letter path, the number found on the
	 * alphanumeric path, and whether the solo-token rule fired (a single gibberish
	 * token as a form's entire content). Counts are clamped at 0 so a malformed
	 * caller value can never produce a negative label.
	 *
	 * @param int  $letters Gibberish tokens found on the pure-letter path.
	 * @param int  $alnum   Gibberish tokens found on the alphanumeric path.
	 * @param bool $solo    Whether the solo-token rule fired.
	 * @return string Reason string, e.g. "gibberish:letters=2,alnum=0,solo=0".
	 */
	public static function gibberish( $letters, $alnum, $solo ) {
		return self::CODE_GIBBERISH . ':letters=' . max( 0, (int) $letters )
			. ',alnum=' . max( 0, (int) $alnum )
			. ',solo=' . ( $solo ? '1' : '0' );
	}

	/**
	 * The code part of a reason string: everything before the first colon (the whole
	 * string for codes that carry no detail).
	 *
	 * @param mixed $reason Reason string (any input accepted defensively — stored
	 *                      values pass through the database and may be anything).
	 * @return string Code part, or '' for non-string/empty input.
	 */
	public static function code( $reason ) {
		if ( ! is_string( $reason ) || '' === $reason ) {
			return '';
		}
		$colon = strpos( $reason, ':' );
		// Cast: substr() is typed string|false below PHP 8 (it cannot fail here —
		// offset 0 — but the analyser must not have to know that).
		return false === $colon ? $reason : (string) substr( $reason, 0, $colon );
	}

	/**
	 * Short English UI label for a reason string. Never throws and never returns an
	 * empty string: unknown codes, malformed strings and non-string input all yield
	 * UNKNOWN_LABEL. A stored reason may predate (or postdate) the code that reads
	 * it, so an unrecognised value must degrade to something printable rather than
	 * break the message view.
	 *
	 * @param mixed $reason Reason string.
	 * @return string Label.
	 */
	public static function label( $reason ) {
		$code = self::code( $reason );
		return isset( self::CODE_LABELS[ $code ] ) ? self::CODE_LABELS[ $code ] : self::UNKNOWN_LABEL;
	}
}
