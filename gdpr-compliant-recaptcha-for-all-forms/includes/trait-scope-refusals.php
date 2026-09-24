<?php
/**
 * DIE ABLEHNUNGEN DER NICHT-TEXTAREA-SCHREIBWEGE (Schnitt 2026-08-28).
 *
 * Area doc: handbuch/overbroad.md ("Wer prueft welchen Schreibweg" — die Reaktion je
 * Weg), Detail zur Action-Regelzeile in handbuch/matchers.md.
 *
 * SCHNITTLINIE (CLAUDE.md "Dateigroessen"): class-scope-add.php stand mit
 * action_line_refusal() bei 611 von 600 Zeilen. Getrennt wurde entlang der einzigen
 * Naht, die die Datei ohnehin hat — plan()/apply()/record() beantworten "darf dieser
 * AGENT das?" und geben einem Agenten REASON-CODES zurueck; alles hier beantwortet
 * "darf dieser EIN-KLICK-KNOPF das?" und gibt einem MENSCHEN einen Satz zurueck.
 *
 * Ein Trait, keine zweite Klasse, und zwar aus einem Grund, der hier mehr wiegt als
 * bei den anderen Schnitten: diese Methoden werden aus vier Dateien als
 * `Scope_Add::…()` gerufen (trait-analysis-endpoints.php, trait-message-actions.php,
 * trait-settings-save.php, class-scope-add.php selbst) und in
 * OneClickWriteTargetsTest auf Quelltext-Ebene GENAU SO festgenagelt. Ein Trait haelt
 * jeden dieser Aufrufe byte-gleich — der Schnitt ist ein Umzug, keine Umverdrahtung.
 *
 * @package VENDOR\RECAPTCHA_GDPR_COMPLIANT
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Trait Scope_Refusals: the operator-facing half of Scope_Add — the two "would this
 * line put wp-admin under evaluation?" questions, the ONE verdict on a line headed for
 * POW_EXPLICIT_ACTION through a one-click endpoint, and the sentences all of them
 * answer with.
 */
trait Scope_Refusals {

	/**
	 * Would monitoring this FIELD PATTERN line put wp-admin's own traffic under
	 * evaluation? THE one answer to that question, for every path that writes into
	 * POW_PARAMETER_PATTERN — the agent path here, the direct-analysis one-click
	 * (Analysis::save_pattern_callback()) and the message-view one-click
	 * (Message_Actions::save_pattern_callback()). The settings textarea asks the same
	 * question of the same function, one layer down (Overbroad_Pattern_Guard).
	 *
	 * UNTIL 2026-08-26 THIS CLASS ANSWERED IT ITSELF, from a hand-kept list of twelve
	 * bare field names — a second catalog about the question Pattern_Matcher already
	 * owns, hanging on no test against the first. Two catalogs that are never exercised
	 * together drift, and the weaker one was guarding the path whose caller is an agent
	 * reading text it did not write. So the list is gone and the real matcher decides.
	 *
	 * The boundary MOVES with that, in both directions, and both are wanted:
	 *   - LOOSER where the old list was blind to values. `{"action":"fluentform_submit"}`
	 *     was refused because the KEY `action` was listed, although no admin screen sends
	 *     that value — the same reasoning CLAUDE.md already applies to the Formidable seed
	 *     (`frm_action=create` is a form, `frm_action=save` is the backend).
	 *   - STRICTER where the old list was blind to the rest of the line: a pattern must
	 *     satisfy ALL its keys, so `{"option_page":null,"my_form":null}` cannot match any
	 *     core screen and is now accepted, while every line that really does match one is
	 *     refused with its values taken into account.
	 *
	 * @param string $line Trimmed pattern line.
	 * @return bool
	 */
	public static function pattern_locks_out_admin( $line ) {
		return array() !== Pattern_Matcher::overbroad_lines( (string) $line );
	}

	/**
	 * The same question for an ADMIN-AJAX ACTION NAME, and here a list is the right
	 * shape: the ajax branch of the triage matches an action by name only, never
	 * against a field map (handbuch/gate.md), so there is nothing for a matcher to
	 * compare. Shared with the two one-click writers for the same reason as above —
	 * a second copy of ADMIN_AJAX_ACTIONS is exactly the mistake being undone here.
	 *
	 * @param string $action Action name as submitted.
	 * @return bool
	 */
	public static function action_locks_out_admin( $action ) {
		return in_array( strtolower( trim( (string) $action ) ), self::ADMIN_AJAX_ACTIONS, true );
	}

	/**
	 * THE ONE VERDICT ON A LINE HEADED FOR POW_EXPLICIT_ACTION through a one-click
	 * endpoint: the refusal text to show, or null when the line may be written.
	 *
	 * Added 2026-08-28, when a line in that option was allowed to become a JSON RULE
	 * that pins the action name plus further fields or values (Action_Rules,
	 * handbuch/matchers.md). The two one-click endpoints knew nothing about that form:
	 * they wrote the supplied key verbatim and asked only action_locks_out_admin(),
	 * which reads a whole rule line as one long "action name" and therefore always
	 * answers "harmless". The UI that will produce such lines is untrusted — it is the
	 * ENDPOINT that is the boundary, so the contract stands here, before the overlay
	 * learns to build them.
	 *
	 * A PLAIN LINE is judged exactly as before; the endpoints trade their own inline
	 * guard for this call, which is a simplification, not an addition.
	 *
	 * A RULE LINE is asked three questions, in this order:
	 *
	 *   (a) does it ARM (Action_Rules::pinned_action() !== '')? This is the deliberate
	 *       difference to the settings textarea, which WARNS and stores: a one-click
	 *       path never writes an inert line. The line arrives from a button, not from
	 *       an operator's keyboard, so "the operator meant it" cannot be assumed — and
	 *       there is no second save to hang a confirmation on. The QUESTION is the same
	 *       one Settings_Menu::update_settings() asks; only the REACTION differs.
	 *   (b) is the PINNED NAME one wp-admin drives itself with? Asked of the name, not
	 *       of the whole line — the ajax branch recognises a request by action name,
	 *       and the line as a whole is not one.
	 *   (c) does the line also match one of WordPress' core backend POSTs? Asked of
	 *       Pattern_Matcher::overbroad_lines(), the SAME function and the same catalog
	 *       the pattern textarea uses. No second implementation, for the reason spelled
	 *       out at pattern_locks_out_admin() above.
	 *
	 * SANITISING, and its one named limit: both endpoints run the value through
	 * sanitize_text_field() before it gets here. A rule line as the overlay builds it
	 * survives that byte-identically (proven live in
	 * tests/integration/cases/one-click-scope-guard.mjs). A `<` inside a VALUE does not:
	 * WordPress escapes it, the line stops being valid JSON, stops arming — and is
	 * refused by (a) rather than stored as a quietly different rule. Percent-escapes
	 * (`%2F`) are dropped and runs of whitespace collapse to one space for the same
	 * reason. The failure mode is a refusal, never a silent narrowing.
	 *
	 * @param string $line One line as offered by a one-click endpoint, already sanitised.
	 * @return string|null Refusal text for the operator, or null when the line may be written.
	 */
	public static function action_line_refusal( $line ) {
		$entry = trim( (string) $line );

		if ( ! Action_Rules::is_rule_line( $entry ) ) {
			return self::action_locks_out_admin( $entry ) ? self::action_lockout_message() : null;
		}

		$pinned = Action_Rules::pinned_action( $entry );
		if ( '' === $pinned ) {
			return self::action_rule_inert_message();
		}
		if ( self::action_locks_out_admin( $pinned ) ) {
			return self::action_lockout_message();
		}
		if ( array() !== Pattern_Matcher::overbroad_lines( $entry ) ) {
			return self::action_rule_core_screen_message();
		}

		return null;
	}

	/**
	 * A rule line that pins no action name can never match anything — and reads like
	 * protection while doing nothing.
	 *
	 * @return string
	 */
	public static function action_rule_inert_message() {
		return __( 'Refused: this rule pins no fixed "action" value, so it can never match anything. A rule looks like {"action":"mailpoet","endpoint":"subscribers"} — the action name first, then the further conditions. If you really want to store this line, enter it under Settings → GDPR ReCaptcha → Scope → "Apply on actions".', 'gdpr-compliant-recaptcha-for-all-forms' );
	}

	/**
	 * A rule line whose conditions also fit one of WordPress' own backend POSTs.
	 *
	 * @return string
	 */
	public static function action_rule_core_screen_message() {
		return __( 'Refused: this rule would also match a request WordPress\' own admin screens send, so saving one of those screens would be treated as spam and discarded — and wp-admin never gets a puzzle to solve, so you could not undo it from there. Narrow the conditions to fields only your form sends. If you really want this rule, enter it under Settings → GDPR ReCaptcha → Scope → "Apply on actions", where it is stored with a warning.', 'gdpr-compliant-recaptcha-for-all-forms' );
	}

	/**
	 * The one extra sentence the MESSAGE LIST adds to a refused rule line.
	 *
	 * That button has server parity with the overlay (it asks the same
	 * action_line_refusal()) but deliberately no user interface for rules: it lists an
	 * action NAME taken from a stored message, and a rule is a statement about the field
	 * values of one concrete submission, which the list does not have in front of it.
	 * So the refusal there says where rules are actually built, instead of leaving the
	 * operator to guess.
	 *
	 * @return string
	 */
	public static function action_rule_analysis_hint() {
		return __( 'This list adds a plain action name; a rule that tells two requests with the same action name apart is built from a captured request in "Direct analysis mode".', 'gdpr-compliant-recaptcha-for-all-forms' );
	}

	/**
	 * Why a one-click writer refused a pattern line, in the operator's words.
	 *
	 * The ajax write paths cannot HOLD BACK the way the settings page does: that
	 * mechanic is a form round trip (parked text plus a hash-bound confirmation on the
	 * next save), and a one-click ajax call has no next save. A named refusal is the
	 * fully recoverable answer instead — provided it says where to go, which is what
	 * the second half of this sentence is for.
	 *
	 * @return string
	 */
	public static function pattern_lockout_message() {
		return __( 'Refused: this pattern would also match a request WordPress\' own admin screens send, so saving one of those screens would be treated as spam and discarded — and wp-admin never gets a puzzle to solve, so you could not undo it from there. Add a field only your form sends. If you really want this pattern, enter it under Settings → GDPR ReCaptcha → Scope → "Apply on pattern", where you can confirm it.', 'gdpr-compliant-recaptcha-for-all-forms' );
	}

	/**
	 * The same for an admin-ajax action name.
	 *
	 * "targets one of" rather than "is one of" since 2026-08-28: the same sentence now
	 * also answers a RULE line that pins such a name (action_line_refusal() below), and
	 * a rule line is not itself an action name. One hazard, one sentence — a second copy
	 * differing only in grammar is the duplication this class exists to undo.
	 *
	 * @return string
	 */
	public static function action_lockout_message() {
		return __( 'Refused: this targets one of WordPress\' own admin-ajax actions, so monitoring it would break that part of wp-admin with no way back from inside it. If you really want this action, enter it under Settings → GDPR ReCaptcha → Scope → "Apply on actions".', 'gdpr-compliant-recaptcha-for-all-forms' );
	}
}
