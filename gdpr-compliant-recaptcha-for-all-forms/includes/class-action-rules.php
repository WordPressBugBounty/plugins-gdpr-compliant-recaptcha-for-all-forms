<?php
/**
 * DIE REGELZEILEN DER ACTION-LISTE (2026-08-28).
 *
 * Eine Zeile in `POW_EXPLICIT_ACTION` durfte bisher nur ein Action-NAME sein, und der
 * Ajax-Zweig der Triage kennt genau diese eine Signaturklasse: Muster
 * (`POW_PARAMETER_PATTERN`) werden dort nie gelesen (handbuch/matchers.md, "Die
 * Regelzeilen der Action-Liste"). Für jeden Builder, dessen Frontend-Action denselben
 * Namen trägt wie seine Backend-API, hiess das "ganz oder gar nicht" — und "ganz" sperrt
 * den Betreiber aus. Gemessener Fall: MailPoet postet aus dem Frontend `action=mailpoet`,
 * den Namen seiner GESAMTEN JSON-API; Besucher- und Administrator-Anfrage unterscheiden
 * sich nur durch WERTE (`endpoint=subscribers` + `method=subscribe`).
 *
 * Diese Klasse ist die dritte Lesart einer Action-Zeile, und sie ist bewusst die
 * ENGSTE: eine Regelzeile armiert nur, wenn sie den Schlüssel `action` auf einen
 * nicht-leeren String pinnt. Damit ist jede Regelzeile eine strikte VERENGUNG einer
 * heute schon ausdrückbaren Klartext-Zeile —
 * `{"action":"mailpoet","endpoint":"subscribers","method":"subscribe"}` ist eine
 * Teilmenge der Zeile `mailpoet`. Die neue Form kann also nichts aussperren, was die
 * alte nicht längst konnte; sie kann nur weniger.
 *
 * KEIN ZWEITER FELDVERGLEICH. Verglichen wird ausschliesslich über
 * `Pattern_Matcher::matches()` — dieselbe Traversierung, dieselbe Monitoring-Semantik
 * (`null` = blosse Existenz, Non-null strikt, Rekursion über Objekte UND Arrays), und
 * dasselbe `json_decode()` OHNE assoc-Flag, damit verschachtelte Objekte als stdClass
 * ankommen. Diese Klasse entscheidet nur, OB eine Zeile eine armierte Regel ist; WIE
 * verglichen wird, entscheidet sie nie. Genau die Divergenz, die
 * PatternMatcherEquivalenceTest für die Muster-Seite verhindert, darf hier nicht neu
 * entstehen — gepinnt in tests/unit/ActionRulesTest.php.
 *
 * WAS DIESE KLASSE NICHT TUT, und was das einhegt: sie liest die Option nicht, sie kennt
 * keinen Frühausstieg und sie wird nur aus `Stamp::check_explicit_actions()` gerufen —
 * also nur auf einem Request, der überhaupt eine `action` trägt. Die Zeilenform kann
 * damit nie zum zweiten allgemeinen Muster-Kasten werden.
 *
 * Rein und WordPress-frei, deshalb direkt unit-getestet (tests/unit/ActionRulesTest.php).
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/matchers.md, Abschnitt "Die Regelzeilen der
// Action-Liste". Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Stateless reading of a JSON RULE line in the action list.
 */
final class Action_Rules {

	/**
	 * The one key a rule line must pin to arm — see the class doc-comment.
	 *
	 * @var string
	 */
	const PIN_KEY = 'action';

	/**
	 * Does this line even look like a rule, i.e. is it meant to be read as one?
	 *
	 * Deliberately the cheapest possible question — "starts with `{` after trimming" —
	 * and deliberately NOT "is it a valid, armed rule": a line that looks like a rule but
	 * is not one has to stay recognisable as such, otherwise the save-time warning could
	 * not name it (inert_rule_lines() below). A plain action name never starts with `{`.
	 *
	 * @param string $raw_line One line as entered by the administrator.
	 * @return bool
	 */
	public static function is_rule_line( string $raw_line ): bool {
		$line = trim( $raw_line );
		return '' !== $line && '{' === $line[0];
	}

	/**
	 * The action name a rule line pins, or '' when the line does not arm.
	 *
	 * THE ARMING CONDITION IS THE CONTAINMENT (class doc-comment): the line has to be a
	 * JSON object that pins `action` to a NON-EMPTY string. Anything else — `{}`, a line
	 * whose conditions never mention `action`, `{"action":null}` (which would mean "any
	 * request that has an action at all"), `{"action":""}` or a whitespace-only pin —
	 * returns '' and is therefore inert. Without that condition the rule form would be a
	 * second, general pattern box on a list that is read in the ajax branch, where
	 * wp-admin's own traffic lives and no PoW script is ever served.
	 *
	 * @param string $raw_line One line as entered by the administrator.
	 * @return string The pinned action name, verbatim; '' when the line does not arm.
	 */
	public static function pinned_action( string $raw_line ): string {
		$rule = self::decode( $raw_line );
		if ( null === $rule ) {
			return '';
		}
		$fields = get_object_vars( $rule );
		if ( ! isset( $fields[ self::PIN_KEY ] ) || ! is_string( $fields[ self::PIN_KEY ] ) ) {
			return '';
		}
		return '' === trim( $fields[ self::PIN_KEY ] ) ? '' : $fields[ self::PIN_KEY ];
	}

	/**
	 * Does this rule line match $request?
	 *
	 * The whole interpretation of a rule line, and the only entry point a caller may use
	 * for one: it must be a rule line, it must decode to an object, it must arm — and
	 * only then is the comparison handed to Pattern_Matcher::matches(), unchanged and
	 * with no own comparison of any kind. An unreadable or unarmed line is silently
	 * false, exactly like an unparsable pattern line; it never throws.
	 *
	 * @param string $raw_line One line as entered by the administrator.
	 * @param mixed  $request  Field map to test (typically $_REQUEST).
	 * @return bool
	 */
	public static function line_matches( string $raw_line, $request ): bool {
		if ( '' === self::pinned_action( $raw_line ) ) {
			return false;
		}
		return Pattern_Matcher::matches( self::decode( $raw_line ), $request );
	}

	/**
	 * SAVE-TIME DIAGNOSIS for POW_EXPLICIT_ACTION: which lines look like a rule but can
	 * never match, because they pin no action name?
	 *
	 * Warn-only — the line is stored as typed. An inert line that looks like a rule is
	 * exactly what sends an operator debugging the wrong thing, same reasoning as the
	 * unreadable-blocklist-line notice in Settings_Menu::update_settings().
	 *
	 * @param string $option_value The complete textarea value, exactly as submitted.
	 * @return string[] Trimmed offending lines, de-duplicated, in submission order.
	 */
	public static function inert_rule_lines( string $option_value ): array {
		$lines = preg_split( "/\r\n|\n|\r/", $option_value );
		if ( false === $lines ) {
			return array();
		}
		$inert = array();
		foreach ( $lines as $raw_line ) {
			if ( self::is_rule_line( $raw_line ) && '' === self::pinned_action( $raw_line ) ) {
				$inert[] = trim( $raw_line );
			}
		}
		return array_values( array_unique( $inert ) );
	}

	/**
	 * One rule line as a decoded object, or null when it is not one.
	 *
	 * json_decode() WITHOUT the assoc flag, deliberately: that is the one decoding of
	 * this plugin (Pattern_Matcher::line_matches()), and matches() expects nested objects
	 * as stdClass. Two decodings would be two semantics.
	 *
	 * @param string $raw_line One line as entered by the administrator.
	 * @return \stdClass|null
	 */
	private static function decode( string $raw_line ) {
		if ( ! self::is_rule_line( $raw_line ) ) {
			return null;
		}
		// Deliberately no assoc flag — see above.
		$rule = json_decode( trim( $raw_line ) );
		return $rule instanceof \stdClass ? $rule : null;
	}
}
