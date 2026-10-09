<?php
/**
 * How a multi-line rule/list textarea of the settings page (every Option::TEXT) is
 * stored — as typed — and the one-off repair of values an older version stored
 * HTML-encoded.
 *
 * THE DEFECT THIS REPLACES (forum, "=> becomes =&gt;"). update_settings() used to send
 * every TEXT value through wp_kses_post(). That function is an HTML filter for post
 * content, and these textareas hold rules, not HTML:
 *   - `=>` became `=&gt;` — a gibberish line (`pattern {"_wpcf7":null} => your-message`)
 *     no longer parsed, i.e. it silently stopped checking anything;
 *   - `&` became `&amp;` — `{"company":"Smith & Sons"}` in "Blocked values" and
 *     `{"form":"Q&A"}` in "Apply on pattern" no longer matched what a visitor sends;
 *   - anything shaped like a tag (`<x>`) was stripped altogether.
 * Because the settings form always posts every field, ANY save of the page rewrote
 * every textarea that way — including gibberish lines the per-field button in the
 * message view had just written correctly.
 *
 * WHY NO ENCODING AT ALL, and why that is safe: the stored text is never HTML. Every
 * output point escapes for its own context (esc_textarea() in the textarea, esc_html()
 * in every add_settings_error() and notice, counts only in the support report, JSON in
 * the abilities, esc_sql() in the message-list filter) — checked one by one when this
 * class was introduced, see handbuch/admin.md. Encoding on input on top of that does
 * not add safety, it only corrupts the rule. What IS removed is what no rule can mean:
 * byte sequences that are not UTF-8, and control characters other than tab and the two
 * line breaks.
 *
 * Option::STRING (the visitor-facing error message, the salt) is not handled here and
 * keeps wp_kses_post(): the error message is shown to visitors as HTML.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Store-as-typed cleaning for TEXT options plus the one-off entity repair.
 */
final class Text_Option_Value {

	/**
	 * Done flag of the one-off repair. Bookkeeping, not a setting (never in
	 * prepare_options()); carries the plugin prefix, so uninstall.php removes it.
	 */
	const REPAIRED = Option::PREFIX . 'pow_text_entities_repaired';

	/**
	 * Every option the settings page declares as Option::TEXT. Pinned against the
	 * options matrix by tests/unit/TextOptionValueTest.php in both directions — a new
	 * TEXT option that is missing here would keep its encoded legacy value forever.
	 */
	const TEXT_OPTIONS = array(
		Option::POW_EXPLICIT_ACTION,
		Option::POW_PARAMETER_PATTERN,
		Option::POW_REST_ROUTES,
		Option::POW_BLOCKED_VALUES,
		Option::POW_GIBBERISH_FIELDS,
		Option::POW_FLAG_SUFFIXES,
		Option::POW_FLAG_TAGS,
		Option::POW_FAIL_2_BAN_PATH,
		Option::POW_SKIP_FIELDS,
		Option::POW_CREDENTIAL_FIELDS,
		Option::POW_MESSAGE_HEADS,
		Option::POW_IP_WHITELIST,
		Option::POW_SITE_WHITELIST,
		Option::POW_TRUSTED_PROXIES,
		Option::POW_HIDE_ACTION,
		Option::POW_HIDE_PATTERN,
	);

	/**
	 * The value of a TEXT textarea as it is stored: exactly as typed, minus what no rule
	 * can mean. Pure — the caller has already applied wp_unslash().
	 *
	 * Invalid UTF-8 is removed here rather than with wp_check_invalid_utf8(): with
	 * `$strip = true` that function falls back to iconv() on older WordPress (this
	 * plugin supports 4.8+), and iconv() answers invalid input with false — one stray
	 * byte would have emptied the whole textarea. Only the offending bytes go.
	 *
	 * Control characters: C0 except tab (\t), line feed (\n) and carriage return (\r),
	 * plus DEL. Matched byte-wise, which is safe on UTF-8 because no byte of a multi-byte
	 * sequence lies below 0x80.
	 *
	 * @param string $raw Unslashed textarea value.
	 * @return string
	 */
	public static function clean( string $raw ): string {
		return (string) preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', self::strip_invalid_utf8( $raw ) );
	}

	/**
	 * Undo exactly what the old wp_kses_post() save did to plain rule text: `&gt;`,
	 * `&lt;` and `&amp;` back to `>`, `<` and `&`. ONE pass (strtr with an array never
	 * re-reads its own output), so a stored `&amp;gt;` becomes `&gt;`, not `>`: every
	 * stored entity is decoded by exactly one level. Nothing else is decoded — kses
	 * produced no other entity from plain text (measured on WordPress 7.1:
	 * `a => b & c` became `a =&gt; b &amp; c`; a typed `&gt;` was kept as it was).
	 *
	 * Two ambiguities are inherent and accepted: an entity the operator really typed
	 * (`&gt;`) cannot be told apart from an encoded `>` and is decoded; and a value written
	 * WITHOUT the old save (one-click buttons, Scope_Sync) that happens to contain a
	 * literal `&amp;` is decoded too. Both are far rarer than the broken lines this repairs.
	 * Text kses stripped as a "tag" (`<x>`) is gone and cannot be restored.
	 *
	 * @param string $stored A TEXT option value as an older version stored it.
	 * @return string
	 */
	public static function repair_entities( string $stored ): string {
		return strtr(
			$stored,
			array(
				'&gt;'  => '>',
				'&lt;'  => '<',
				'&amp;' => '&',
			)
		);
	}

	/**
	 * Run the repair once per installation.
	 *
	 * Called from RCM_Main::activate() on EVERY load, outside its version gate, ahead of
	 * Blocked_Values_Migration::maybe_run() (which reads a TEXT option) — same placement
	 * and reasoning as that migration (handbuch/admin.md). Writes only options whose
	 * value actually changes; afterwards it costs one autoloaded get_option().
	 */
	public static function maybe_repair(): void {
		if ( get_option( self::REPAIRED ) ) {
			return;
		}
		foreach ( self::TEXT_OPTIONS as $name ) {
			$value = get_option( $name, null );
			if ( ! is_string( $value ) || '' === $value ) {
				continue;
			}
			$repaired = self::repair_entities( $value );
			if ( $repaired !== $value ) {
				update_option( $name, $repaired );
			}
		}
		update_option( self::REPAIRED, 1, true ); // Last, so an interrupted run repeats.
	}

	/**
	 * Drop every byte sequence that is not well-formed UTF-8 and keep the rest
	 * unchanged. A valid string (the normal case) is returned without being rebuilt.
	 *
	 * @param string $text Input.
	 * @return string
	 */
	private static function strip_invalid_utf8( string $text ): string {
		if ( '' === $text || 1 === preg_match( '//u', $text ) ) {
			return $text;
		}
		preg_match_all(
			'/[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}|\xED[\x80-\x9F][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2}/',
			$text,
			$matches
		);
		return implode( '', $matches[0] );
	}
}
