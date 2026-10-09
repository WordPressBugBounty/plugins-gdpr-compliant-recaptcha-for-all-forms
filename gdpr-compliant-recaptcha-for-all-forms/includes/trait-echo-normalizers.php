<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/echo.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.

/**
 * Trait Echo_Normalizers: wie ein Wert vereinheitlicht wird, bevor die Echo-Sperre ihn
 * vergleicht oder hasht — Freitext. (Die Telefonnummern-Normalisierung samt
 * Kartennummern-Ausschluss stand bis 2026-10 hier; seitdem lernt die Sperre gar keine
 * Zahlen mehr, handbuch/echo.md.)
 *
 * ABGESPALTEN AM 2026-09-24 aus class-echo-values.php, als der Kartennummern-Ausschluss
 * jene Datei auf 645 von 600 Zeilen brachte. Die Schnittlinie ist keine Verlegenheit,
 * sondern die vorhandene Fuge: `Echo_Values` entscheidet, WAS in die Sperre geht
 * (Auswahl, Domains, Ausnahmen, Hashes); dieses Trait entscheidet, in welcher FORM ein
 * einzelner Wert dort ankommt. Beides zusammen war nie eine Verantwortlichkeit.
 *
 * Trait statt zweiter Klasse, damit `Echo_Values::normalize_text()` weiterhin genau so
 * heisst und aufrufbar bleibt — der Umzug aendert keinen Aufrufer und keinen Test.
 */
trait Echo_Normalizers {

	/**
	 * Normalize a text value (lower-case, strip everything but letters/digits) for
	 * the exact-resend text hash, or null when it is shorter than
	 * TEXT_HASH_MIN_LENGTH normalized characters. Deliberately exact, not fuzzy.
	 *
	 * @param string $value Value.
	 * @return string|null Normalized text, or null.
	 */
	public static function normalize_text( $value ) {
		$value = (string) $value;
		if ( '' === $value || 1 !== preg_match( '//u', $value ) ) {
			return null;
		}
		$lower      = function_exists( 'mb_strtolower' ) ? mb_strtolower( $value, 'UTF-8' ) : strtolower( $value );
		$normalized = (string) preg_replace( '/[^\p{L}\p{N}]+/u', '', $lower );
		$length     = function_exists( 'mb_strlen' ) ? mb_strlen( $normalized, 'UTF-8' ) : strlen( $normalized );
		if ( $length < self::TEXT_HASH_MIN_LENGTH ) {
			return null;
		}
		return $normalized;
	}
}
