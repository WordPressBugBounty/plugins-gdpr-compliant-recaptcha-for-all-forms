<?php
/**
 * Pure, WordPress-independent helpers of the field flagging ("Fieldname:prefix to flag
 * spam", "Fieldname:value to add"): reading one rule line, and putting a prefix into a
 * field that lives inside a JSON text.
 *
 * WHY JSON AT ALL. The prefix has to reach the data the form builder reads, because only
 * then is it in the builder's mail (trait-stamp-flagging.php). For an ordinary field that
 * is $_POST. Two kinds of submission carry their fields as JSON TEXT instead:
 *   - an envelope field: ONE $_POST field holding the whole form (Ninja Forms `formData`,
 *     see Field_Envelopes). The rule addresses it by the path the inbox shows, e.g.
 *     `formData->fields->5->value`; the first segment is the $_POST key, the rest lies
 *     inside the JSON text.
 *   - a JSON request body (REST with Content-Type application/json). WordPress' REST
 *     server reads it through a cached copy that the caller can replace.
 * Both mean: decode, prefix, encode, write the text back. This class does the middle.
 *
 * THE ENCODING HAS TO GIVE BACK WHAT THE BROWSER SENT, apart from the prefix:
 *   - decoded as OBJECTS, not arrays, so an empty `{}` stays `{}` (as an array it would
 *     come back as `[]`, and a builder decoding to objects would read a list);
 *   - encoded with JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE |
 *     JSON_UNESCAPED_LINE_TERMINATORS | JSON_PRESERVE_ZERO_FRACTION, which matches
 *     JSON.stringify: no `\/`, no `\u`-escaped umlauts, U+2028/U+2029 as they are,
 *     `1.0` stays `1.0`;
 *   - ROUND-TRIP GATE (Fable, release plan): before anything is prefixed, decoding and
 *     re-encoding the UNCHANGED text must give back exactly that text. Otherwise the
 *     re-encoding itself would change something the builder reads — a big integer turned
 *     into a float, `1e21`, whitespace, an escaped spelling. JSON.stringify output passes;
 *     everything else is left alone, so the only difference the builder can ever see is
 *     the prefix;
 *   - any doubt returns null, and the caller leaves the original text untouched. A text
 *     we cannot round-trip is better delivered unflagged than changed.
 * Tests: tests/unit/FlagPrefixTest.php.
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
 * Rule-line parsing and prefixing inside JSON text.
 */
final class Flag_Prefix {

	/** Separator between the levels of a field path — the same one the inbox shows. */
	const PATH_SEPARATOR = '->';

	/** Encoding flags that reproduce what JSON.stringify sent. See the file docblock. */
	const JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS | JSON_PRESERVE_ZERO_FRACTION;

	/**
	 * Splits a rule line at its FIRST colon: everything before is the field, everything
	 * after is the prefix (or the value to add), colons included. Until 6.2.0 a line had
	 * to split into exactly two parts, so `message:[SPAM]: ` was silently ignored.
	 *
	 * @param string $line One line of POW_FLAG_SUFFIXES or POW_FLAG_TAGS.
	 * @return array{0: string, 1: string}|null Null when there is no colon or no field.
	 */
	public static function parse_line( $line ) {
		$parts = explode( ':', (string) $line, 2 );
		if ( 2 !== count( $parts ) || '' === $parts[0] ) {
			return null;
		}
		return array( $parts[0], $parts[1] );
	}

	/**
	 * Puts $prefix in front of the scalar at $segments inside $json and returns the new text.
	 *
	 * @param mixed    $json     The JSON text (an envelope field's value or a request body); anything else is refused.
	 * @param string[] $segments Path inside the text, e.g. array( 'fields', '5', 'value' ).
	 * @param string   $prefix   The prefix, already in the form it is to appear in.
	 * @return string|null Null when the text is no JSON object/array, too large or too deep,
	 *                     does not survive the round trip unchanged, the path does not lead
	 *                     to a scalar, or encoding fails.
	 */
	public static function prefix_in_json( $json, array $segments, $prefix ) {
		if ( ! is_string( $json ) || '' === $json || ! $segments || strlen( $json ) > Field_Envelopes::MAX_BYTES ) {
			return null;
		}
		$data = json_decode( $json, false, Field_Envelopes::MAX_DEPTH );
		if ( ! is_object( $data ) && ! is_array( $data ) ) {
			return null;
		}
		// Round-trip gate, see the file docblock.
		if ( json_encode( $data, self::JSON_FLAGS ) !== $json ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- pure class, see below.
			return null;
		}
		if ( ! self::prefix_at( $data, $segments, (string) $prefix ) ) {
			return null;
		}
		$encoded = json_encode( $data, self::JSON_FLAGS ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- pure class without WordPress; wp_json_encode() would add nothing but a dependency here.
		return is_string( $encoded ) ? $encoded : null;
	}

	/**
	 * Walks $segments through decoded JSON and prefixes the scalar at the end, in place.
	 *
	 * @param object|array<mixed> $node     Decoded JSON (objects for `{}`, arrays for `[]`).
	 * @param string[]            $segments Remaining path.
	 * @param string              $prefix   The prefix.
	 * @return bool Whether a scalar was found and prefixed.
	 */
	private static function prefix_at( &$node, array $segments, $prefix ) {
		$segment = (string) array_shift( $segments );
		if ( is_object( $node ) && property_exists( $node, $segment ) ) {
			$child = &$node->$segment;
		} elseif ( is_array( $node ) && ctype_digit( $segment ) && array_key_exists( (int) $segment, $node ) ) {
			$child = &$node[ (int) $segment ];
		} else {
			return false;
		}
		if ( $segments ) {
			return ( is_object( $child ) || is_array( $child ) ) && self::prefix_at( $child, $segments, $prefix );
		}
		if ( ! is_scalar( $child ) || is_bool( $child ) ) {
			return false;
		}
		$child = $prefix . $child;
		return true;
	}
}
