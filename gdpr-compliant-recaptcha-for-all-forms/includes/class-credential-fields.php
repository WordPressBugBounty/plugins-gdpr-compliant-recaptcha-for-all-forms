<?php
/**
 * Pure, WordPress-independent credential-field detection and redaction.
 *
 * Two jobs, both about never persisting a cleartext password in the message
 * inbox (`wp_recaptcha_gdpr_details_rgd`), which every admin can read:
 *
 *  1. A NAME HEURISTIC (`is_password_key()`) — the exact server-side twin of
 *     `isPasswordKey()` in `scripts/recaptcha-gdpr-analysis.js`. It is the
 *     primary line of defence: unlike the client-injected `hashPWFields`
 *     marker it also covers submissions that never ran the plugin's JS
 *     (no-JS logins, hand-built ajax bodies, minimal POSTs). The twin
 *     relationship is enforced by a source-pinning test
 *     (`tests/unit/CredentialFieldsTest.php::test_heuristic_matches_js_twin`) —
 *     change one side and the suite goes red. Do NOT widen it unilaterally:
 *     `passenger`/`compass` must keep returning false on BOTH sides.
 *
 *  2. A REDACTION PRE-PASS (`redact()`) over the (possibly nested) field map,
 *     replacing every matching value — including whole sub-trees — with
 *     REDACTED_VALUE while keeping the key. Redacting instead of dropping the
 *     row keeps a false-positive rescue readable in the UI (field name still
 *     visible, protection visible) and keeps the nested structure intact.
 *
 * A THIRD line lives next to this class, not inside it: the admin-confirmed
 * learned field names (Learned_Credential_Fields). They reach the walk through
 * redact()'s `$learned_names` parameter and are never merged into the heuristic's
 * constants — see redact()'s docblock for why that separation is load-bearing.
 *
 * Error direction: fail-closed per field (anything odd under a password-ish key
 * becomes REDACTED_VALUE, sub-tree and all), fail-open per message — `redact()`
 * is total by construction (it never throws, whatever the input), so the save
 * path never gains a new abort branch.
 *
 * The `hashPWFields` marker stays as an ADDITIONAL signal: the client
 * (`scripts/recaptcha-gdpr-pow.js`, `addFirstStamp()`) collects each
 * `input[type=password]` name through `fieldNameToNestedObject()` and posts
 * `btoa(JSON.stringify([ <nested object per password field> ]))`, i.e. a list of
 * single-key chains whose key sequence IS the field path (`a[b][c]` →
 * `{"a":{"b":{"c":null}}}`). `marker_paths_from_raw()` decodes that into segment
 * paths exactly the way the JS twin `stripPasswordFields()` does (first key per
 * level), so both ends agree on which path a marker entry denotes.
 *
 * No WordPress dependencies (no options, no $wpdb, no translation functions) →
 * unit-testable in isolation, see tests/unit/CredentialFieldsTest.php.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/credentials.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Stateless credential-field heuristics and redaction helpers.
 */
final class Credential_Fields {

	/** Replacement written instead of a credential value. */
	public const REDACTED_VALUE = '[redacted]';

	/**
	 * Exact key names that are credentials (twin of the JS regex
	 * `/^(pwd|passwd|pass|pass1|pass2|user_pass)$/`).
	 *
	 * Deliberately NOT included: `pass1-text` (WP < 5.3 wp-admin profile only —
	 * that path bails out via is_admin() long before persistence), so the twin
	 * stays exact.
	 *
	 * @var string[]
	 */
	private const EXACT_KEYS = array( 'pwd', 'passwd', 'pass', 'pass1', 'pass2', 'user_pass' );

	/**
	 * Substrings that make a key a credential (twin of the JS
	 * `k.includes('password') || k.includes('passwort')`).
	 *
	 * @var string[]
	 */
	private const SUBSTRINGS = array( 'password', 'passwort' );

	/** Separator used in persisted `rgd_attribute` paths (Stamp::generate_paths()). */
	private const PATH_SEPARATOR = '->';

	/**
	 * Nesting depth beyond which redaction stops descending and fails CLOSED.
	 *
	 * Real form payloads nest a handful of levels at most (`a[b][c]`); anything
	 * deeper is hostile or malformed input, and a self-referencing array would
	 * otherwise recurse forever. Past the limit the whole remaining sub-tree is
	 * replaced by REDACTED_VALUE rather than passed through unchecked —
	 * losing diagnostic depth is cheap, leaking a password is not.
	 */
	private const MAX_DEPTH = 32;

	/**
	 * Does this field name denote a credential?
	 *
	 * Never throws: non-scalar keys (arrays, objects, null) are not field names
	 * and return false.
	 *
	 * @param mixed $key Candidate field-name segment.
	 * @return bool
	 */
	public static function is_password_key( $key ): bool {
		if ( ! is_scalar( $key ) ) {
			return false;
		}
		$lower = strtolower( (string) $key );
		foreach ( self::SUBSTRINGS as $needle ) {
			if ( false !== strpos( $lower, $needle ) ) {
				return true;
			}
		}
		return in_array( $lower, self::EXACT_KEYS, true );
	}

	/**
	 * Does a persisted `rgd_attribute` path point at a credential?
	 *
	 * The stored attribute is the `->`-joined key chain of a nested field
	 * (`fields->user->pass`), so ANY segment matching makes the whole row a
	 * credential row — matching only the last or only the first segment would
	 * miss real cases in both directions.
	 *
	 * @param string $path Persisted attribute path.
	 * @return bool
	 */
	public static function is_password_path( string $path ): bool {
		foreach ( explode( self::PATH_SEPARATOR, $path ) as $segment ) {
			if ( self::is_password_key( $segment ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Redaction pre-pass over a (possibly nested) field map.
	 *
	 * Walks the whole structure and replaces the value of every credential
	 * field — recognised by the name heuristic (primary), by a decoded
	 * `hashPWFields` marker path (additional signal), or by an admin-confirmed
	 * LEARNED name (third line, see Learned_Credential_Fields) — with
	 * REDACTED_VALUE. The key is kept, sub-trees under a hit are replaced
	 * wholesale.
	 *
	 * The learned names are a separate PARAMETER on purpose, never merged into
	 * EXACT_KEYS/SUBSTRINGS: those two are pinned against the JS twin
	 * (test_heuristic_matches_js_twin), and the learned list has no twin — on the
	 * JS path the `input[type=password]` marker already covers the same fields.
	 * They are compared as whole keys, case-insensitively; a substring rule would
	 * reintroduce the `passenger` error class the heuristic avoids.
	 *
	 * Total by construction: never throws for any input. A non-array input is
	 * returned unchanged; objects are not rewritten but are checked, and an
	 * object containing a credential property anywhere is replaced as a whole
	 * (fail-closed — Stamp::generate_paths() would otherwise flatten and persist
	 * its properties).
	 *
	 * @param mixed $fields        The submission's field map.
	 * @param array $marker_paths  Segment paths from marker_paths_from_raw().
	 * @param array $learned_names Admin-confirmed credential field names.
	 * @return mixed Redacted copy (non-arrays returned unchanged).
	 */
	public static function redact( $fields, array $marker_paths = array(), array $learned_names = array() ) {
		if ( ! is_array( $fields ) ) {
			return $fields;
		}

		$marker_index = array();
		foreach ( $marker_paths as $segments ) {
			if ( ! is_array( $segments ) || 0 === count( $segments ) ) {
				continue;
			}
			$index_key = self::path_index_key( $segments );
			if ( null !== $index_key ) {
				$marker_index[ $index_key ] = true;
			}
		}

		$learned_index = array();
		foreach ( $learned_names as $name ) {
			if ( ! is_scalar( $name ) ) {
				continue;
			}
			$lower = strtolower( trim( (string) $name ) );
			if ( '' !== $lower ) {
				$learned_index[ $lower ] = true;
			}
		}

		return self::redact_level( $fields, $marker_index, $learned_index, array(), 0 );
	}

	/**
	 * Is this key a credential key by the heuristic OR by the learned list?
	 *
	 * The two are checked side by side; is_password_key() itself stays exactly
	 * what its JS twin says it is.
	 *
	 * @param mixed $key           Field-name segment.
	 * @param array $learned_index Lookup set of lower-cased learned names.
	 * @return bool
	 */
	private static function is_credential_key( $key, array $learned_index ): bool {
		if ( self::is_password_key( $key ) ) {
			return true;
		}
		if ( 0 === count( $learned_index ) || ! is_scalar( $key ) ) {
			return false;
		}
		return isset( $learned_index[ strtolower( trim( (string) $key ) ) ] );
	}

	/**
	 * Decode a raw `hashPWFields` request value into segment paths.
	 *
	 * Mirrors the JS twin `stripPasswordFields()`: each list entry is a chain of
	 * single-key objects, and only the FIRST key of each level is followed.
	 * Anything unexpected (non-string, broken base64, non-JSON, non-list) yields
	 * an empty list — the marker is only an additional signal, the name
	 * heuristic carries the protection on its own.
	 *
	 * @param mixed $raw Unauthenticated request value.
	 * @return array<int, array<int, string>> List of segment paths.
	 */
	public static function marker_paths_from_raw( $raw ): array {
		if ( ! is_string( $raw ) || '' === $raw ) {
			return array();
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- benign: hashPWFields is the plugin's own base64-encoded password-field marker (client twin in recaptcha-gdpr-pow.js), not obfuscated code.
		$json = base64_decode( $raw, true );
		if ( false === $json ) {
			return array();
		}

		$decoded = json_decode( $json, true );
		if ( ! is_array( $decoded ) ) {
			return array();
		}

		$paths = array();
		foreach ( $decoded as $entry ) {
			$segments = array();
			$node     = $entry;
			$level    = 0;
			while ( is_array( $node ) && $level < self::MAX_DEPTH ) {
				$keys = array_keys( $node );
				if ( 0 === count( $keys ) ) {
					break;
				}
				$segments[] = (string) $keys[0];
				$node       = $node[ $keys[0] ];
				++$level;
			}
			if ( 0 !== count( $segments ) ) {
				$paths[] = $segments;
			}
		}

		return $paths;
	}

	/**
	 * Redact credential keys inside a stored `_gdpr_analysis_payload` JSON blob.
	 *
	 * Used by the one-off cleanup of pre-existing rows. Returns null when
	 * nothing had to change, so the caller can skip the UPDATE.
	 *
	 * Fail-closed: a value that does not decode into a JSON array at all (the
	 * caller only passes rows whose raw text already matched a credential
	 * prefilter) is replaced by REDACTED_VALUE as a whole — these payloads are
	 * diagnostic captures, cheap to lose, unlike a leaked password.
	 *
	 * @param string $json Stored payload value.
	 * @return string|null New value, or null when no change is needed.
	 */
	public static function redact_payload_json( string $json ): ?string {
		$decoded = json_decode( $json, true );
		if ( ! is_array( $decoded ) ) {
			return self::REDACTED_VALUE;
		}

		$redacted = self::redact( $decoded );
		if ( $redacted === $decoded ) {
			return null;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- this class is deliberately WordPress-free (unit-testable in isolation); wp_json_encode() is unavailable here.
		$encoded = json_encode( $redacted );
		return false === $encoded ? self::REDACTED_VALUE : $encoded;
	}

	/**
	 * Recursive worker for redact().
	 *
	 * @param array $data          Current level.
	 * @param array $marker_index  Lookup set of marker paths (see path_index_key()).
	 * @param array $learned_index Lookup set of lower-cased learned names.
	 * @param array $path          Key segments walked so far.
	 * @param int   $depth         Current nesting depth.
	 * @return array Redacted copy of this level.
	 */
	private static function redact_level( array $data, array $marker_index, array $learned_index, array $path, int $depth ): array {
		$result = array();

		foreach ( $data as $key => $value ) {
			$child_path   = $path;
			$child_path[] = $key;

			if ( self::is_credential_key( $key, $learned_index ) || self::is_marker_path( $marker_index, $child_path ) ) {
				$result[ $key ] = self::REDACTED_VALUE;
				continue;
			}

			if ( is_array( $value ) ) {
				if ( $depth >= self::MAX_DEPTH ) {
					// Fail closed: past the depth limit nothing below can be
					// inspected any more, so nothing below may be persisted.
					$result[ $key ] = self::REDACTED_VALUE;
					continue;
				}
				$result[ $key ] = self::redact_level( $value, $marker_index, $learned_index, $child_path, $depth + 1 );
				continue;
			}

			if ( is_object( $value ) && self::object_holds_credential( $value, $learned_index, $depth ) ) {
				$result[ $key ] = self::REDACTED_VALUE;
				continue;
			}

			$result[ $key ] = $value;
		}

		return $result;
	}

	/**
	 * Does an object carry a credential-named property anywhere below it?
	 *
	 * Objects are not rewritten (that would change their type in the copy), so
	 * the whole object is dropped when it holds one. Past the depth limit the
	 * answer is "yes" — fail closed.
	 *
	 * @param object $value         Object to inspect.
	 * @param array  $learned_index Lookup set of lower-cased learned names.
	 * @param int    $depth         Current nesting depth.
	 * @return bool
	 */
	private static function object_holds_credential( $value, array $learned_index, int $depth ): bool {
		if ( $depth >= self::MAX_DEPTH ) {
			return true;
		}

		foreach ( get_object_vars( $value ) as $key => $property ) {
			if ( self::is_credential_key( $key, $learned_index ) ) {
				return true;
			}
			if ( is_array( $property ) && self::array_holds_credential( $property, $learned_index, $depth + 1 ) ) {
				return true;
			}
			if ( is_object( $property ) && self::object_holds_credential( $property, $learned_index, $depth + 1 ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Array counterpart of object_holds_credential() (only reached from inside
	 * an object, since arrays proper are rewritten in place).
	 *
	 * @param array $data          Array to inspect.
	 * @param array $learned_index Lookup set of lower-cased learned names.
	 * @param int   $depth         Current nesting depth.
	 * @return bool
	 */
	private static function array_holds_credential( array $data, array $learned_index, int $depth ): bool {
		if ( $depth >= self::MAX_DEPTH ) {
			return true;
		}

		foreach ( $data as $key => $value ) {
			if ( self::is_credential_key( $key, $learned_index ) ) {
				return true;
			}
			if ( is_array( $value ) && self::array_holds_credential( $value, $learned_index, $depth + 1 ) ) {
				return true;
			}
			if ( is_object( $value ) && self::object_holds_credential( $value, $learned_index, $depth + 1 ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Is the given key path one of the marker paths?
	 *
	 * @param array $marker_index Lookup set built in redact().
	 * @param array $path         Key segments.
	 * @return bool
	 */
	private static function is_marker_path( array $marker_index, array $path ): bool {
		if ( 0 === count( $marker_index ) ) {
			return false;
		}
		$index_key = self::path_index_key( $path );
		return null !== $index_key && isset( $marker_index[ $index_key ] );
	}

	/**
	 * Flatten a segment list into a lookup key.
	 *
	 * Segments are compared as strings so that PHP's int-casting of numeric
	 * array keys (`$data['0']` → `0`) still matches the marker's JSON strings.
	 * NUL is used as the joiner because it cannot occur in a form field name.
	 *
	 * @param array $segments Key segments.
	 * @return string|null Null when a segment is not stringable.
	 */
	private static function path_index_key( array $segments ): ?string {
		$parts = array();
		foreach ( $segments as $segment ) {
			if ( ! is_scalar( $segment ) ) {
				return null;
			}
			$parts[] = (string) $segment;
		}
		return implode( "\0", $parts );
	}
}
