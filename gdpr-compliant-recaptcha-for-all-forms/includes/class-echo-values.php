<?php
/**
 * Pure, WordPress-independent value extraction for the value-based spam patterns
 * (BACKLOG "Wertbasierte Spam-Pattern über alle Formulare"): both the wildcard
 * value patterns ({"*":"value"}) and the auto-echo lock.
 *
 * This class knows nothing about WordPress (no options, no $wpdb, no transients,
 * no home_url()) — the WP glue (reading the pattern option, the transient store,
 * the site's own domain) lives in the thin integration layer (Echo_Store and
 * Stamp). That keeps every non-trivial invariant unit-testable in isolation, see
 * tests/unit/EchoValuesTest.php.
 *
 * Two consumers:
 * - Wildcard value matching: collect_user_values()/matches_wildcard_values()/
 *   wildcard_values_from_lines() — an admin-configured {"*":"value"} line matches
 *   when ANY user-content field (any depth) equals that value (trim + lowercase).
 * - Auto-echo lock: build_echo_set() extracts the "core values" of a submission
 *   (sender email, payload domain, phone, long-text hash), returns them as SHA-256
 *   hashes only (GDPR: never store the plaintext of a personally-identifiable
 *   value), and Echo_Store persists/looks them up with a TTL.
 *
 * HARD security invariants (see class docblocks below and the BACKLOG entry):
 * 1. Extraction runs ONLY over user-content fields: technical keys are skipped
 *    (underscore-prefixed, e.g. _wpcf7*, and the referrer/page-URL field-name
 *    blacklist) — otherwise the site's own referrer/page URL in whole_request_data
 *    would seed an echo/wildcard value for the site's own domain (self-DoS).
 * 2. The site's own registrable domain is NEVER emitted as an echo value — the
 *    caller passes its own domain(s) as the $own_domains exclude list, and URL
 *    extraction drops any URL resolving to them. This is the SECOND, independent
 *    defense line to invariant 1 (either alone must already prevent the self-block).
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
 * Stateless value extraction / normalization for the value-based spam patterns.
 */
final class Echo_Values {

	/**
	 * Multi-part public suffixes (eTLD) where the registrable domain (eTLD+1) is
	 * the last THREE labels, not the last two. Deliberately a curated, conservative
	 * built-in list — NOT the full Public Suffix List (no external dependency, no
	 * bundled ~10k-entry file to keep in sync). Being incomplete is safe: a missing
	 * multi-part suffix only means we echo one label too FEW (e.g. "co.uk" instead
	 * of "spam.co.uk"), which never blocks more than intended — at worst it fails to
	 * block. Extend as real misses show up in field data.
	 *
	 * @var string[]
	 */
	const MULTI_PART_SUFFIXES = array(
		'co.uk',
		'org.uk',
		'gov.uk',
		'ac.uk',
		'net.uk',
		'sch.uk',
		'ltd.uk',
		'plc.uk',
		'me.uk',
		'com.au',
		'net.au',
		'org.au',
		'edu.au',
		'gov.au',
		'com.br',
		'com.mx',
		'com.ar',
		'co.jp',
		'ne.jp',
		'or.jp',
		'co.nz',
		'co.za',
		'co.in',
		'com.cn',
		'com.tr',
		'com.sg',
		'com.hk',
		'com.tw',
	);

	/**
	 * Hosts where the PATH (not just the domain) carries the sender's identity:
	 * messenger deep-links and URL shorteners. For these, the echo/block value is
	 * "host/first-path-segment" (e.g. "t.me/spammer123") rather than the bare host —
	 * otherwise blocking one Telegram spammer's link would block every t.me link on
	 * the site. Curated const, extend as needed.
	 *
	 * @var string[]
	 */
	const PATH_IDENTITY_HOSTS = array(
		't.me',
		'wa.me',
		'telegram.me',
		'bit.ly',
		'tinyurl.com',
		'goo.gl',
		'is.gd',
		'cutt.ly',
		'rb.gy',
		'linktr.ee',
	);

	/**
	 * Exact (case-insensitive) field names that are technical, not user content,
	 * and must never be extracted from — they typically carry the site's own
	 * referrer/page URL. This is in addition to the underscore-prefix rule in
	 * is_technical_key() (covers _wpcf7_container_post, _wpcf7_unit_tag,
	 * _wp_http_referer, …). Kept to the exact blacklist from the BACKLOG entry.
	 *
	 * @var string[]
	 */
	const TECHNICAL_FIELD_NAMES = array( 'referer', 'referrer', 'page_url', 'url' );

	/**
	 * Minimum number of NORMALIZED characters (letters/digits, whitespace and
	 * punctuation removed) a text value must have before its hash is echoed. Below
	 * this, short standard values ("yes", first names, "Berlin") would collide and
	 * cause false positives, so they are ignored. Deliberately exact, not fuzzy.
	 */
	const TEXT_HASH_MIN_LENGTH = 40;

	/** Minimum digit count for a value to be treated as a phone number. */
	const PHONE_MIN_DIGITS = 7;

	/** Recursion depth cap for the field walk (defensive; forms rarely nest deep). */
	const MAX_DEPTH = 6;

	/**
	 * SHA-256 of a value (lower-case hex, 64 chars). All echo values are stored and
	 * compared ONLY as this hash (GDPR: no plaintext of an email/phone/text).
	 *
	 * @param string $value Input.
	 * @return string 64-char lower-case hex digest.
	 */
	public static function hash_value( $value ) {
		return hash( 'sha256', (string) $value, false );
	}

	/**
	 * Whether a field key is technical (not user content) and must be skipped:
	 * underscore-prefixed (e.g. _wpcf7*) or in TECHNICAL_FIELD_NAMES.
	 *
	 * @param string $key Field key.
	 * @return bool
	 */
	public static function is_technical_key( $key ) {
		$key = (string) $key;
		if ( '' === $key ) {
			return false;
		}
		if ( '_' === $key[0] ) {
			return true;
		}
		return in_array( strtolower( $key ), self::TECHNICAL_FIELD_NAMES, true );
	}

	/**
	 * Collect the raw string leaves of the user-content fields of a submission,
	 * recursively, skipping technical keys (see is_technical_key()) at every level.
	 * Non-array/non-scalar values are ignored; empty strings dropped.
	 *
	 * @param mixed $fields Field map (request-derived, so not guaranteed an array).
	 * @param int   $depth  Current recursion depth (internal).
	 * @return string[] User-content string values.
	 */
	public static function collect_content_strings( $fields, $depth = 0 ) {
		$out = array();
		if ( $depth > self::MAX_DEPTH || ! is_array( $fields ) ) {
			return $out;
		}
		foreach ( $fields as $key => $value ) {
			if ( self::is_technical_key( (string) $key ) ) {
				continue;
			}
			if ( is_array( $value ) ) {
				$out = array_merge( $out, self::collect_content_strings( $value, $depth + 1 ) );
			} elseif ( is_scalar( $value ) ) {
				$string = (string) $value;
				if ( '' !== $string ) {
					$out[] = $string;
				}
			}
		}
		return $out;
	}

	/**
	 * Normalize a value for wildcard comparison: trim + lowercase, exactly as the
	 * BACKLOG entry specifies.
	 *
	 * @param string $value Raw value.
	 * @return string Normalized value.
	 */
	public static function normalize_wildcard( $value ) {
		return strtolower( trim( (string) $value ) );
	}

	/**
	 * Collect the normalized (trim + lowercase) user-content string values of a
	 * submission, for wildcard-value comparison.
	 *
	 * @param mixed $fields Field map.
	 * @return string[]
	 */
	public static function collect_user_values( $fields ) {
		$out = array();
		foreach ( self::collect_content_strings( $fields ) as $string ) {
			$out[] = self::normalize_wildcard( $string );
		}
		return $out;
	}

	/**
	 * Extract the normalized wildcard values from a set of raw POW_PARAMETER_PATTERN
	 * lines: a line is a wildcard line iff it JSON-decodes to a single-entry object
	 * {"*":"value"} with a string value. Non-wildcard pattern lines are ignored.
	 *
	 * @param string[] $lines Raw pattern lines.
	 * @return string[] Unique, normalized, non-empty wildcard values.
	 */
	public static function wildcard_values_from_lines( $lines ) {
		$values = array();
		foreach ( (array) $lines as $line ) {
			$line = trim( (string) $line );
			if ( '' === $line ) {
				continue;
			}
			$decoded = json_decode( $line, true );
			if ( ! is_array( $decoded ) || 1 !== count( $decoded ) || ! array_key_exists( '*', $decoded ) || ! is_string( $decoded['*'] ) ) {
				continue;
			}
			$value = self::normalize_wildcard( $decoded['*'] );
			if ( '' !== $value ) {
				$values[] = $value;
			}
		}
		return array_values( array_unique( $values ) );
	}

	/**
	 * Whether any user-content field of $fields matches one of the already-normalized
	 * $wildcard_values. Three comparisons per field value, so a one-click block stays
	 * effective when the blocked value is EMBEDDED in message text rather than being
	 * the whole field ("Block this domain" would otherwise be near-useless — spam
	 * links live inside the message body, not in a field equal to "spam.com"):
	 * 1. whole-value equality (trim + lowercase — the literal spec rule),
	 * 2. every email address extracted from the value,
	 * 3. the registrable domain (or path identity) of every URL extracted from the
	 *    value — with $own_domains excluded, so even a hand-typed wildcard line for
	 *    the site's own domain can never match a legitimate submission that merely
	 *    contains an internal link (same defense line as in build_echo_set()).
	 *
	 * @param mixed    $fields          Field map.
	 * @param string[] $wildcard_values Normalized wildcard values.
	 * @param string[] $own_domains     Registrable domains of the site itself,
	 *                                  excluded from URL-domain extraction.
	 * @return bool
	 */
	public static function matches_wildcard_values( $fields, $wildcard_values, $own_domains = array() ) {
		if ( empty( $wildcard_values ) ) {
			return false;
		}
		$set = array_flip( $wildcard_values );
		foreach ( self::collect_content_strings( $fields ) as $string ) {
			if ( isset( $set[ self::normalize_wildcard( $string ) ] ) ) {
				return true;
			}
			foreach ( self::extract_emails( $string ) as $email ) {
				if ( isset( $set[ $email ] ) ) {
					return true;
				}
			}
			foreach ( self::extract_urls( $string ) as $url ) {
				$domain = self::registrable_domain( $url, $own_domains );
				if ( null !== $domain && isset( $set[ $domain ] ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Find URL-like substrings in a text value (http(s):// or bare www.).
	 *
	 * @param string $text Value.
	 * @return string[] Raw URL substrings.
	 */
	public static function extract_urls( $text ) {
		$text = (string) $text;
		if ( '' === $text ) {
			return array();
		}
		$matches = array();
		if ( preg_match_all( '#(?:https?://|www\.)[^\s<>"\'\)\]\},;]+#i', $text, $found ) ) {
			$matches = $found[0];
		}
		return $matches;
	}

	/**
	 * Find email addresses in a text value, trimmed + lowercased.
	 *
	 * @param string $text Value.
	 * @return string[] Lower-cased email addresses.
	 */
	public static function extract_emails( $text ) {
		$text = (string) $text;
		if ( '' === $text ) {
			return array();
		}
		$emails = array();
		if ( preg_match_all( '/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/', $text, $found ) ) {
			foreach ( $found[0] as $email ) {
				$emails[] = strtolower( trim( $email ) );
			}
		}
		return array_values( array_unique( $emails ) );
	}

	/**
	 * Convenience: the first email found in a value, or null. Used by the one-click
	 * "Block this sender" callback.
	 *
	 * @param string $text Value.
	 * @return string|null
	 */
	public static function extract_email( $text ) {
		$emails = self::extract_emails( $text );
		return empty( $emails ) ? null : $emails[0];
	}

	/**
	 * SHA-256 hashes of a list of raw email addresses, normalized (trim + lowercase)
	 * exactly like extract_emails(), so a hash produced here is bit-identical to the
	 * one build_echo_set() would emit for the same address. Empty/blank entries are
	 * dropped, the result is de-duplicated.
	 *
	 * Used by the WP glue (Echo_Store) to build the exclude set of registered-user
	 * emails: a value that belongs to a real user account must never be recorded as,
	 * or matched against, an echo value — otherwise an attacker who submits spam
	 * carrying a legitimate user's address could get that user echo-locked and thereby
	 * blocked at login / password-reset (the check runs there too). GDPR: only the
	 * hashes leave this method, never the plaintext addresses.
	 *
	 * @param string[] $emails Raw email addresses.
	 * @return string[] Unique SHA-256 hashes (lower-case hex).
	 */
	public static function hash_emails( $emails ) {
		$out = array();
		foreach ( (array) $emails as $email ) {
			$normalized = strtolower( trim( (string) $email ) );
			if ( '' !== $normalized ) {
				$out[ self::hash_value( $normalized ) ] = true;
			}
		}
		return array_keys( $out );
	}

	/**
	 * The registrable domain (eTLD+1) of a URL, or null when it does not resolve to
	 * a real domain (bare word, IP literal — the explicit NOT-IP rule — or one of
	 * the $own_domains). For a PATH_IDENTITY_HOSTS host the result is
	 * "host/first-path-segment". Accepts a full URL, a scheme-less URL, or a bare
	 * host/domain.
	 *
	 * @param string   $url          URL, scheme-less URL, or bare domain.
	 * @param string[] $own_domains  Registrable domains of the site itself, excluded.
	 * @return string|null
	 */
	public static function registrable_domain( $url, $own_domains = array() ) {
		$url = trim( (string) $url );
		if ( '' === $url ) {
			return null;
		}
		// Strip scheme.
		$url = (string) preg_replace( '#^[a-zA-Z][a-zA-Z0-9+.\-]*://#', '', $url );

		// Split host(+port) from path/query/fragment at the first slash.
		$host_part = $url;
		$path_part = '';
		$slash     = strpos( $url, '/' );
		if ( false !== $slash ) {
			$host_part = substr( $url, 0, $slash );
			$path_part = substr( $url, $slash + 1 );
		}
		// Drop query/fragment attached without a slash (host?x=1 / host#a).
		foreach ( array( '?', '#' ) as $separator ) {
			$position = strpos( $host_part, $separator );
			if ( false !== $position ) {
				$host_part = substr( $host_part, 0, $position );
			}
		}
		// Strip any leading userinfo (the part before an at-sign).
		$at = strrpos( $host_part, '@' );
		if ( false !== $at ) {
			$host_part = substr( $host_part, $at + 1 );
		}

		$host = strtolower( trim( $host_part ) );
		if ( '' === $host ) {
			return null;
		}
		// Bracketed IPv6 literal → not a domain (explicit NOT-IP rule).
		if ( '[' === $host[0] ) {
			return null;
		}
		// Strip a leading www.
		if ( 0 === strpos( $host, 'www.' ) ) {
			$host = substr( $host, 4 );
		}
		// Strip :port.
		$colon = strpos( $host, ':' );
		if ( false !== $colon ) {
			$host = substr( $host, 0, $colon );
		}
		if ( '' === $host ) {
			return null;
		}
		// IPv4 literal → not a domain (explicit NOT-IP rule).
		if ( false !== filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return null;
		}
		// Needs at least one dot to be a domain.
		if ( false === strpos( $host, '.' ) ) {
			return null;
		}

		// Path-identity hosts: domain + first path segment is the identity.
		if ( in_array( $host, self::PATH_IDENTITY_HOSTS, true ) ) {
			if ( in_array( $host, $own_domains, true ) ) {
				return null;
			}
			$result = $host;
			if ( '' !== $path_part ) {
				$segment = $path_part;
				foreach ( array( '/', '?', '#' ) as $separator ) {
					$position = strpos( $segment, $separator );
					if ( false !== $position ) {
						$segment = substr( $segment, 0, $position );
					}
				}
				$segment = strtolower( trim( $segment ) );
				if ( '' !== $segment ) {
					$result = $host . '/' . $segment;
				}
			}
			return $result;
		}

		// eTLD+1 via the curated multi-part suffix list.
		$labels   = explode( '.', $host );
		$count    = count( $labels );
		$last_two = $labels[ $count - 2 ] . '.' . $labels[ $count - 1 ];
		if ( $count >= 3 && in_array( $last_two, self::MULTI_PART_SUFFIXES, true ) ) {
			$domain = $labels[ $count - 3 ] . '.' . $last_two;
		} else {
			$domain = $last_two;
		}
		if ( in_array( $domain, $own_domains, true ) ) {
			return null;
		}
		return $domain;
	}

	/**
	 * Normalize a value to a bare phone digit-string, or null when it is not
	 * phone-shaped. Value-based (not field-name-based) detection is deliberate: the
	 * field name varies across form builders (the very problem this feature solves),
	 * so a shape guard on the value is more robust. A leading "+" becomes a "00"
	 * prefix; the value must carry at least PHONE_MIN_DIGITS digits so arbitrary
	 * numbers (order totals, years) are not mistaken for phone numbers.
	 *
	 * @param string $value Value.
	 * @return string|null Digit string, or null.
	 */
	public static function normalize_phone( $value ) {
		$value = trim( (string) $value );
		if ( '' === $value ) {
			return null;
		}
		// Shape guard: only phone-plausible characters.
		if ( 1 !== preg_match( '#^\+?[0-9 ()/.\-]{6,}$#', $value ) ) {
			return null;
		}
		$has_plus = 0 === strpos( $value, '+' );
		$digits   = (string) preg_replace( '/\D+/', '', $value );
		if ( strlen( $digits ) < self::PHONE_MIN_DIGITS ) {
			return null;
		}
		return $has_plus ? '00' . $digits : $digits;
	}

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

	/**
	 * Build the set of echo hashes for a submission: the SHA-256 of every extracted
	 * core value (sender email, payload domain/path-identity, phone, long-text). The
	 * site's own registrable domain(s) are excluded from URL extraction. The result
	 * contains ONLY 64-char hex hashes — never a plaintext value (GDPR).
	 *
	 * @param mixed    $fields          Field map (user-content extraction; technical keys skipped).
	 * @param string[] $own_domains     Registrable domains of the site itself, excluded.
	 * @param string[] $excluded_hashes SHA-256 hashes that must never be emitted (e.g.
	 *                                  registered-user email hashes from hash_emails()).
	 *                                  A THIRD, value-level defense line alongside the
	 *                                  technical-key skip (invariant 1) and the own-domain
	 *                                  drop (invariant 2): it lets the WP glue keep any
	 *                                  value that belongs to a real account out of the echo
	 *                                  lock, so submitting spam with a user's address cannot
	 *                                  lock that user out at login/password-reset.
	 * @return string[] Unique SHA-256 hashes.
	 */
	public static function build_echo_set( $fields, $own_domains = array(), $excluded_hashes = array() ) {
		$hashes = array();
		foreach ( self::collect_content_strings( $fields ) as $value ) {
			foreach ( self::extract_emails( $value ) as $email ) {
				$hashes[ self::hash_value( $email ) ] = true;
			}
			foreach ( self::extract_urls( $value ) as $url ) {
				$domain = self::registrable_domain( $url, $own_domains );
				if ( null !== $domain ) {
					$hashes[ self::hash_value( $domain ) ] = true;
				}
			}
			$phone = self::normalize_phone( $value );
			if ( null !== $phone ) {
				$hashes[ self::hash_value( $phone ) ] = true;
			}
			$text = self::normalize_text( $value );
			if ( null !== $text ) {
				$hashes[ self::hash_value( $text ) ] = true;
			}
		}
		foreach ( (array) $excluded_hashes as $excluded ) {
			unset( $hashes[ $excluded ] );
		}
		return array_keys( $hashes );
	}
}
