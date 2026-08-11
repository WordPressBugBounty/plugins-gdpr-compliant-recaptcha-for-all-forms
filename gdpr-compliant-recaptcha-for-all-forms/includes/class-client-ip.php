<?php
/**
 * Pure, WordPress-independent client-IP resolution behind a trusted-proxy allowlist.
 *
 * This is the single source of truth for turning REMOTE_ADDR + Forwarded-For-style
 * headers into "the" client IP. It has NO WordPress dependencies (no $_SERVER/getenv,
 * no options), which makes it unit-testable in isolation — see
 * tests/unit/ClientIpTest.php. Stamp::get_client_ip() reads the raw request values and
 * delegates the actual decision here.
 *
 * Trusted-proxy concept: Forwarded-For-style headers are entirely client-settable, so
 * honoring them unconditionally lets a bot spoof a whitelisted IP or rotate IPs at will.
 * Here, REMOTE_ADDR (the TCP peer WordPress/PHP itself observed — not spoofable) is
 * always the base. Headers are only consulted when REMOTE_ADDR itself is a known/
 * trusted proxy, and then only the right-most IP in the chain that is NOT itself a
 * trusted proxy is used — this stops a client behind a real trusted proxy from
 * prepending forged entries to the chain. Only X-Forwarded-For is consulted at all;
 * see HEADER_PRIORITY for why the four other headers were dropped.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/pow.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Stateless client-IP resolution helpers.
 */
final class ClientIp {

	/**
	 * The ONLY forwarding header that is honored. Public so Stamp::get_client_ip() can
	 * collect exactly these from $_SERVER instead of keeping a second, drifting list.
	 *
	 * WHY THE OTHER FOUR ARE GONE (they used to be honored, in priority order, ahead of
	 * X-Forwarded-For): all of them are plain client-settable request headers with no
	 * validation whatsoever, and the priority loop below runs BEFORE the rightmost-
	 * untrusted walk — so a single forged header outranked the real proxy chain. That
	 * includes HTTP_FORWARDED: RFC 7239's `for=…` syntax is a convention, not a
	 * validation, and a bare `Forwarded: 6.6.6.6` passes FILTER_VALIDATE_IP just fine.
	 * The spoof hit precisely the CORRECTLY configured sites: a real proxy appends to
	 * X-Forwarded-For but passes the other headers through untouched, so an attacker
	 * could displace the proxy-supplied address and impersonate a whitelisted IP.
	 * Exotic setups whose proxy sets only Client-IP now fall back to REMOTE_ADDR —
	 * flagged in the changelog; token validity no longer depends on the IP either way.
	 *
	 * @var string[]
	 */
	public const HEADER_PRIORITY = array(
		'HTTP_X_FORWARDED_FOR',
	);

	/**
	 * Forwarding headers that merely INDICATE "this request came through a proxy",
	 * for the settings-page hint that offers configuring POW_TRUSTED_PROXIES. Never
	 * used for resolution — resolve() honors HEADER_PRIORITY and nothing else.
	 *
	 * @var string[]
	 */
	public const DIAGNOSTIC_HEADERS = array(
		'HTTP_X_FORWARDED_FOR',
		'HTTP_CLIENT_IP',
		'HTTP_X_FORWARDED',
		'HTTP_FORWARDED_FOR',
		'HTTP_FORWARDED',
	);

	/**
	 * Resolve the client IP for a request.
	 *
	 * @param string   $remote_addr       The connection's REMOTE_ADDR. Always the base/
	 *                                    fallback value.
	 * @param string[] $forwarded_headers Map of header name (see HEADER_PRIORITY) => raw
	 *                                    header value (may be a comma-separated chain).
	 * @param string[] $trusted_proxies   List of trusted IPs and/or CIDR ranges (IPv4 and
	 *                                    IPv6). Invalid entries are ignored.
	 * @return string
	 */
	public static function resolve( $remote_addr, array $forwarded_headers, array $trusted_proxies ) {
		$remote_addr = trim( (string) $remote_addr );

		// Forwarded headers are only trustworthy if they were set by a proxy we trust.
		if ( ! self::is_trusted( $remote_addr, $trusted_proxies ) ) {
			return $remote_addr;
		}

		$header_value = '';
		foreach ( self::HEADER_PRIORITY as $header_name ) {
			if ( isset( $forwarded_headers[ $header_name ] ) && '' !== trim( (string) $forwarded_headers[ $header_name ] ) ) {
				$header_value = (string) $forwarded_headers[ $header_name ];
				break;
			}
		}

		if ( '' === $header_value ) {
			return $remote_addr;
		}

		$candidates = array_map( 'trim', explode( ',', $header_value ) );

		// Rightmost-untrusted: walk from the end (the hop closest to us) backwards. Each
		// trusted proxy along the way is expected to append the IP of whoever it talked
		// to; the first entry (from the right) that isn't itself a trusted proxy is the
		// most credible "real" client IP.
		for ( $i = count( $candidates ) - 1; $i >= 0; $i-- ) {
			$candidate = $candidates[ $i ];
			if ( false === filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				continue;
			}
			if ( ! self::is_trusted( $candidate, $trusted_proxies ) ) {
				return $candidate;
			}
		}

		// Only trusted proxies (or no valid IP at all) in the chain — fall back.
		return $remote_addr;
	}

	/**
	 * Whether $ip is a valid IP that matches one of the trusted entries (exact IP or
	 * CIDR range).
	 *
	 * @param string   $ip
	 * @param string[] $trusted_proxies
	 * @return bool
	 */
	private static function is_trusted( $ip, array $trusted_proxies ) {
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		foreach ( $trusted_proxies as $entry ) {
			$entry = trim( (string) $entry );
			if ( '' === $entry ) {
				continue;
			}
			if ( false !== strpos( $entry, '/' ) ) {
				if ( self::ip_in_cidr( $ip, $entry ) ) {
					return true;
				}
			} elseif ( self::ips_equal( $ip, $entry ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether $ip lies within the CIDR range $cidr. Supports IPv4 and IPv6 via
	 * inet_pton() byte/bitmask comparison. Malformed CIDR entries never match.
	 *
	 * @param string $ip
	 * @param string $cidr
	 * @return bool
	 */
	private static function ip_in_cidr( $ip, $cidr ) {
		$parts = explode( '/', $cidr, 2 );
		if ( 2 !== count( $parts ) ) {
			return false;
		}

		list( $subnet, $prefix_length ) = $parts;

		if ( ! ctype_digit( $prefix_length ) ) {
			return false;
		}
		$prefix_length = (int) $prefix_length;

		if ( false === filter_var( $subnet, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		$ip_bin     = inet_pton( $ip );
		$subnet_bin = inet_pton( $subnet );
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			// Mismatched address families (IPv4 vs IPv6) never match.
			return false;
		}

		$max_prefix = strlen( $ip_bin ) * 8;
		if ( $prefix_length < 0 || $prefix_length > $max_prefix ) {
			return false;
		}

		$byte_count    = intdiv( $prefix_length, 8 );
		$bit_remainder = $prefix_length % 8;

		if ( $byte_count > 0 && substr( $ip_bin, 0, $byte_count ) !== substr( $subnet_bin, 0, $byte_count ) ) {
			return false;
		}

		if ( 0 === $bit_remainder ) {
			return true;
		}

		$mask = chr( ( 0xFF << ( 8 - $bit_remainder ) ) & 0xFF );

		return ( $ip_bin[ $byte_count ] & $mask ) === ( $subnet_bin[ $byte_count ] & $mask );
	}

	/**
	 * Whether $a and $b denote the same IP, comparing via inet_pton() so equivalent
	 * IPv6 notations (e.g. "::1" vs "0:0:0:0:0:0:0:1") compare equal.
	 *
	 * @param string $a
	 * @param string $b
	 * @return bool
	 */
	private static function ips_equal( $a, $b ) {
		if ( false === filter_var( $b, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		$a_bin = inet_pton( $a );
		$b_bin = inet_pton( $b );
		return false !== $a_bin && false !== $b_bin && $a_bin === $b_bin;
	}
}
