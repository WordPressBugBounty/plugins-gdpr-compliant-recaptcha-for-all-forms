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
	 * @param bool     $trust_private     Opt-in (Option::POW_TRUST_PRIVATE_PROXY, default
	 *                                    OFF): treat a private/loopback peer as a trusted
	 *                                    proxy when $trusted_proxies is EMPTY. See
	 *                                    is_private() for what it costs.
	 * @return string
	 */
	public static function resolve( $remote_addr, array $forwarded_headers, array $trusted_proxies, $trust_private = false ) {
		$remote_addr = trim( (string) $remote_addr );

		// The opt-in only applies while NOTHING is configured. Once an operator has
		// filled the trusted-proxy list, that list is the single source of truth — an
		// option that silently widens explicit configuration would be the worse kind of
		// surprise, and "my proxy is listed but another private peer is also believed"
		// is not a state anyone asked for.
		$private_trust = $trust_private
			&& array() === array_filter( array_map( 'trim', $trusted_proxies ) )
			&& self::is_private( $remote_addr );

		// Forwarded headers are only trustworthy if they were set by a proxy we trust.
		if ( ! $private_trust && ! self::is_trusted( $remote_addr, $trusted_proxies ) ) {
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
		//
		// THE PRIVATE-TRUST MODE MUST APPLY TO THE WHOLE CHAIN, not just to REMOTE_ADDR.
		// Trusting only the peer while still treating private addresses in the chain as
		// "untrusted" would stop the walk at the first internal hop: a two-hop setup
		// (XFF "client, 10.0.0.5" arriving from 10.0.0.9) would resolve every visitor to
		// the internal load balancer's address. All visitors would then share one
		// identity, the per-IP row budget would collapse onto it, and the result is mass
		// false positives — the exact failure this option exists to prevent.
		for ( $i = count( $candidates ) - 1; $i >= 0; $i-- ) {
			$candidate = $candidates[ $i ];
			if ( false === filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				continue;
			}
			if ( $private_trust && self::is_private( $candidate ) ) {
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
	 * Split admin-entered address lines into the usable ones and the `/0` ranges.
	 *
	 * PURE, and separate from the save site for the same reason
	 * RestRoute::reject_self_lockout_lines() is: the decision is what needs testing, the
	 * `update_option()` around it is not.
	 *
	 * A `/0` line is rejected because it makes EVERY peer a trusted proxy (see
	 * ip_in_cidr()). matches_list() already refuses to honour one, so this is not the
	 * security fix — that sits at check time and covers entries already in the database.
	 * This is the other half: without it a `/0` line is silently INERT. The operator
	 * typed something, the page saved it, nothing complains, and their proxy still is not
	 * trusted. A setting that quietly does nothing is how someone spends an afternoon
	 * debugging the wrong thing.
	 *
	 * @param string $value Raw textarea content.
	 * @return array{0:string,1:string[]} Cleaned value, and the rejected lines verbatim.
	 */
	public static function reject_all_matching_ranges( $value ) {
		$lines    = preg_split( '/\r\n|\n|\r/', (string) $value );
		$kept     = array();
		$rejected = array();

		foreach ( $lines as $line ) {
			$trimmed = trim( $line );
			if ( '' !== $trimmed && preg_match( '#/0\s*$#', $trimmed ) ) {
				$rejected[] = $trimmed;
				continue;
			}
			$kept[] = $line;
		}

		return array( implode( "\n", $kept ), $rejected );
	}

	/**
	 * Whether $ip is a private, loopback or link-local address — i.e. an address that
	 * cannot have come from the open internet, so a peer bearing it is de facto a
	 * reverse proxy or the local machine.
	 *
	 * Covers RFC1918 (10/8, 172.16/12, 192.168/16), loopback (127/8, ::1), link-local
	 * (169.254/16, fe80::/10) and IPv6 unique-local (fc00::/7). IPv4-mapped IPv6
	 * notations (::ffff:10.0.0.1) are normalised first — a peer arriving in that form is
	 * exactly as private as the same address written plainly, and treating the two
	 * differently would make the option's behaviour depend on the web server's socket
	 * configuration.
	 *
	 * WHAT THIS IS FOR, AND WHAT IT COSTS. It backs Option::POW_TRUST_PRIVATE_PROXY, an
	 * opt-in that is OFF by default. On a site behind a reverse proxy whose operator does
	 * not know (or cannot find out) the proxy's address, every visitor is otherwise seen
	 * under that one address — the "4.x worked, 5.x blocks everything" class of report.
	 * The option heals that without configuration. The price is real and is why it is
	 * not the default: on a site whose genuine visitors come from a private network, any
	 * client could then choose its own address by setting X-Forwarded-For, which makes
	 * the IP whitelist claimable, fail2ban logging useless and per-IP limits bypassable.
	 * That is a decision about a specific installation, so it belongs to its operator.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_private( $ip ) {
		$ip = trim( (string) $ip );
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		// ::ffff:10.0.0.1 and 10.0.0.1 must not answer differently.
		if ( 0 === stripos( $ip, '::ffff:' ) ) {
			$mapped = substr( $ip, 7 );
			if ( false !== filter_var( $mapped, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				$ip = $mapped;
			}
		}

		// FILTER_FLAG_NO_PRIV_RANGE/NO_RES_RANGE would be the obvious tool and is the
		// wrong one: its "reserved" set differs between PHP versions and covers more
		// than this decision is about. The ranges are therefore named explicitly.
		$ranges = array(
			'10.0.0.0/8',
			'172.16.0.0/12',
			'192.168.0.0/16',
			'127.0.0.0/8',
			'169.254.0.0/16',
			'::1/128',
			'fc00::/7',
			'fe80::/10',
		);

		foreach ( $ranges as $range ) {
			if ( self::ip_in_cidr( $ip, $range ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether $ip is a valid IP that matches one of the given entries (exact IP or CIDR
	 * range). THE address-list comparison of this plugin — every admin-configured list
	 * of addresses must go through here.
	 *
	 * Public because two different lists need exactly this semantics and used to have
	 * two different ones: POW_TRUSTED_PROXIES (via is_trusted() below) and
	 * POW_IP_WHITELIST (Stamp::__construct(), which compared with `===` until 5.3.4 —
	 * so an entry whose notation differed from what the proxy actually sends silently
	 * never matched, and no subnet could be entered at all, see ISSUES.md). Two
	 * comparison semantics in one plugin, with the weaker one guarding the whitelist,
	 * is the kind of asymmetry nobody notices until it matters.
	 *
	 * @param string   $ip      Candidate address (server-resolved, never client-posted).
	 * @param string[] $entries Admin-configured lines.
	 * @return bool
	 */
	public static function matches_list( $ip, array $entries ) {
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		foreach ( $entries as $entry ) {
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
	 * Whether $ip is one of the configured trusted proxies. Thin wrapper over
	 * matches_list() so the resolve() walk above keeps reading in proxy terms.
	 *
	 * @param string   $ip
	 * @param string[] $trusted_proxies
	 * @return bool
	 */
	private static function is_trusted( $ip, array $trusted_proxies ) {
		return self::matches_list( $ip, $trusted_proxies );
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

		// A /0 NEVER MATCHES — deliberately, and this is not a formality. With prefix
		// length 0 the byte loop below is skipped and `0 === $bit_remainder` returns
		// true immediately, so `0.0.0.0/0` matched every IPv4 address and `::/0` every
		// IPv6 one. In POW_TRUSTED_PROXIES that means EVERY peer is a trusted proxy:
		// every X-Forwarded-For header is believed, the resolved address becomes freely
		// choosable, and with it the IP whitelist, fail2ban logging and per-IP limits.
		// The path there is not an attack but a plausible operator mistake ("I'm behind
		// a proxy, I'll just enter everything"). Same reasoning as Turnstile 1.42.0,
		// which fixed exactly this in its own whitelist. Rejected here at CHECK time, so
		// entries ALREADY in the option are covered too — the save-time guard
		// (reject_all_matching_ranges(), wired in Settings_Menu::update_settings()) is
		// the other half and exists so the operator is told, not so the site is safe.
		$max_prefix = strlen( $ip_bin ) * 8;
		if ( $prefix_length < 1 || $prefix_length > $max_prefix ) {
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
