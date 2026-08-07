<?php
/**
 * Pure, WordPress-independent submission-binding token (AP3 of the anti-spam
 * hardening plan, see ANTISPAM_HARDENING_PLAN.md / AP3_TOKEN_DESIGN.md).
 *
 * A token replaces the old per-IP/time-bucket "stamp" as the thing the client's
 * proof-of-work is computed over. It is a fixed-width, purely hex string
 * ([0-9a-f] only, so the existing check_stamp() sanitisation of `[^a-zA-Z0-9]`
 * never mangles it). CURRENT FORMAT — v2, 100 chars:
 *
 *   DD IIIIIIIIII FFFFFFFF RRRRRRRRRRRRRRRR HHHH…(64)
 *   │  │          │        │                └ hmac = hash_hmac('sha256', DD.'|'.II.'|'.FF.'|'.RR, salt)
 *   │  │          │        └ random: 16 hex chars, caller-supplied (8 bytes random_bytes())
 *   │  │          └ fingerprint: 8 hex chars, keyed hash of the issuing IP — DIAGNOSIS ONLY
 *   │  └ issued_at: unix time, 10 digits, zero-padded
 *   └ difficulty: 2 digits, zero-padded (difficulty travels IN the token — AP4 prep)
 *
 * Fixed-width parsing (2/10/8/16/64), no separator.
 *
 * NO IP IN THE HMAC (v2, see POW_IP_BINDING_PLAN.md). The v1 format (92 chars, still
 * accepted for one release via create()/verify() below) bound the server-resolved IP
 * into the HMAC, which made every honest client whose observed address changes between
 * issuing and solving — page/response cache in front of get_stamp, proxy pool, plain
 * IPv4/IPv6 dual stack — fail verification and be classified as spam. Validity is
 * therefore IP-FREE now: the token identifies itself (its own row is looked up by
 * rgs_stamp), the IP was only ever an extra condition on top. What the HMAC still
 * binds is difficulty, issue time, the fingerprint and the random component, so none
 * of those can be forged, and the token stays entirely stateless: an unsolved token
 * never touches the database (Stamp::get_stamp() just returns one; nothing is written
 * until Stamp::check_stamp() sees a solved PoW), so flooding get_stamp() creates no
 * server-side state to clean up.
 *
 * THE FINGERPRINT IS DIAGNOSIS, NEVER A DECISION. FF is a keyed (non-reversible) hash
 * of the IP the token was issued to, so a site owner can SEE how often solves come back
 * from a different address than they were issued to (cache/proxy rotation). No code path
 * may derive an accept/reject/re-challenge decision from fp_status() — the whole point
 * of v2 is that validity does not depend on the IP. The render-path token carries
 * FP_ANONYMOUS because that path deliberately resolves no IP at all (privacy: no IP,
 * hashed or not, ends up in the page source).
 *
 * No WordPress dependencies (no options, no $wpdb) → unit-testable in isolation,
 * see tests/unit/StampTokenTest.php. Stamp::get_stamp()/check_stamp() are the only
 * callers on the server side; the client never inspects the token's structure, it
 * only ever uses it as an opaque string to run the same hashcash search over
 * (scripts/recaptcha-gdpr-pow.js, unchanged proof-of-work algorithm).
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Stateless submission-binding token helpers.
 */
final class StampToken {

	/** LEGACY (v1) token length: 2 (difficulty) + 10 (issued_at) + 16 (random) + 64 (hmac). */
	const LENGTH = 92;

	/** Current (v2) token length: 2 + 10 (issued_at) + 8 (fingerprint) + 16 (random) + 64 (hmac). */
	const LENGTH_V2 = 100;

	/**
	 * Fingerprint field of a token that was issued WITHOUT resolving an IP at all (the
	 * render path, see Stamp::add_script_to_header()). A real fingerprint could collide
	 * with this value with probability 2^-32; the only consequence is that one solve is
	 * counted as "anonymous" instead of matched — diagnosis noise, never a decision.
	 */
	const FP_ANONYMOUS = '00000000';

	/** fp_status(): the token was issued to the address that is now solving it. */
	const STATUS_MATCH = 'match';

	/** fp_status(): the token was issued to a DIFFERENT address (cache/proxy/rotation). */
	const STATUS_MISMATCH = 'mismatch';

	/** fp_status(): the token carries no fingerprint (render path), or is unparseable. */
	const STATUS_ANONYMOUS = 'anonymous';

	/**
	 * Keyed, non-reversible 8-hex fingerprint of an IP: the first 8 hex chars of
	 * hash_hmac('sha256', ip, salt). Keyed on purpose — an unkeyed hash of an IPv4
	 * address is trivially reversible by enumeration (2^32 candidates), which would put
	 * a de-facto plaintext IP into a token that travels through caches.
	 *
	 * @param string $ip   Server-resolved client IP.
	 * @param string $salt Server-side HMAC key (Option::POW_SALT).
	 * @return string 8 lower-case hex chars.
	 */
	public static function fingerprint( $ip, $salt ) {
		return substr( hash_hmac( 'sha256', (string) $ip, (string) $salt ), 0, 8 );
	}

	/**
	 * Normalise a fingerprint into the FF field's exact shape. Anything that is not 8
	 * lower-case hex chars degrades to FP_ANONYMOUS rather than corrupting the token's
	 * length invariant (a caller can only ever produce this by passing garbage).
	 *
	 * @param mixed $fp Candidate fingerprint.
	 * @return string
	 */
	private static function normalize_fp( $fp ) {
		$fp = strtolower( (string) $fp );
		return 1 === preg_match( '/^[0-9a-f]{8}$/', $fp ) ? $fp : self::FP_ANONYMOUS;
	}

	/**
	 * Build a v2 token string (100 chars). Takes a FINGERPRINT, never an IP — the
	 * IP-freeness of token validity is the point of the format, so this signature is
	 * the place it is enforced (and pinned by StampTokenV2Test).
	 *
	 * @param string $fp         8-hex fingerprint (self::fingerprint()) or FP_ANONYMOUS.
	 * @param string $salt       Server-side HMAC key (Option::POW_SALT).
	 * @param int    $difficulty Number of leading zero bits the PoW must meet.
	 * @param int    $issued_at  Unix timestamp the token was issued at.
	 * @param string $random_hex 16 lower-case hex chars of caller-supplied randomness.
	 * @return string 100-char token.
	 */
	public static function create_v2( $fp, $salt, $difficulty, $issued_at, $random_hex ) {
		$difficulty_part = sprintf( '%02d', max( 0, min( 99, (int) $difficulty ) ) );
		$issued_at_part  = sprintf( '%010d', max( 0, (int) $issued_at ) );
		$fp_part         = self::normalize_fp( $fp );
		$random_part     = strtolower( (string) $random_hex );

		$hmac = hash_hmac(
			'sha256',
			$difficulty_part . '|' . $issued_at_part . '|' . $fp_part . '|' . $random_part,
			(string) $salt
		);

		return $difficulty_part . $issued_at_part . $fp_part . $random_part . $hmac;
	}

	/**
	 * Parse a v2 token into its fields, strictly validating shape/length/charset.
	 *
	 * @param mixed $token Candidate token.
	 * @return array{difficulty:int,issued_at:int,fp:string,random:string,hmac:string}|null
	 */
	public static function parse_v2( $token ) {
		if ( ! is_string( $token ) || self::LENGTH_V2 !== strlen( $token ) ) {
			return null;
		}
		if ( ! preg_match( '/^[0-9a-f]{100}$/', $token ) ) {
			return null;
		}

		$difficulty_part = substr( $token, 0, 2 );
		$issued_at_part  = substr( $token, 2, 10 );
		$fp_part         = substr( $token, 12, 8 );
		$random_part     = substr( $token, 20, 16 );
		$hmac_part       = substr( $token, 36, 64 );

		// DD/II are sprintf('%0Nd', ...)-formatted decimal by create_v2() and must never
		// contain a-f (the FF field may — it is a hash). Same strictness as parse().
		if ( ! ctype_digit( $difficulty_part ) || ! ctype_digit( $issued_at_part ) ) {
			return null;
		}

		return array(
			'difficulty' => (int) $difficulty_part,
			'issued_at'  => (int) $issued_at_part,
			'fp'         => $fp_part,
			'random'     => $random_part,
			'hmac'       => $hmac_part,
		);
	}

	/**
	 * Verify a v2 token: well-formed, HMAC matches for the given salt (hash_equals,
	 * timing-safe), not expired, and not implausibly far in the future.
	 *
	 * DELIBERATELY HAS NO IP PARAMETER. Adding one back — in any form, "just to be
	 * safe" — reintroduces exactly the regression this format exists to fix: an honest
	 * visitor whose observed address changes between issuing and solving (cache, proxy
	 * pool, IPv4/IPv6 dual stack) would fail here and be classified as spam. Rate
	 * limiting and identity stay with the distrustfully resolved IP elsewhere
	 * (Stamp::consume_ip_row(), whitelist, fail2ban) — validity does not.
	 *
	 * @param string $token          Candidate token.
	 * @param string $salt           Server-side HMAC key (Option::POW_SALT).
	 * @param int    $now            Current unix timestamp.
	 * @param int    $window_minutes Configured validity window (Option::POW_TIME_WINDOW);
	 *                               clamped to a minimum of 1, as in verify().
	 * @return bool
	 */
	public static function verify_integrity( $token, $salt, $now, $window_minutes ) {
		$parsed = self::parse_v2( $token );
		if ( null === $parsed ) {
			return false;
		}

		$expected = self::create_v2( $parsed['fp'], $salt, $parsed['difficulty'], $parsed['issued_at'], $parsed['random'] );
		if ( ! hash_equals( $expected, (string) $token ) ) {
			return false;
		}

		$now = (int) $now;

		// Future-skew tolerance and expiry are identical to verify() — only the IP
		// condition is gone.
		if ( $parsed['issued_at'] > ( $now + 120 ) ) {
			return false;
		}

		$window_seconds = ( max( 1, (int) $window_minutes ) + 2 ) * 60;
		if ( ( $now - $parsed['issued_at'] ) > $window_seconds ) {
			return false;
		}

		return true;
	}

	/**
	 * PURE DIAGNOSIS: does this token's fingerprint match the address observing it now?
	 *
	 * The answer feeds counters and the dashboard, nothing else. A MISMATCH is NOT a
	 * reason to reject, re-challenge or raise difficulty — it is the expected outcome on
	 * a cached page or behind a rotating proxy, i.e. exactly the honest-visitor case v2
	 * was built to stop punishing.
	 *
	 * @param string $token Candidate v2 token.
	 * @param string $ip    Server-resolved client IP of the CURRENT request.
	 * @param string $salt  Server-side HMAC key (Option::POW_SALT).
	 * @return string One of STATUS_MATCH | STATUS_MISMATCH | STATUS_ANONYMOUS.
	 */
	public static function fp_status( $token, $ip, $salt ) {
		$parsed = self::parse_v2( $token );
		// Unparseable: nothing can be concluded, so it feeds neither counter.
		if ( null === $parsed || self::FP_ANONYMOUS === $parsed['fp'] ) {
			return self::STATUS_ANONYMOUS;
		}

		return hash_equals( self::fingerprint( $ip, $salt ), $parsed['fp'] )
			? self::STATUS_MATCH
			: self::STATUS_MISMATCH;
	}

	/**
	 * Build a LEGACY (v1) token string.
	 *
	 * Kept unchanged for one release so tokens issued by the previous version — and
	 * still in flight in a browser tab or a cached page — keep verifying. Removal is
	 * tracked in BACKLOG.md; nothing new is ever issued in this format.
	 *
	 * @param string $ip         Client IP the token is bound to (server-resolved).
	 * @param string $salt       Server-side HMAC key (Option::POW_SALT).
	 * @param int    $difficulty Number of leading zero bits the PoW must meet.
	 * @param int    $issued_at  Unix timestamp the token was issued at.
	 * @param string $random_hex 16 lower-case hex chars of caller-supplied randomness
	 *                           (e.g. bin2hex(random_bytes(8))) — kept out of this pure
	 *                           function so it stays deterministic and testable.
	 * @return string 92-char token.
	 */
	public static function create( $ip, $salt, $difficulty, $issued_at, $random_hex ) {
		$difficulty_part = sprintf( '%02d', max( 0, min( 99, (int) $difficulty ) ) );
		$issued_at_part  = sprintf( '%010d', max( 0, (int) $issued_at ) );
		$random_part     = strtolower( (string) $random_hex );

		$hmac = hash_hmac(
			'sha256',
			(string) $ip . '|' . $difficulty_part . '|' . $issued_at_part . '|' . $random_part,
			(string) $salt
		);

		return $difficulty_part . $issued_at_part . $random_part . $hmac;
	}

	/**
	 * Parse a LEGACY (v1) token into its fields, strictly validating shape/length/charset.
	 *
	 * @param mixed $token Candidate token.
	 * @return array{difficulty:int,issued_at:int,random:string,hmac:string}|null
	 */
	public static function parse( $token ) {
		if ( ! is_string( $token ) || self::LENGTH !== strlen( $token ) ) {
			return null;
		}
		// Whole token must be lower-case hex (decimal digits are a subset of hex, so
		// the DD/II segments — which must be strictly decimal — are covered too).
		if ( ! preg_match( '/^[0-9a-f]{92}$/', $token ) ) {
			return null;
		}

		$difficulty_part = substr( $token, 0, 2 );
		$issued_at_part  = substr( $token, 2, 10 );
		$random_part     = substr( $token, 12, 16 );
		$hmac_part       = substr( $token, 28, 64 );

		// DD/II are sprintf('%0Nd', ...)-formatted decimal by create() and must never
		// contain a-f — reject a token that smuggled a hex letter into those positions
		// instead of silently (int)-casting a truncated value.
		if ( ! ctype_digit( $difficulty_part ) || ! ctype_digit( $issued_at_part ) ) {
			return null;
		}

		return array(
			'difficulty' => (int) $difficulty_part,
			'issued_at'  => (int) $issued_at_part,
			'random'     => $random_part,
			'hmac'       => $hmac_part,
		);
	}

	/**
	 * Verify a LEGACY (v1) token: well-formed, HMAC matches for the given IP/salt (via
	 * hash_equals, timing-safe), not expired, and not implausibly far in the future.
	 * Transitional only — see create(); v2 tokens go through verify_integrity().
	 *
	 * @param string $token          Candidate token.
	 * @param string $ip             The IP to verify against — MUST be the server-
	 *                               resolved IP (Stamp::get_client_ip()), never a
	 *                               client-posted value, or the binding is worthless.
	 * @param string $salt           Server-side HMAC key (Option::POW_SALT).
	 * @param int    $now            Current unix timestamp.
	 * @param int    $window_minutes Configured validity window (Option::POW_TIME_WINDOW);
	 *                               clamped to a minimum of 1, mirroring ProofOfWork::time_bucket().
	 * @return bool
	 */
	public static function verify( $token, $ip, $salt, $now, $window_minutes ) {
		$parsed = self::parse( $token );
		if ( null === $parsed ) {
			return false;
		}

		$expected = self::create( $ip, $salt, $parsed['difficulty'], $parsed['issued_at'], $parsed['random'] );
		if ( ! hash_equals( $expected, (string) $token ) ) {
			return false;
		}

		$now = (int) $now;

		// Future-skew tolerance: small clock drift between servers/load balancers is
		// normal, but a token "issued" far in the future is a forgery attempt (or the
		// server clock is broken either way — reject).
		if ( $parsed['issued_at'] > ( $now + 120 ) ) {
			return false;
		}

		// Expiry mirrors the same "window + 2 minutes" grace used elsewhere (rollover
		// tolerance / DB cleanup buffer, see ProofOfWork::time_bucket / Stamp::check_request).
		$window_seconds = ( max( 1, (int) $window_minutes ) + 2 ) * 60;
		if ( ( $now - $parsed['issued_at'] ) > $window_seconds ) {
			return false;
		}

		return true;
	}
}
