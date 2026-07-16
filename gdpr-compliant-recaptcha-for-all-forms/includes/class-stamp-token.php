<?php
/**
 * Pure, WordPress-independent submission-binding token (AP3 of the anti-spam
 * hardening plan, see ANTISPAM_HARDENING_PLAN.md / AP3_TOKEN_DESIGN.md).
 *
 * A token replaces the old per-IP/time-bucket "stamp" as the thing the client's
 * proof-of-work is computed over. It is a fixed-width, purely hex string (92
 * chars — [0-9a-f] only, so the existing check_stamp() sanitisation of
 * `[^a-zA-Z0-9]` never mangles it):
 *
 *   DD IIIIIIIIII RRRRRRRRRRRRRRRR HHHH…(64)
 *   │  │          │                └ hmac  = hash_hmac('sha256', ip.'|'.DD.'|'.II.'|'.RR, salt)
 *   │  │          └ random: 16 hex chars, caller-supplied (8 bytes random_bytes())
 *   │  └ issued_at: unix time, 10 digits, zero-padded
 *   └ difficulty: 2 digits, zero-padded (difficulty travels IN the token — AP4 prep)
 *
 * Fixed-width parsing (2/10/16/64), no separator. The HMAC binds the token to the
 * IP, the difficulty, the issue time, and the random component, so it can neither
 * be forged nor replayed against a different IP — and it is entirely stateless:
 * an unsolved token never touches the database (Stamp::get_stamp() just returns
 * one; nothing is written until Stamp::check_stamp() sees a solved PoW), so
 * flooding get_stamp() creates no server-side state to clean up.
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

	/** Total token length: 2 (difficulty) + 10 (issued_at) + 16 (random) + 64 (hmac). */
	const LENGTH = 92;

	/**
	 * Build a token string.
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
	 * Parse a token into its fields, strictly validating shape/length/charset.
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
	 * Verify a token: well-formed, HMAC matches for the given IP/salt (via
	 * hash_equals, timing-safe), not expired, and not implausibly far in the future.
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
