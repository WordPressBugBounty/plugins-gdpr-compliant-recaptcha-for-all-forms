<?php
/**
 * Pure, WordPress-independent RE-CHALLENGE chain token (solve-time plausibility,
 * see BACKLOG "Solve-Zeit-Plausibilität" — now HANDBUCH §4).
 *
 * A chain token is issued ONLY as the answer to a verified-but-implausibly-fast
 * base-token solve (StampToken, 92 chars). Possession of a valid chain token
 * therefore proves a PAID first solve. It carries the running state of the
 * re-challenge chain entirely inside an HMAC (no per-client server storage): the
 * cumulative MEASURED solve time so far vs. the cumulative REQUIRED time. The chain
 * is accepted once cumulative measured >= cumulative required (Erlang: the relative
 * variance of the summed exponential solve times shrinks as 1/k, so after 2–3 rounds
 * the verdict is sharp — a single lucky-fast solve proves nothing, native/GPU solvers
 * that keep beating the threshold hang in the escalation loop).
 *
 * Fixed-width, purely hex (so check_stamp()'s [^a-zA-Z0-9] sanitisation never mangles
 * it — decimal digits are a subset of hex):
 *
 *   DD IIIIIIIIIIIII K SSSSSSSS QQQQQQQQ RRRRRRRRRRRRRRRR HHHH…(64)
 *   │  │             │ │        │        │                └ hmac = hash_hmac('sha256',
 *   │  │             │ │        │        │                  ip.'|'.DD.'|'.II.'|'.KK.'|'.SS.'|'.QQ.'|'.RR, salt)
 *   │  │             │ │        │        └ random: 16 hex chars, caller-supplied
 *   │  │             │ │        └ QQ: cumulative REQUIRED ms, 8 digits, saturates at 99999999
 *   │  │             │ └ SS: cumulative MEASURED ms, 8 digits, saturates at 99999999
 *   │  │             └ KK: round counter 1–9 (saturates at 9), 1 digit
 *   │  └ II: issued_at in ms, 13 digits, zero-padded
 *   └ DD: difficulty of THIS round, 2 digits, zero-padded (HMAC-bound like StampToken)
 *
 * The HMAC binds the token to the IP, difficulty, issue time, round, cumulative
 * measured/required times and the random component, so none of it can be forged or
 * replayed against a different IP. Deliberately vs. StampToken: this one is time-
 * measured in MILLISECONDS (issued_at_ms), because the chain path measures real
 * microtime spans, whereas the base token's 1-second granularity is coarse by design.
 *
 * No WordPress dependencies (no options, no $wpdb) → unit-testable in isolation, see
 * tests/unit/ChainTokenTest.php. Vorbild: class-stamp-token.php (final, do not touch).
 * Stamp::check_stamp()/check_request() are the only server-side callers; the client
 * only ever treats it as an opaque hashcash input string (scripts/recaptcha-gdpr-pow.js).
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Stateless re-challenge chain token helpers.
 */
final class ChainToken {

	/** Total length: 2 (DD) + 13 (II) + 1 (KK) + 8 (SS) + 8 (QQ) + 16 (RR) + 64 (HMAC). */
	const LENGTH = 112;

	/** Ceiling for the cumulative measured/required ms fields (8 decimal digits). */
	const MAX_CUMULATIVE_MS = 99999999;

	/** Ceiling for the round counter (single decimal digit); the chain itself is uncapped. */
	const MAX_ROUND = 9;

	/**
	 * Realistic crypto.subtle browser hash rate (H/s) used to size the adaptive poll
	 * window — DISTINCT from ProofOfWork::H_MAX (the generous gate bound). Here we want
	 * the EXPECTED solve time to hold a submission's poll open long enough, so a
	 * realistic (not worst-case-fast) rate is correct.
	 */
	const POLL_HASHRATE = 500000;

	/** Hard cap on adaptive poll attempts (80 * 100ms = 8s). */
	const MAX_POLL_ATTEMPTS = 80;

	/**
	 * Build a chain token string. All values come from the caller (no randomness or
	 * clock read inside) → deterministic and unit-testable. Fixed-width segments are
	 * clamped defensively so the length invariant (LENGTH) always holds.
	 *
	 * @param string $ip           Client IP the token is bound to (server-resolved).
	 * @param string $salt         Server-side HMAC key (Option::POW_SALT).
	 * @param int    $difficulty   Difficulty of this round.
	 * @param int    $issued_at_ms Issue time in milliseconds (round(microtime(true)*1000)).
	 * @param int    $round        Round counter (1–9, saturates at 9).
	 * @param int    $measured_ms  Cumulative measured ms so far (saturates at 99999999).
	 * @param int    $required_ms  Cumulative required ms so far (saturates at 99999999).
	 * @param string $random_hex   16 lower-case hex chars of caller-supplied randomness.
	 * @return string 112-char token.
	 */
	public static function create( $ip, $salt, $difficulty, $issued_at_ms, $round, $measured_ms, $required_ms, $random_hex ) {
		$dd = sprintf( '%02d', max( 0, min( 99, (int) $difficulty ) ) );
		$ii = sprintf( '%013d', max( 0, min( 9999999999999, (int) $issued_at_ms ) ) );
		$kk = sprintf( '%01d', max( 1, min( self::MAX_ROUND, (int) $round ) ) );
		$ss = sprintf( '%08d', max( 0, min( self::MAX_CUMULATIVE_MS, (int) $measured_ms ) ) );
		$qq = sprintf( '%08d', max( 0, min( self::MAX_CUMULATIVE_MS, (int) $required_ms ) ) );
		$rr = strtolower( (string) $random_hex );

		$hmac = hash_hmac(
			'sha256',
			(string) $ip . '|' . $dd . '|' . $ii . '|' . $kk . '|' . $ss . '|' . $qq . '|' . $rr,
			(string) $salt
		);

		return $dd . $ii . $kk . $ss . $qq . $rr . $hmac;
	}

	/**
	 * Parse a token into its fields, strictly validating shape/length/charset.
	 *
	 * @param mixed $token Candidate token.
	 * @return array{difficulty:int,issued_at_ms:int,round:int,measured_ms:int,required_ms:int,random:string,hmac:string}|null
	 */
	public static function parse( $token ) {
		if ( ! is_string( $token ) || self::LENGTH !== strlen( $token ) ) {
			return null;
		}
		// Whole token must be lower-case hex; decimal digits are a subset, so the
		// DD/II/KK/SS/QQ segments (strictly decimal) are covered by this first gate.
		if ( ! preg_match( '/^[0-9a-f]{112}$/', $token ) ) {
			return null;
		}

		$dd = substr( $token, 0, 2 );
		$ii = substr( $token, 2, 13 );
		$kk = substr( $token, 15, 1 );
		$ss = substr( $token, 16, 8 );
		$qq = substr( $token, 24, 8 );
		$rr = substr( $token, 32, 16 );
		$hm = substr( $token, 48, 64 );

		// The decimal-only segments must never smuggle a hex letter (a-f) — reject
		// instead of silently (int)-casting a value create() could never have produced.
		if ( ! ctype_digit( $dd ) || ! ctype_digit( $ii ) || ! ctype_digit( $kk )
			|| ! ctype_digit( $ss ) || ! ctype_digit( $qq ) ) {
			return null;
		}

		return array(
			'difficulty'   => (int) $dd,
			'issued_at_ms' => (int) $ii,
			'round'        => (int) $kk,
			'measured_ms'  => (int) $ss,
			'required_ms'  => (int) $qq,
			'random'       => $rr,
			'hmac'         => $hm,
		);
	}

	/**
	 * Verify a chain token: well-formed, HMAC matches for the IP/salt (timing-safe),
	 * not expired, and not implausibly far in the future.
	 *
	 * @param string $token          Candidate token.
	 * @param string $ip             The IP to verify against — MUST be the server-
	 *                               resolved IP (Stamp::get_client_ip()), never a
	 *                               client-posted value, or the binding is worthless.
	 * @param string $salt           Server-side HMAC key (Option::POW_SALT).
	 * @param int    $now_ms         Current time in milliseconds.
	 * @param int    $window_minutes Configured validity window (Option::POW_TIME_WINDOW);
	 *                               clamped to a minimum of 1.
	 * @return bool
	 */
	public static function verify( $token, $ip, $salt, $now_ms, $window_minutes ) {
		$parsed = self::parse( $token );
		if ( null === $parsed ) {
			return false;
		}

		$expected = self::create(
			$ip,
			$salt,
			$parsed['difficulty'],
			$parsed['issued_at_ms'],
			$parsed['round'],
			$parsed['measured_ms'],
			$parsed['required_ms'],
			$parsed['random']
		);
		if ( ! hash_equals( $expected, (string) $token ) ) {
			return false;
		}

		$now_ms = (int) $now_ms;

		// Future-skew tolerance: small clock drift is normal, a token "issued" far in
		// the future is a forgery (or a broken clock — reject either way). 120s in ms.
		if ( $parsed['issued_at_ms'] > ( $now_ms + 120000 ) ) {
			return false;
		}

		// Expiry mirrors the "window + 2 minutes" grace used elsewhere, in ms.
		$window_ms = ( max( 1, (int) $window_minutes ) + 2 ) * 60 * 1000;
		if ( ( $now_ms - $parsed['issued_at_ms'] ) > $window_ms ) {
			return false;
		}

		return true;
	}

	/**
	 * Erlang acceptance: the chain is satisfied once the cumulative measured time
	 * (already-accumulated + this round's) reaches the cumulative required time.
	 *
	 * @param int $cumulative_measured Already-accumulated measured ms (token SS).
	 * @param int $incoming_measured   This round's measured ms (now_ms - issued_at_ms).
	 * @param int $cumulative_required Cumulative required ms (token QQ).
	 * @return bool
	 */
	public static function is_accepted( $cumulative_measured, $incoming_measured, $cumulative_required ) {
		return ( max( 0, (int) $cumulative_measured ) + max( 0, (int) $incoming_measured ) ) >= max( 0, (int) $cumulative_required );
	}

	/**
	 * Difficulty of the next round: one bit harder, capped.
	 *
	 * @param int $current Current round difficulty.
	 * @param int $cap     Hard difficulty ceiling (Stamp::DIFFICULTY_CAP).
	 * @return int
	 */
	public static function next_difficulty( $current, $cap ) {
		return min( (int) $current + 1, (int) $cap );
	}

	/**
	 * Next round counter, saturating at MAX_ROUND (the chain itself is uncapped — a
	 * native solver hangs in the loop; honest browsers accumulate enough time in 1–2
	 * rounds, so the display digit saturating is harmless).
	 *
	 * @param int $current Current round counter.
	 * @return int
	 */
	public static function next_round( $current ) {
		return min( (int) $current + 1, self::MAX_ROUND );
	}

	/**
	 * Add a delta to a cumulative ms field, floored at 0 and saturated at the
	 * 8-digit field ceiling (matches create()'s clamp).
	 *
	 * @param int $current Current cumulative ms.
	 * @param int $delta   Delta to add.
	 * @return int
	 */
	public static function accumulate_ms( $current, $delta ) {
		$sum = max( 0, (int) $current ) + max( 0, (int) $delta );
		return min( self::MAX_CUMULATIVE_MS, $sum );
	}

	/**
	 * Whether a newly issued chain token justifies feeding the site-wide under-attack
	 * spam counter: only from round 2 on (a sharp verdict needs >= 2 rounds; a single
	 * lucky-fast solve — round 1 — is legitimate and must not push a busy site into
	 * under-attack mode). Timing is only ever an aggregated anomaly SIGNAL, never a
	 * per-client gate (BACKLOG AP6).
	 *
	 * @param int $new_round Round counter of the freshly issued token.
	 * @return bool
	 */
	public static function should_feed_counter( $new_round ) {
		return (int) $new_round >= 2;
	}

	/**
	 * Adaptive poll-window size (number of 100ms attempts) for a submission carrying a
	 * valid chain token of the given difficulty: ceil( (2^d / POLL_HASHRATE + 1s margin)
	 * / 100ms ), hard-capped at MAX_POLL_ATTEMPTS. This longer hold is reachable ONLY
	 * after a paid first solve (a chain token is only issued in response to a verified
	 * fast solve), so the protocol-blind mass — which never holds a chain token — stays
	 * on the short IP-fallback window: no free worker-blocking vector on shared hosting.
	 *
	 * @param int $difficulty Difficulty embedded in the chain token (DD).
	 * @return int Number of poll attempts, in [1, MAX_POLL_ATTEMPTS].
	 */
	public static function poll_attempts_for_difficulty( $difficulty ) {
		$expected_seconds = pow( 2, (int) $difficulty ) / self::POLL_HASHRATE;
		$attempts         = (int) ceil( ( $expected_seconds + 1.0 ) / 0.1 );
		return max( 1, min( self::MAX_POLL_ATTEMPTS, $attempts ) );
	}
}
