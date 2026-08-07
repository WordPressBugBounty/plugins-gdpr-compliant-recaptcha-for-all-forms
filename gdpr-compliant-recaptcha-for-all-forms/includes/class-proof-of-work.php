<?php
/**
 * Pure, WordPress-independent hashcash proof-of-work primitives.
 *
 * This is the single source of truth for the server-side PoW math. It has NO
 * WordPress dependencies (no options, no $wpdb, no hooks), which makes it unit-
 * testable in isolation — see tests/unit/ProofOfWorkTest.php.
 *
 * The client re-implements the exact same algorithm in the inline script printed
 * by Stamp::add_script_to_header(). If you change anything here, change it there
 * (and in the test) in lockstep, or valid clients will be rejected.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Stateless hashcash helpers.
 */
final class ProofOfWork {

	/**
	 * Generous upper bound on a legitimate BROWSER hash rate (hashes/second), used
	 * to derive the solve-time plausibility threshold below. Real crypto.subtle
	 * throughput on a top desktop is ~0.2–0.5 MH/s (async overhead per digest call);
	 * 2 MH/s is deliberately well above that, so the derived threshold is a HARD
	 * lower bound on the real elapsed time — a legitimate solve can never physically
	 * beat it, and network latency (which only ADDS) never produces a false positive.
	 * Native/GPU solvers (SHA-NI, ~ms) fall far below it. See BACKLOG (now HANDBUCH §4).
	 */
	const H_MAX = 2000000;

	/**
	 * Minimum plausible server-measured solve time, in milliseconds, for a puzzle of
	 * the given difficulty: floor( 1000 * 2^d / H_MAX ). A solve reported faster than
	 * this cannot have done the work at any browser hash rate and triggers a
	 * difficulty-scaled re-challenge (never a hard block — a single fast solve is
	 * legitimate luck, solve time being exponentially distributed; only the cumulative
	 * Erlang time over several rounds is decisive, see ChainToken / HANDBUCH §4).
	 *
	 * Below d ~= 16 the threshold drops under real network latency, so the gate can
	 * never fire there (fail-safe by construction — documented in the settings hint).
	 *
	 * Pure arithmetic, no WordPress dependency → unit-tested in ProofOfWorkTest.
	 *
	 * @param int $difficulty Number of leading zero bits the PoW targets.
	 * @return int Threshold in milliseconds (>= 0).
	 */
	public static function solve_time_threshold_ms( $difficulty ) {
		return (int) floor( 1000 * pow( 2, (int) $difficulty ) / self::H_MAX );
	}

	/**
	 * The hash function underlying stamps and proof-of-work.
	 *
	 * @param string $x Input.
	 * @return string Lower-case hex SHA-256 digest (64 chars).
	 */
	public static function hash_value( $x ) {
		return hash( 'sha256', (string) $x, false );
	}

	/**
	 * Return the leading $num_bits of a hex string as a bit string.
	 *
	 * Reads ceil($num_bits / 4) hex characters, expands each to 4 binary digits,
	 * then truncates to exactly $num_bits.
	 *
	 * @param string $hex_string Hex digest.
	 * @param int    $num_bits   Number of leading bits requested.
	 * @return string Bit string of length $num_bits (big-endian).
	 */
	public static function extract_bits( $hex_string, $num_bits ) {
		$num_bits   = (int) $num_bits;
		$bit_string = '';
		$num_chars  = (int) ceil( $num_bits / 4 );
		for ( $i = 0; $i < $num_chars; $i++ ) {
			// Convert hex nibble to binary, left-padded to 4 bits.
			$bit_string .= str_pad( base_convert( $hex_string[ $i ], 16, 2 ), 4, '0', STR_PAD_LEFT );
		}
		return substr( $bit_string, 0, $num_bits );
	}

	/**
	 * Check whether sha256($stamp . $nonce) meets the difficulty target.
	 *
	 * The target is met when the leading $difficulty bits are all zero.
	 *
	 * @param int    $difficulty Number of leading zero bits required.
	 * @param string $stamp      The server-issued stamp.
	 * @param string $nonce      The client-found nonce.
	 * @return bool True iff the difficulty target is met.
	 */
	public static function meets_difficulty( $difficulty, $stamp, $nonce ) {
		$difficulty = (int) $difficulty;
		$work       = self::hash_value( (string) $stamp . (string) $nonce );

		$leading_bits = self::extract_bits( $work, $difficulty );

		// All-zero leading bits ⇒ intval() of the bit STRING is 0 only when every char is '0'.
		return ( strlen( $leading_bits ) > 0 && intval( $leading_bits ) === 0 );
	}

	/**
	 * Map a Unix timestamp to a coarse time bucket. Sole remaining use since the
	 * legacy bucket-stamp was removed: the DSGVO-neutral under-attack spam counter
	 * (Stamp::increment_spam_counter()/is_under_attack()), which keys one transient
	 * per 5-minute bucket and therefore carries no client identity at all.
	 *
	 * @param int $timestamp      Unix timestamp.
	 * @param int $window_minutes Bucket width in minutes; clamped to a minimum of 1
	 *                            so a misconfigured (empty/zero) option never yields
	 *                            a division by zero or an infinitely wide bucket.
	 * @return int Bucket index.
	 */
	public static function time_bucket( $timestamp, $window_minutes ) {
		$window_minutes = max( 1, (int) $window_minutes );
		return (int) floor( ( (int) $timestamp ) / ( $window_minutes * 60 ) );
	}

	/**
	 * Compute the difficulty to actually hand out, given a configured base and an
	 * optional site-wide "under attack" boost (AP4 of the anti-spam hardening
	 * plan, see Stamp::is_under_attack()). Pure math — no WordPress dependency —
	 * so both the deciding-whether-to-boost logic (WP options/transients, in
	 * Stamp) and this arithmetic stay independently testable.
	 *
	 * There is deliberately NO upper ceiling: Stamp::check_stamp() only accepts a
	 * token whose difficulty is >= the configured base, so any clipping here would
	 * make the server hand out tokens that fail its own entrance check (with a base
	 * above the ceiling, EVERY submission became spam). Issued difficulty must
	 * therefore always be >= max( 1, base ). An absurdly high base is the site
	 * owner's own choice — see the Difficulty option's help text.
	 *
	 * @param int  $base         Configured base difficulty (Option::POW_DIFFICULTY);
	 *                            clamped to a minimum of 1 so a misconfigured
	 *                            (empty/zero/negative) option never disables the
	 *                            puzzle entirely.
	 * @param bool $under_attack Whether the site-wide under-attack boost applies.
	 * @param int  $bonus        Extra leading zero bits added while under attack.
	 * @return int Effective difficulty, always >= max( 1, $base ).
	 */
	public static function effective_difficulty( $base, $under_attack, $bonus ) {
		return max( 1, (int) $base ) + ( $under_attack ? (int) $bonus : 0 );
	}
}
