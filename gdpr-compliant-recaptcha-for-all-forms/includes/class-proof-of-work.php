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
	 * Map a Unix timestamp to a coarse time bucket, so that stamps issued within
	 * the same window hash to the same value (and therefore expire in step with
	 * the DB-side cleanup window instead of being valid forever for a given IP).
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
	 * Compute the stamp value for a given IP, salt, and time bucket.
	 *
	 * @param string $ip     Client IP address.
	 * @param string $salt   Server-side salt option.
	 * @param int    $bucket Time bucket, see time_bucket().
	 * @return string Lower-case hex SHA-256 digest (64 chars).
	 */
	public static function stamp_value( $ip, $salt, $bucket ) {
		return self::hash_value( (string) $ip . (string) $salt . (string) $bucket );
	}

	/**
	 * Compute the difficulty to actually hand out, given a configured base and an
	 * optional site-wide "under attack" boost (AP4 of the anti-spam hardening
	 * plan, see Stamp::is_under_attack()). Pure math — no WordPress dependency —
	 * so both the deciding-whether-to-boost logic (WP options/transients, in
	 * Stamp) and this arithmetic stay independently testable.
	 *
	 * @param int  $base         Configured base difficulty (Option::POW_DIFFICULTY);
	 *                            clamped to a minimum of 1 so a misconfigured
	 *                            (empty/zero/negative) option never disables the
	 *                            puzzle entirely.
	 * @param bool $under_attack Whether the site-wide under-attack boost applies.
	 * @param int  $bonus        Extra leading zero bits added while under attack.
	 * @param int  $cap          Hard ceiling on the returned difficulty.
	 * @return int Effective difficulty, in [1, $cap] when $cap >= 1.
	 */
	public static function effective_difficulty( $base, $under_attack, $bonus, $cap ) {
		$effective = max( 1, (int) $base ) + ( $under_attack ? (int) $bonus : 0 );
		return min( $effective, (int) $cap );
	}
}
