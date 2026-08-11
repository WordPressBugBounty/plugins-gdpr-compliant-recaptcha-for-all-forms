<?php
/**
 * Self-test: drives the real proof-of-work handshake and reports in plain language.
 *
 * Area doc: handbuch/abilities.md (this class), handbuch/pow.md (the handshake it
 * exercises), HANDBUCH.md §12 (the support case it exists for).
 *
 * @package VENDOR\RECAPTCHA_GDPR_COMPLIANT
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Runs the plugin's own get_stamp/check_stamp handshake against this site over HTTP
 * and turns the result into a sentence a non-developer can act on.
 *
 * This exists for the single most common support case (HANDBUCH.md §12): almost every
 * submission is flagged as spam because the client-side proof-of-work never computed
 * a stamp. Diagnosing it today means opening the browser network tab and judging
 * whether get_stamp returned clean JSON — knowledge the person reporting the problem
 * usually does not have. The probe makes that judgement itself.
 *
 * Two things it deliberately is NOT:
 *
 *   - It has no privileged path. It goes over HTTP through admin-ajax like any
 *     visitor, and check_stamp verifies its solve exactly as it verifies anyone's.
 *     There is no test flag in the verification code, because a bypass built for
 *     diagnostics is still a bypass.
 *   - Its `ok` does not mean "submissions get through". It measures the handshake,
 *     and §12 causes 5 and 6 are precisely the cases where the handshake is green
 *     and the submission is still spam. interpret() says so in the message rather
 *     than letting an agent read `ok` as an all-clear.
 *
 * interpret() is pure — no WordPress, no network — so every verdict is unit-testable
 * from string fixtures (tests/unit/AbilityProbeInterpretTest.php). run() is the thin
 * half that actually talks to the site.
 */
final class Ability_Probe {

	/**
	 * Wall-clock budget for the server-side solve, in seconds.
	 *
	 * A time budget rather than an attempt count, because the cost of a solve is
	 * exponential in the difficulty and the difficulty is not ours to choose: at the
	 * default 14-16 bits a solve is a fraction of a second, but under-attack mode
	 * adds 3 bits (~8x) and an admin may set the base higher still. Past this budget
	 * the probe stops and says so, instead of holding an admin request open.
	 */
	const SOLVE_BUDGET_SECONDS = 2.0;

	/** How many hash attempts between two clock reads. */
	const SOLVE_BATCH = 2000;

	/** Characters of a non-JSON response body quoted back in the report. */
	const RAW_PREFIX_LENGTH = 120;

	/** Seconds to wait for each HTTP round trip. */
	const HTTP_TIMEOUT = 10;

	/**
	 * Drive the handshake and return the interpreted result.
	 *
	 * @return array{verdict:string,code:string,message:string,details:array<string,mixed>}
	 */
	public static function run() {
		$url = admin_url( 'admin-ajax.php' );

		$first  = self::request_challenge( $url );
		$second = self::request_challenge( $url );

		$steps = array(
			'challenge'        => $first,
			'challenge_repeat' => $second,
			'solve'            => array(
				'attempted'        => false,
				'solved'           => false,
				'difficulty'       => 0,
				'budget_exhausted' => false,
			),
			'submit'           => null,
			'context'          => self::context(),
		);

		$parsed = self::decode( $first['body'] );
		if ( is_array( $parsed ) && isset( $parsed['stamp'], $parsed['difficulty'] ) ) {
			$token      = (string) $parsed['stamp'];
			$difficulty = (int) $parsed['difficulty'];

			$nonce = self::solve( $token, $difficulty );

			$steps['solve'] = array(
				'attempted'        => true,
				'solved'           => null !== $nonce,
				'difficulty'       => $difficulty,
				'budget_exhausted' => null === $nonce,
			);

			if ( null !== $nonce ) {
				$steps['submit'] = self::submit_solution( $url, $token, $nonce );
			}
		}

		return self::interpret( $steps );
	}

	/**
	 * Fetch one challenge.
	 *
	 * @param string $url admin-ajax URL.
	 * @return array{error:string,code:int,body:string}
	 */
	private static function request_challenge( $url ) {
		$response = wp_remote_get(
			add_query_arg(
				array(
					'action' => 'get_stamp',
					// Same cache-buster idea as the client (handbuch/pow.md): without
					// it a caching layer in front of admin-ajax would hand us a stale
					// body and the repeat-request cache check below could never fire.
					'_'      => (string) wp_rand( 100000, 999999 ),
				),
				$url
			),
			array(
				'timeout'   => self::HTTP_TIMEOUT,
				// The probe talks to this very site. A self-signed or otherwise
				// imperfect certificate is normal on staging and local installs, and
				// failing there would report "unreachable" for a site that is fine.
				// Same reasoning core's Site Health uses for its loopback checks.
				'sslverify' => false,
				'headers'   => array( 'Cache-Control' => 'no-cache' ),
			)
		);

		return self::normalize_response( $response );
	}

	/**
	 * Post a solved challenge back.
	 *
	 * @param string $url   admin-ajax URL.
	 * @param string $token The challenge token.
	 * @param string $nonce The solving nonce.
	 * @return array{error:string,code:int,body:string}
	 */
	private static function submit_solution( $url, $token, $nonce ) {
		$response = wp_remote_post(
			$url,
			array(
				'timeout'   => self::HTTP_TIMEOUT,
				'sslverify' => false,
				'body'      => array(
					'action'    => 'check_stamp',
					'hashStamp' => $token,
					'hashNonce' => $nonce,
				),
			)
		);

		return self::normalize_response( $response );
	}

	/**
	 * Flatten a wp_remote_* result into the shape interpret() reads.
	 *
	 * @param array<string,mixed>|\WP_Error $response Raw HTTP API result.
	 * @return array{error:string,code:int,body:string}
	 */
	private static function normalize_response( $response ) {
		if ( is_wp_error( $response ) ) {
			return array(
				'error' => $response->get_error_message(),
				'code'  => 0,
				'body'  => '',
			);
		}

		return array(
			'error' => '',
			'code'  => (int) wp_remote_retrieve_response_code( $response ),
			'body'  => (string) wp_remote_retrieve_body( $response ),
		);
	}

	/**
	 * Settings that change how the verdict must be read.
	 *
	 * @return array<string,bool>
	 */
	private static function context() {
		return array(
			'simulation_mode' => (bool) get_option( Option::POW_SIMULATE_SPAM ),
			'blocking'        => (bool) get_option( Option::POW_BLOCK ),
			'under_attack'    => Stamp::is_under_attack(),
		);
	}

	/**
	 * Search for a nonce that meets the difficulty, within the time budget.
	 *
	 * Mirrors the client (scripts/recaptcha-gdpr-pow.js): counter from 1 upwards,
	 * sha256(token . nonce), leading zero bits. Uses ProofOfWork so there is one
	 * definition of the arithmetic, not a second one that could drift.
	 *
	 * @param string $token      The challenge token.
	 * @param int    $difficulty Required leading zero bits.
	 * @return string|null The nonce, or null if the budget ran out.
	 */
	private static function solve( $token, $difficulty ) {
		if ( $difficulty < 1 ) {
			return null;
		}

		$deadline = microtime( true ) + self::SOLVE_BUDGET_SECONDS;
		$nonce    = 1;

		while ( true ) {
			for ( $i = 0; $i < self::SOLVE_BATCH; $i++ ) {
				if ( ProofOfWork::meets_difficulty( $difficulty, $token, (string) $nonce ) ) {
					return (string) $nonce;
				}
				++$nonce;
			}

			if ( microtime( true ) >= $deadline ) {
				return null;
			}
		}
	}

	/**
	 * Decode a response body tolerantly.
	 *
	 * The server-side twin of the client's parseJsonLoose (handbuch/pow.md): a body
	 * carrying a PHP notice, a BOM or a WAF banner in front of the JSON is exactly
	 * the failure this whole probe is meant to name, so the decoder has to be able to
	 * see past the noise in order to report it.
	 *
	 * @param string $body Raw response body.
	 * @return array<string,mixed>|null
	 */
	public static function decode( $body ) {
		$body = (string) $body;

		$direct = json_decode( $body, true );
		if ( is_array( $direct ) ) {
			return $direct;
		}

		$start = strpos( $body, '{' );
		$end   = strrpos( $body, '}' );
		if ( false === $start || false === $end || $end <= $start ) {
			return null;
		}

		$carved = json_decode( substr( $body, $start, $end - $start + 1 ), true );

		return is_array( $carved ) ? $carved : null;
	}

	/**
	 * Turn collected steps into a verdict. Pure: no WordPress, no network, no clock.
	 *
	 * @param array<string,mixed> $steps Step records as assembled by run().
	 * @return array{verdict:string,code:string,message:string,details:array<string,mixed>}
	 */
	public static function interpret( array $steps ) {
		$challenge = isset( $steps['challenge'] ) && is_array( $steps['challenge'] ) ? $steps['challenge'] : array();
		$repeat    = isset( $steps['challenge_repeat'] ) && is_array( $steps['challenge_repeat'] ) ? $steps['challenge_repeat'] : array();
		$solve     = isset( $steps['solve'] ) && is_array( $steps['solve'] ) ? $steps['solve'] : array();
		$submit    = isset( $steps['submit'] ) && is_array( $steps['submit'] ) ? $steps['submit'] : null;
		$context   = isset( $steps['context'] ) && is_array( $steps['context'] ) ? $steps['context'] : array();

		$error = isset( $challenge['error'] ) ? (string) $challenge['error'] : '';
		$code  = isset( $challenge['code'] ) ? (int) $challenge['code'] : 0;
		$body  = isset( $challenge['body'] ) ? (string) $challenge['body'] : '';

		if ( '' !== $error || 200 !== $code ) {
			return self::verdict(
				'challenge_unreachable',
				sprintf(
					/* translators: %s: HTTP status code or transport error. */
					__( 'The site could not reach its own challenge endpoint (%s). Visitors will not get a puzzle either, so every submission will be treated as spam. A firewall, a security plugin or a blocked loopback connection is the usual cause.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'' !== $error ? $error : sprintf( 'HTTP %d', $code )
				),
				$context
			);
		}

		$parsed = self::decode( $body );

		if ( null === $parsed ) {
			return self::verdict(
				'not_json',
				sprintf(
					/* translators: %s: first characters of the response body. */
					__( 'The challenge endpoint did not answer with JSON. The client-side script cannot read this, so it never computes a puzzle and every submission is treated as spam. The response began with: %s', 'gdpr-compliant-recaptcha-for-all-forms' ),
					self::quote( $body )
				),
				$context
			);
		}

		if ( ! self::starts_with_json( $body ) ) {
			return self::verdict(
				'json_noise',
				sprintf(
					/* translators: %s: the text preceding the JSON. */
					__( 'The challenge endpoint answered with valid JSON, but something was printed in front of it — usually a PHP notice or warning from another plugin or the theme, with display_errors switched on. This breaks the client-side script and every submission ends up treated as spam. The response began with: %s', 'gdpr-compliant-recaptcha-for-all-forms' ),
					self::quote( $body )
				),
				$context
			);
		}

		if ( ! isset( $parsed['stamp'] ) || ! isset( $parsed['difficulty'] ) ) {
			return self::verdict(
				'missing_fields',
				__( 'The challenge endpoint answered with JSON, but without the expected "stamp" and "difficulty" fields. Something is answering in this plugin\'s place — most often another plugin that hooks the same admin-ajax action.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				$context
			);
		}

		$repeat_body   = isset( $repeat['body'] ) ? (string) $repeat['body'] : '';
		$repeat_parsed = '' === $repeat_body ? null : self::decode( $repeat_body );
		if (
			is_array( $repeat_parsed )
			&& isset( $repeat_parsed['stamp'] )
			&& (string) $repeat_parsed['stamp'] === (string) $parsed['stamp']
		) {
			return self::verdict(
				'cached_response',
				__( 'Two challenge requests returned exactly the same token. That is impossible without a cache in front of the site, because every token contains fresh random data. All visitors are being served one shared token, so their solutions are rejected and their submissions are treated as spam. Exclude admin-ajax.php from your page or CDN cache.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				$context
			);
		}

		if ( ! empty( $solve['budget_exhausted'] ) ) {
			return self::verdict(
				'difficulty_out_of_test_range',
				sprintf(
					/* translators: %d: puzzle difficulty in bits. */
					__( 'The handshake works, but the puzzle is currently too expensive for this self-test to solve on the server within its time budget (difficulty %d). This is not a fault on its own — visitors solve it in their browser, which is usually faster. If under-attack mode has raised the difficulty, run the test again once the wave has passed.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					isset( $solve['difficulty'] ) ? (int) $solve['difficulty'] : 0
				),
				$context
			);
		}

		if ( null === $submit ) {
			return self::verdict(
				'solve_rejected',
				__( 'The challenge was issued but the self-test never got to submit a solution.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				$context
			);
		}

		$submit_error  = isset( $submit['error'] ) ? (string) $submit['error'] : '';
		$submit_code   = isset( $submit['code'] ) ? (int) $submit['code'] : 0;
		$submit_parsed = self::decode( isset( $submit['body'] ) ? (string) $submit['body'] : '' );

		// The server verified the solve and could not KEEP it (check_stamp() answers
		// {accepted:false, stored:false} for exactly this, see class-stamp.php). Its own
		// verdict, because the advice differs completely from a rejected solve: nothing
		// about the proof of work is wrong here, the plugin's table is.
		if ( is_array( $submit_parsed ) && isset( $submit_parsed['stored'] ) && false === $submit_parsed['stored'] ) {
			return self::verdict(
				'not_stored',
				__( 'The puzzle was solved and verified correctly, but this site could not store the result. Nothing is wrong with the protection itself — its own database table is missing or cannot be written to, and without a stored result every submission is treated as spam. Deactivating and reactivating the plugin re-creates the table; if the problem returns, your host has to check the database user\'s write permissions. The settings screen shows the database error underneath the status bar.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				$context
			);
		}

		if ( '' !== $submit_error || 200 !== $submit_code || ! is_array( $submit_parsed ) || empty( $submit_parsed['accepted'] ) ) {
			return self::verdict(
				'solve_rejected',
				__( 'A correctly solved puzzle was not accepted, so no proof-of-work record is ever stored and every submission is treated as spam. Stale cached PHP code after an update is the usual cause — clearing the OPcache or restarting PHP-FPM normally fixes it.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				$context
			);
		}

		return self::verdict(
			'ok',
			__( 'The proof-of-work handshake works end to end: a challenge was issued, solved, and the solution was accepted and stored. Note what this does not cover — if submissions are still being flagged, the token is reaching the server but not the form payload, which is a separate fault in how that particular form builder sends its data.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			$context
		);
	}

	/**
	 * Assemble a verdict, folding in the settings that change how to read it.
	 *
	 * @param string              $code    Verdict code.
	 * @param string              $message Plain-language message.
	 * @param array<string,mixed> $context Settings context.
	 * @return array{verdict:string,code:string,message:string,details:array<string,mixed>}
	 */
	private static function verdict( $code, $message, array $context ) {
		$notes = array();

		if ( ! empty( $context['simulation_mode'] ) ) {
			$notes[] = __( 'Simulation mode is switched on: every submission is treated as spam regardless of this result. Switch it off before judging live behaviour.', 'gdpr-compliant-recaptcha-for-all-forms' );
		}
		if ( ! empty( $context['under_attack'] ) ) {
			$notes[] = __( 'A spam wave is currently detected, so the puzzle difficulty is temporarily raised.', 'gdpr-compliant-recaptcha-for-all-forms' );
		}

		return array(
			'verdict' => 'ok' === $code ? 'ok' : 'problem',
			'code'    => $code,
			'message' => $message,
			'details' => array(
				'notes'           => $notes,
				'simulation_mode' => ! empty( $context['simulation_mode'] ),
				'blocking'        => ! empty( $context['blocking'] ),
				'under_attack'    => ! empty( $context['under_attack'] ),
			),
		);
	}

	/**
	 * Whether the body is JSON from its very first byte.
	 *
	 * @param string $body Raw response body.
	 * @return bool
	 */
	private static function starts_with_json( $body ) {
		return isset( $body[0] ) && '{' === $body[0];
	}

	/**
	 * Quote the head of a response body safely.
	 *
	 * The body is untrusted: it can be a WAF page, another plugin's HTML error, or
	 * anything else. It is truncated and stripped of markup before it ever reaches a
	 * report that an agent or an admin screen will render.
	 *
	 * @param string $body Raw response body.
	 * @return string
	 */
	private static function quote( $body ) {
		$flat = trim( preg_replace( '/\s+/', ' ', wp_strip_all_tags( (string) $body ) ) );

		if ( '' === $flat ) {
			return __( '(an empty response)', 'gdpr-compliant-recaptcha-for-all-forms' );
		}

		if ( strlen( $flat ) > self::RAW_PREFIX_LENGTH ) {
			$flat = substr( $flat, 0, self::RAW_PREFIX_LENGTH ) . '…';
		}

		return '"' . $flat . '"';
	}
}
