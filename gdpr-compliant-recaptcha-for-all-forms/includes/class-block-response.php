<?php
/**
 * What a blocked submission gets back: the status, the body, and which of the two forms.
 *
 * Cut out of Stamp::check_submit()'s block branch so the one decision that faces every
 * client — "does this answer read as a failure?" — lives in one place and is unit-testable
 * (tests/unit/BlockResponseTest.php).
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
 * The answer to a blocked submission.
 */
final class Block_Response {

	/**
	 * The HTTP status of EVERY block answer, JSON or plain text.
	 *
	 * WHY NOT 200 (the status until 2026-09-25): `wp_send_json_error()` defaults to 200,
	 * and a client that only looks at the status — axios, jQuery 3's `.done()`, `fetch`
	 * with `response.ok`, `wp.apiFetch` — takes a 200 for success. Measured on the zips of
	 * Amelia (axios) and Simply Schedule (jQuery): both showed the visitor the confirmation
	 * page for a booking that was never made. Our client patch could not prevent that: it
	 * hangs on `onreadystatechange`, which those clients never set.
	 *
	 * WHY 422 AND NOT 403: 422 says "the content was refused", which is what happened. 403
	 * is the status a host's error-page interception (nginx `error_page`, WAF templates)
	 * is most often configured for, and a replaced body would lose our message.
	 */
	const STATUS = 422;

	/**
	 * Machine-readable code in the JSON answer, next to the human message.
	 */
	const CODE = 'gdpr_spam_blocked';

	/**
	 * Whether the client expects JSON — unchanged condition from check_submit().
	 *
	 * @param array<string, mixed> $server $_SERVER or a test double.
	 * @param bool                 $ajax   Whether the request was triaged as ajax.
	 * @return bool
	 */
	public static function wants_json( array $server, $ajax ) {
		$accept = isset( $server['HTTP_ACCEPT'] ) && is_string( $server['HTTP_ACCEPT'] ) ? $server['HTTP_ACCEPT'] : '';
		return false !== stripos( $accept, 'application/json' ) || $ajax || isset( $server['HTTP_X_REQUESTED_WITH'] );
	}

	/**
	 * The JSON body. A SUPERSET of what `wp_send_json_error()` produced before, so every
	 * reader of `success`/`data.gdpr_error_message` keeps working; `code` and `message`
	 * are added at the top level because that is where REST clients look — `wp.apiFetch`
	 * rejects with the parsed body, and the WooCommerce blocks show its `message`.
	 *
	 * @param string $message The operator's (or the default) error message.
	 * @return array<string, mixed>
	 */
	public static function json_body( $message ) {
		return array(
			'success' => false,
			'code'    => self::CODE,
			'message' => $message,
			'data'    => array(
				'gdpr_error_message' => $message,
				'status'             => self::STATUS,
			),
		);
	}

	/**
	 * Sends the answer and ends the request.
	 *
	 * @param string $message The error message shown to the sender.
	 * @param bool   $ajax    Whether the request was triaged as ajax.
	 * @return never
	 */
	public static function send( $message, $ajax ) {
		if ( self::wants_json( $_SERVER, $ajax ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- read-only header sniffing, nothing is stored.
			wp_send_json( self::json_body( $message ), self::STATUS ); // Dies itself.
		}
		status_header( self::STATUS );
		echo esc_html( $message );
		exit;
	}
}
