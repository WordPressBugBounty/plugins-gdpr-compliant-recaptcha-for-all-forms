<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Message_Actions: the write half of Message_Page — every ajax callback that
 * CHANGES something (the two list/pattern savers, the two one-click writers
 * "block this value" / "monitor this route", plus moving and deleting messages).
 *
 * SCHNITTLINIE (Welle 3, PLAN-DATEIGROESSE.md): Message_Page was one 1428-line file.
 * It is split by what a method DOES, not by what it is about:
 *   - trait-message-actions.php (this file) — callbacks that write.
 *   - trait-message-list.php               — callbacks that only read and render.
 *   - class-message-page.php               — construction, menu, enqueue and the
 *                                            single-message detail view.
 * A trait, not a second class, on purpose: these methods are registered as
 * `array( $this, ... )` ajax callbacks of Message_Page and share its private
 * list/whitelist caches. A trait keeps every one of those bindings byte-identical —
 * the split is a move, not a rewire.
 */
trait Message_Actions {
	/** List Ajax-Action*/
	public function save_list_parameter_callback() {

		// Check capability + security nonce. Editing the explicit-actions / hide lists
		// writes plugin configuration, so require manage_options (consistent with
		// block_value_callback and save_pattern_callback), not merely the edit_pages
		// the admin page is rendered under.
		$message_type   = filter_var( isset( $_POST['messageType'] ) ? wp_unslash( $_POST['messageType'] ) : '', FILTER_VALIDATE_INT );
		$security_nonce = isset( $_POST['security_nonce'] ) ? filter_var( wp_unslash( $_POST['security_nonce'] ), FILTER_UNSAFE_RAW ) : '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $security_nonce, 'save_list_nonce_' . $message_type ) ) {
			$array_result = array(
				'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
			wp_send_json_error( $array_result );
			exit;
		}

		// Get whitelisting parameters
		$list_key = isset( $_POST['listKey'] ) ? sanitize_text_field( wp_unslash( $_POST['listKey'] ) ) : '';
		// Sanitize the boolean using filter_var()
		$hide = isset( $_POST['hide'] ) ? filter_var( wp_unslash( $_POST['hide'] ), FILTER_VALIDATE_BOOLEAN ) : false;

		$existing_option = null;
		if ( $hide ) {
			$existing_option = get_option( Option::POW_HIDE_ACTION );
		} else {
			$existing_option = get_option( Option::POW_EXPLICIT_ACTION );
		}

		$existing_lines = preg_split( "/\r\n|\n|\r/", $existing_option );

		// Check, whether the listing-parameter already exists
		if ( ! in_array( $list_key, $existing_lines, true ) ) {
			// If not add the new parameter
			$existing_lines[] = $list_key;

			// Transform to String again
			$updated_option = implode( "\n", $existing_lines );

			// Save the option
			if ( $hide ) {
				update_option( Option::POW_HIDE_ACTION, $updated_option );
			} else {
				update_option( Option::POW_EXPLICIT_ACTION, $updated_option );
			}
			$this->render_messages();
		} else {
			// Whitelisting parametert already in place
			wp_send_json_error( array( 'error_message' => __( 'Ajax-action already listed.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		exit;
	}

	/** Save Pattern*/
	public function save_pattern_callback() {

		// Check capability + security nonce. Managing spam patterns writes plugin
		// configuration, so require manage_options (not merely the edit_pages the
		// admin page is rendered under) — this narrows the SQLi attack surface from
		// Editor+ to admins (CVE-2026-16094 / CVE-2026-16146, defense in depth on top
		// of the esc_sql() at the LIKE sinks in Option::get_rows()/get_messages()).
		$message_type   = filter_var( isset( $_POST['messageType'] ) ? wp_unslash( $_POST['messageType'] ) : '', FILTER_VALIDATE_INT );
		$security_nonce = isset( $_POST['security_nonce'] ) ? filter_var( wp_unslash( $_POST['security_nonce'] ), FILTER_UNSAFE_RAW ) : '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $security_nonce, 'save_pattern_nonce_' . $message_type ) ) {
			$array_result = array(
				'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
			wp_send_json_error( $array_result );
			exit;
		}

		// Get whitelisting parameters. wp_unslash() reverses WordPress' magic-quote
		// slashing so the stored JSON pattern stays valid; sanitize_text_field()
		// cleans it. The SQL safety itself is enforced at the LIKE sinks via esc_sql().
		$pattern = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
		$hide    = isset( $_POST['hide'] ) ? filter_var( wp_unslash( $_POST['hide'] ), FILTER_VALIDATE_BOOLEAN ) : false;

		$existing_option = null;
		if ( $hide ) {
			$existing_option = get_option( Option::POW_HIDE_PATTERN );
		} else {
			$existing_option = get_option( Option::POW_PARAMETER_PATTERN );
		}
		$existing_lines = preg_split( "/\r\n|\n|\r/", $existing_option );

		// Check, whether the whitelisting-parameter already exists
		if ( ! in_array( $pattern, $existing_lines, true ) ) {
			// If not add the new parameter
			$existing_lines[] = $pattern;

			// Transform to String again
			$updated_option = implode( "\n", $existing_lines );

			// Save the option
			if ( $hide ) {
				update_option( Option::POW_HIDE_PATTERN, $updated_option );
			} else {
				update_option( Option::POW_PARAMETER_PATTERN, $updated_option );
			}
			$this->render_messages();
		} else {
			// Pattern already in place
			wp_send_json_error( array( 'error_message' => __( 'Pattern already exists.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		exit;
	}

	/**
	 * One-click "Block this sender"/"Block this domain"/"Block this sender's domain"
	 * (BACKLOG bausteine 2 + "Absender-Domain-Blockliste"): append the value as a
	 * PLAIN-TEXT line to POW_BLOCKED_VALUES, the standalone blocklist option. For
	 * 'sender_domain' the stored value is "@domain" — Echo_Values::matches_wildcard_values()
	 * treats a leading @ as the sender-domain match form, see handbuch/detection.md.
	 * Capability-gated (manage_options) + nonce. CRITICAL self-DoS guard: refuses to
	 * block a value on the site's own registrable domain.
	 *
	 * The three guards and the four match forms are UNCHANGED by
	 * PLAN-BLOCKLIST-TRENNUNG.md; what changed is where the line is written and in what
	 * shape. Until then this wrote {"*":"value"} into POW_PARAMETER_PATTERN, where the
	 * same textarea also held monitoring patterns — one option carrying two authorities.
	 * Dedup now compares the plain value against the blocklist's own lines.
	 */
	public function block_value_callback() {
		$message_type   = filter_var( isset( $_POST['messageType'] ) ? wp_unslash( $_POST['messageType'] ) : '', FILTER_VALIDATE_INT );
		$security_nonce = isset( $_POST['security_nonce'] ) ? filter_var( wp_unslash( $_POST['security_nonce'] ), FILTER_UNSAFE_RAW ) : '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $security_nonce, 'block_value_nonce_' . $message_type ) ) {
			wp_send_json_error( array( 'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
			exit;
		}

		$kind        = isset( $_POST['kind'] ) ? sanitize_text_field( wp_unslash( $_POST['kind'] ) ) : '';
		$raw         = isset( $_POST['value'] ) ? sanitize_text_field( wp_unslash( $_POST['value'] ) ) : '';
		$own_domains = Echo_Store::site_domains();
		$value       = null;

		if ( 'sender' === $kind ) {
			$email = Echo_Values::extract_email( $raw );
			if ( null === $email ) {
				wp_send_json_error( array( 'error_message' => __( 'No valid sender address found.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
				exit;
			}
			// Self-DoS guard: refuse an address on the site's own domain.
			$at            = strrpos( $email, '@' );
			$sender_domain = false !== $at ? Echo_Values::registrable_domain( substr( $email, $at + 1 ), array() ) : null;
			if ( null !== $sender_domain && in_array( $sender_domain, $own_domains, true ) ) {
				wp_send_json_error( array( 'error_message' => __( 'Refusing to block an address on your own domain.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
				exit;
			}
			$value = $email;
		} elseif ( 'sender_domain' === $kind ) {
			$email = Echo_Values::extract_email( $raw );
			if ( null === $email ) {
				wp_send_json_error( array( 'error_message' => __( 'No valid sender address found.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
				exit;
			}
			// Self-DoS guard AND input validation in one call, deliberately the SAME
			// rule the two other sites use (the button in render_message() only appears
			// when this passes, and matches_wildcard_values() only treats a stored
			// "@domain" line as a sender-domain rule when it passes). A line that the
			// three sites judged differently is the bug this shape prevents.
			$at     = strrpos( $email, '@' );
			$domain = false !== $at ? strtolower( trim( substr( $email, $at + 1 ) ) ) : '';
			if ( ! Echo_Values::is_blockable_sender_domain( $domain, $own_domains ) ) {
				wp_send_json_error( array( 'error_message' => __( 'Cannot block this sender domain (invalid, or your own domain).', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
				exit;
			}
			$value = '@' . $domain;
		} elseif ( 'domain' === $kind ) {
			// registrable_domain() returns null for the own domain(s), an IP, or a
			// non-domain — the same self-DoS guard, plus input validation.
			$value = Echo_Values::registrable_domain( $raw, $own_domains );
			if ( null === $value ) {
				wp_send_json_error( array( 'error_message' => __( 'Cannot block this value (empty, an IP address, or your own domain).', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
				exit;
			}
		} else {
			wp_send_json_error( array( 'error_message' => __( 'Invalid block request.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
			exit;
		}

		// Plain text, one value per line — the format Echo_Values::values_from_plaintext_lines()
		// reads. Dedup is done on the NORMALIZED value (trim + lowercase), because that is
		// what the matcher compares: two lines differing only in case are one rule, and
		// storing both would tell the operator he added something when he did not.
		$line     = (string) $value;
		$existing = (string) get_option( Option::POW_BLOCKED_VALUES );
		$lines    = '' === trim( $existing ) ? array() : (array) preg_split( "/\r\n|\n|\r/", $existing, -1, PREG_SPLIT_NO_EMPTY );

		if ( in_array( Echo_Values::normalize_wildcard( $line ), Echo_Values::values_from_plaintext_lines( $lines ), true ) ) {
			wp_send_json_error( array( 'error_message' => __( 'This value is already blocked.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
			exit;
		}

		$lines[] = $line;
		update_option( Option::POW_BLOCKED_VALUES, implode( "\n", $lines ) );
		wp_send_json_success(
			array(
				'message' => __( 'Blocked successfully! The value was added to "Blocked values" in the plugin settings.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'value'   => $value,
			)
		);
		exit;
	}

	/**
	 * One-click "Monitor this route" (REST_ROUTES_PLAN.md AP5): append the REST route
	 * shown on a message's detail view to POW_REST_ROUTES. Same shape as
	 * block_value_callback() above — capability-gated (manage_options) + nonce, dedup
	 * against the existing textarea lines.
	 *
	 * MUST run through the SAME self-lockout guard as the settings textarea
	 * (RestRoute::reject_self_lockout_lines(), verified in AP3's review and wired into
	 * Settings_Menu::update_settings()) — otherwise this one-click path could add a
	 * route that covers a WordPress core namespace (e.g. `wp/v2`) and lock the admin
	 * out of wp-admin/the block editor, even though the textarea itself is protected.
	 */
	public function monitor_route_callback() {
		$message_type   = filter_var( isset( $_POST['messageType'] ) ? wp_unslash( $_POST['messageType'] ) : '', FILTER_VALIDATE_INT );
		$security_nonce = isset( $_POST['security_nonce'] ) ? filter_var( wp_unslash( $_POST['security_nonce'] ), FILTER_UNSAFE_RAW ) : '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $security_nonce, 'monitor_route_nonce_' . $message_type ) ) {
			wp_send_json_error( array( 'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
			exit;
		}

		// Same normalization RestRoute::extract() already produced when the route was
		// captured (leading slash, decoded, no trailing slash) — stored without the
		// leading slash to match the convention of the default/admin-entered pattern
		// lines (matches()/reject_self_lockout_lines() re-segment either way, so this is
		// purely cosmetic consistency in the textarea, not a matching requirement).
		$route = isset( $_POST['route'] ) ? ltrim( sanitize_text_field( wp_unslash( $_POST['route'] ) ), '/' ) : '';
		if ( '' === $route ) {
			wp_send_json_error( array( 'error_message' => __( 'No route to monitor.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
			exit;
		}

		$existing = (string) get_option( Option::POW_REST_ROUTES );
		$lines    = '' === trim( $existing ) ? array() : preg_split( "/\r\n|\n|\r/", $existing, -1, PREG_SPLIT_NO_EMPTY );

		foreach ( $lines as $existing_line ) {
			if ( trim( $existing_line ) === $route ) {
				wp_send_json_error( array( 'error_message' => __( 'This route is already monitored.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
				exit;
			}
		}

		$lines[]   = $route;
		$candidate = implode( "\n", $lines );

		list( $result, $rejected ) = RestRoute::reject_self_lockout_lines( $candidate );
		if ( ! empty( $rejected ) ) {
			wp_send_json_error(
				array(
					'error_message' => __( 'Refusing to monitor this route: it would also cover a WordPress core route and could lock you out of wp-admin.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				)
			);
			exit;
		}

		update_option( Option::POW_REST_ROUTES, $result );
		wp_send_json_success(
			array(
				'message' => __( 'Now monitoring this route.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'route'   => $route,
			)
		);
		exit;
	}
	/**Delete message*/
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- WordPress ajax callback (wp_ajax_delete_message) signature; $messages is unused because the payload is read from $_POST.
	public function delete_message( $messages ) {
		if ( ! (
				isset( $_POST['search'] )
				&& isset( $_POST['search_nonce'] )
				&& isset( $_POST['messageType'] )
				)
			) {
			$array_result = array(
				'success'       => 0,
				'error_message' => __( 'Delete action is invalid!', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
			wp_send_json( $array_result );
			exit;
		}

		global $wpdb;
		$message;
		$message_type   = filter_var( wp_unslash( $_POST['messageType'] ), FILTER_VALIDATE_INT );
		$security_nonce = filter_var( wp_unslash( $_POST['search_nonce'] ), FILTER_UNSAFE_RAW );

		// Authorisation + CSRF gate BEFORE any DELETE. The "delete all" branch below
		// runs whenever $_POST['messages'] is not a valid JSON array, so a missing or
		// blank messages param must never reach a DELETE without a verified capability
		// and nonce. Previously only the presence of search_nonce was checked (its value
		// was first verified in the closing render_messages() call — after the delete),
		// which let any logged-in user (down to Subscriber) wipe a whole message type.
		// The search_nonce is the same 'render-messages_' . $message_type token that the
		// closing render_messages() already requires, so the admin UI keeps working.
		if ( ! current_user_can( 'manage_options' )
			|| ! wp_verify_nonce( $security_nonce, 'render-messages_' . $message_type ) ) {
			wp_send_json_error( array( 'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
			exit;
		}

		$wpdb->query( 'START TRANSACTION' );
		$raw_messages   = isset( $_POST['messages'] ) ? wp_unslash( $_POST['messages'] ) : '';
		$array_variable = json_decode( $raw_messages );

		if ( $array_variable ) {
			foreach ( $array_variable as $raw_message ) {
				parse_str( $raw_message, $message );

				if ( ! (
						isset( $message['deleteNonce'] )
						&& isset( $message['messsageID'] )
						&& wp_verify_nonce( $message['deleteNonce'], 'delete-message-' . $message['messsageID'] . $message_type )
						)
				) {
					$array_result = array(
						'success'       => 0,
						'error_message' => __( 'Delete action is invalid!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					);
					wp_send_json( $array_result );
				}
				$message_id = filter_var( $message['messsageID'], FILTER_VALIDATE_INT );

				// Anfrage ausführen
				$wpdb->query(
					$wpdb->prepare(
						'DELETE FROM ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm
                                    WHERE rgm_id = %d
                                    AND rgm_type = %d
                                ',
						$message_id,
						$message_type
					)
				);

				// Anfrage ausführen
				$wpdb->query(
					$wpdb->prepare(
						'DELETE FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd
                                    WHERE rgm_id = %d
                                ',
						$message_id
					)
				);

			}
		} else {
			// Anfrage ausführen
			$wpdb->query(
				$wpdb->prepare(
					'DELETE FROM ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm
                                WHERE rgm_type = %d
                            ',
					$message_type
				)
			);

			// Anfrage ausführen
			$wpdb->query(
				'DELETE rgd FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd rgd
                            LEFT JOIN ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm rgm ON rgd.rgm_id = rgm.rgm_id
                            WHERE rgm.rgm_id IS NULL'
			);
		}
		$wpdb->query( 'COMMIT' );
		$this->render_messages();
	}

	/**Change the type of the message 1 = clean, 2= spam, 3= trash*/
	public function change_message_type() {

		if ( ! (
				isset( $_POST['search'] )
				&& isset( $_POST['search_nonce'] )
				&& isset( $_POST['messageType'] )
				&& isset( $_POST['changeType'] )
				&& isset( $_POST['messages'] )
				)
			) {
			$array_result = array(
				'success'       => 0,
				'error_message' => __( 'Change action is invalid!', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
			wp_send_json( $array_result );
			exit;
		}

		global $wpdb;
		$message;
		$message_type   = filter_var( wp_unslash( $_POST['messageType'] ), FILTER_VALIDATE_INT );
		$change_type    = filter_var( wp_unslash( $_POST['changeType'] ), FILTER_VALIDATE_INT );
		$security_nonce = filter_var( wp_unslash( $_POST['search_nonce'] ), FILTER_UNSAFE_RAW );

		// Authorisation + CSRF gate before any state change. Per-item moveNonce is still
		// verified in the loop below, but the top-level search_nonce was previously only
		// checked for presence, not validity, and no capability was required.
		if ( ! current_user_can( 'manage_options' )
			|| ! wp_verify_nonce( $security_nonce, 'render-messages_' . $message_type ) ) {
			wp_send_json_error( array( 'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
			exit;
		}

		$raw_messages   = isset( $_POST['messages'] ) ? wp_unslash( $_POST['messages'] ) : '';
		$array_variable = json_decode( $raw_messages );

		// json_decode() returns null for '', invalid JSON, or the literal `null` -- guard
		// before the loop (mirrors delete_message()'s `if ( $array_variable )` check
		// above in this file) so an empty/garbage `messages` payload no-ops instead of a
		// PHP `foreach() argument must be of type array|object, null given` warning
		// landing IN this endpoint's JSON body, ahead of the real response. Same damage
		// class as HANDBUCH.md §12 Ursache 1 (a notice before the JSON breaks the
		// caller's response.json()), just on Message-Page-Ajax instead of the PoW hot
		// path -- confirmed live under display_errors=1 before this fix, see
		// tests/integration/cases/php-deprecation-audit.mjs.
		foreach ( is_array( $array_variable ) ? $array_variable : array() as $raw_message ) {
			parse_str( $raw_message, $message );
			if ( ! (
					isset( $message['moveNonce'] )
					&& isset( $message['messsageID'] )
					&& wp_verify_nonce( $message['moveNonce'], 'move-message-' . $message['messsageID'] . $message_type . $change_type )
					)
			) {
				$array_result = array(
					'success'       => 0,
					'error_message' => __( 'Change action is invalid!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				);
				wp_send_json( $array_result );
			}
			$message_id = filter_var( $message['messsageID'], FILTER_VALIDATE_INT );

			$wpdb->query(
				$wpdb->prepare(
					'UPDATE ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm
                                SET rgm_type = %d
                                WHERE rgm_id = %d
                                  AND rgm_type = %d
                            ',
					$change_type,
					$message_id,
					$message_type
				)
			);

		}

		$this->render_messages();
	}
}
