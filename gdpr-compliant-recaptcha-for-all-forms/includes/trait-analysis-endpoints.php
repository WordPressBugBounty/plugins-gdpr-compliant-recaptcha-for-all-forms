<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/messages.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Analysis_Endpoints: the two direct-analysis-overlay ajax callbacks that hand
 * the frontend its configuration — get_patterns() (the current pattern/action/route
 * lists) and save_pattern_callback() (write a captured entry into the scope).
 *
 * SCHNITTLINIE (2026-08-28, CLAUDE.md "Dateigroessen"): class-analysis.php stood at
 * 595 of its 600-line cap. A trait, not a second class, for the same reason as
 * Message_Actions/Message_Page: both methods are registered as
 * `array( $this, ... )` ajax callbacks of Analysis (run()) and read its own
 * STORE_NONCE_ACTION constant via self:: — a trait keeps those bindings
 * byte-identical, the split is a move, not a rewire. The other three endpoints
 * (store_analysis_entry(), restore_analysis_entries() and their *_data() halves)
 * stay in class-analysis.php; this trait holds only the two that were pulled to
 * close the gap.
 */
trait Analysis_Endpoints {
	/** Function to get the patterns to apply the spam check to the frontend
	 *
	 */
	public function get_patterns() {

		// Same CSRF + capability gate as the other direct-analysis endpoints. The
		// hook-time gate in run() only registers this action for manage_options users,
		// but relying on that alone is fragile (any refactor of run() reopens it) and a
		// callback without check_ajax_referer is a certain review finding — it returns
		// the full spam-detection configuration.
		if ( ! current_user_can( 'manage_options' ) || ! check_ajax_referer( self::STORE_NONCE_ACTION, '_ajax_nonce', false ) ) {
			wp_send_json_error( array( 'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		$existing_pattern       = get_option( Option::POW_PARAMETER_PATTERN );
		$existing_lines_pattern = null;
		$existing_action        = get_option( Option::POW_EXPLICIT_ACTION );
		$existing_lines_action  = null;
		// Third signature class (REST_ROUTES_PLAN.md AP3/AP5): so checkPatterns() in
		// recaptcha-gdpr-analysis.js can mark a captured entry "covered" when its
		// request targeted an already-monitored REST route — mirrors patterns/actions
		// above, same textarea-line format.
		$existing_route       = get_option( Option::POW_REST_ROUTES );
		$existing_lines_route = null;
		if ( $existing_pattern ) {
			$existing_lines_pattern = preg_split( "/\r\n|\n|\r/", $existing_pattern, -1, PREG_SPLIT_NO_EMPTY );
		}
		if ( $existing_action ) {
			$existing_lines_action = preg_split( '/\r\n|\n|\r/', $existing_action, -1, PREG_SPLIT_NO_EMPTY );
		}
		if ( $existing_route ) {
			$existing_lines_route = preg_split( '/\r\n|\n|\r/', $existing_route, -1, PREG_SPLIT_NO_EMPTY );
		}

		$array_result = array(
			'patterns' => $existing_lines_pattern,
			'actions'  => $existing_lines_action,
			'routes'   => $existing_lines_route,
		);

		// Make your array as json
		wp_send_json( $array_result );

		// Don't forget to stop execution afterward.
		wp_die();
	}

	/** Save Pattern or Ajax-Action
	 *
	 * CSRF-guarded like store_analysis_entry()/restore_analysis_entries(): one shared
	 * nonce (STORE_NONCE_ACTION, sent by the overlay JS as _ajax_nonce) covers all
	 * three direct-analysis endpoints. The capability check mirrors the hook-time
	 * gate in run() — defense in depth, and the nonce alone is not an authz check.
	 */
	public function save_pattern_callback() {
		if ( ! current_user_can( 'manage_options' ) || ! check_ajax_referer( self::STORE_NONCE_ACTION, '_ajax_nonce', false ) ) {
			wp_send_json_error(
				array(
					'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				)
			);
		}

		// Get whitelisting parameters. Consistent with Message_Page::save_pattern_callback():
		// wp_unslash() before sanitize; guard against a blank line, which would make
		// Option::get_rows() build "WHERE  GROUP BY" (empty OR-list) and throw a SQL error
		// on every message page.
		$pattern  = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
		$standard = isset( $_POST['standard'] ) ? filter_var( wp_unslash( $_POST['standard'] ), FILTER_VALIDATE_BOOLEAN ) : false;

		if ( '' === $pattern ) {
			wp_send_json_error( array( 'error_message' => __( 'Empty pattern.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
			exit;
		}

		// SELF-LOCKOUT GUARD, the same question the settings textarea and the agent path
		// ask — see Scope_Add::pattern_locks_out_admin(). This is a one-click write from
		// an overlay, so there is no second save to hang a confirmation on the way
		// Overbroad_Pattern_Guard does; a named refusal that says where to go instead is
		// the recoverable answer. Both branches of this endpoint write a MONITORING
		// option, so both are guarded.
		//
		// THE ACTION BRANCH ASKS Scope_Add::action_line_refusal() SINCE 2026-08-28, and
		// nothing else: a line for POW_EXPLICIT_ACTION may now be a JSON rule
		// (Action_Rules, handbuch/matchers.md), and the bare name check this used to do
		// reads such a line as one long action name and always calls it harmless. The
		// helper judges plain names exactly as before and adds the three rule questions
		// (arms / pinned name / core-screen collision). The UI that will build these
		// lines is untrusted — this endpoint is the boundary, so it validates even
		// though today's overlay only sends plain names.
		if ( $standard ) {
			$refusal = Scope_Add::action_line_refusal( $pattern );
			if ( null !== $refusal ) {
				wp_send_json_error( array( 'error_message' => $refusal ) );
				exit;
			}
		} elseif ( Scope_Add::pattern_locks_out_admin( $pattern ) ) {
			wp_send_json_error( array( 'error_message' => Scope_Add::pattern_lockout_message() ) );
			exit;
		}

		$existing_option = null;
		if ( $standard ) {
			$existing_option = get_option( Option::POW_EXPLICIT_ACTION );
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
			if ( $standard ) {
				update_option( Option::POW_EXPLICIT_ACTION, $updated_option );
				$property = __( 'Apply on actions', 'gdpr-compliant-recaptcha-for-all-forms' );
			} else {
				update_option( Option::POW_PARAMETER_PATTERN, $updated_option );
				$property = __( 'Apply on pattern', 'gdpr-compliant-recaptcha-for-all-forms' );
			}

			/* translators: %s is the settings-page property name ("Apply on actions" or "Apply on pattern") the entry was saved under. */
			wp_send_json_success( array( 'message' => sprintf( __( 'Submission type added successfully. You can find and change it on the plugins settings page under the tab "Scope", in the property "%s".', 'gdpr-compliant-recaptcha-for-all-forms' ), $property ) ) );
		} else {
			// Pattern already in place
			wp_send_json_error( array( 'error_message' => __( 'Submission type already exists.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		exit;
	}
}
