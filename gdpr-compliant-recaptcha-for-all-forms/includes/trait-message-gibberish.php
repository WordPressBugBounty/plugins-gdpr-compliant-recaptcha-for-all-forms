<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/gibberish.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.

/**
 * The message view's half of the gibberish field selection: the per-field toggle and
 * the one write path behind it.
 *
 * A SEPARATE trait from trait-message-actions.php, which holds the other one-click
 * actions (block sender/domain, monitor route, treat as credential). Not because these
 * are a different kind of thing — they are the same kind — but because that file sat
 * at 484 lines and this would have pushed it over the 600-line cap. The cut is along
 * the subject: everything here is about WHICH FIELDS get scored for gibberish, and it
 * is the only part of the message view that has to know about form signatures.
 *
 * Used by Message_Page, which composes both traits; every call still reads
 * $this->…() over there and every property is the same.
 */
trait Message_Gibberish {

	/**
	 * The gibberish field selection of one saved message: its signature, the fields
	 * already selected for it, and whether the button can be offered at all.
	 *
	 * Signature is determined at DISPLAY time (Gibberish_Signature::signature_for()), so
	 * the button works on messages saved long before 6.0.0 — see the reasoning there.
	 *
	 * @param object[] $details The message's detail rows.
	 * @phpstan-param array<int, object{rgd_attribute: string, rgd_value: string, rgm_posted: mixed}> $details
	 * @return array{signature: array{kind: string, signature: string}|null, fields: string[]}
	 */
	private static function gibberish_context( $details ) {
		$flat   = array();
		$action = '';
		$route  = '';
		foreach ( $details as $detail ) {
			$attribute = (string) $detail->rgd_attribute;
			if ( '_gdpr_route' === $attribute ) {
				$route = (string) $detail->rgd_value;
				continue;
			}
			if ( 'action' === $attribute ) {
				$action = (string) $detail->rgd_value;
			}
			// ONLY the rows the visitor actually posted. The plugin's own technical rows
			// (`from_site`, `post_on_site`, `is_ajax`, `IP adress`, `action`) are stored
			// alongside them, and letting them into the match would let a line like
			// {"action":null} bind every message in the inbox to one signature. The
			// action and the route are read separately above, where they belong.
			if ( 0 !== strpos( $attribute, '_gdpr_' ) && $detail->rgm_posted ) {
				$flat[ $attribute ] = (string) $detail->rgd_value;
			}
		}
		$signature = Gibberish_Signature::signature_for(
			$action,
			$route,
			array(
				'actions'  => get_option( Option::POW_EXPLICIT_ACTION ),
				'patterns' => get_option( Option::POW_PARAMETER_PATTERN ),
				'routes'   => get_option( Option::POW_REST_ROUTES ),
			),
			Gibberish_Signature::rebuild_tree( $flat )
		);
		$selected  = array();
		if ( null !== $signature ) {
			$rules = Gibberish_Fields::parse_lines( get_option( Option::POW_GIBBERISH_FIELDS ) );
			foreach ( $rules as $rule ) {
				if ( $rule['kind'] === $signature['kind'] && $rule['signature'] === $signature['signature'] ) {
					$selected = $rule['fields'];
				}
			}
		}
		return array(
			'signature' => $signature,
			'fields'    => $selected,
		);
	}

	/**
	 * The per-field gibberish toggle shown in the message detail view.
	 *
	 * A TOGGLE, not an add button: the case that brings an operator here is usually
	 * "stop checking this field", and that has to be solvable in the view where he sees
	 * the problem. Never offered on a credential field — scoring a password is a
	 * permanent false alarm by construction — and never without a signature, where the
	 * caller prints one sentence instead.
	 *
	 * @param string $attribute The field's attribute path.
	 * @param array{signature: array{kind: string, signature: string}|null, fields: string[]} $context The result of gibberish_context().
	 * @return string HTML, empty when no button belongs here.
	 */
	private static function gibberish_button( $attribute, $context ) {
		if ( null === $context['signature'] || Credential_Fields::is_password_path( $attribute ) ) {
			return '';
		}
		$segments = explode( '->', $attribute );
		$leaf     = $segments[ count( $segments ) - 1 ];
		if ( '' === $leaf || Credential_Fields::is_password_key( $leaf ) ) {
			return '';
		}
		$selected = false;
		foreach ( $context['fields'] as $field ) {
			if ( 0 === strcasecmp( $field, $leaf ) ) {
				$selected = true;
				break;
			}
		}
		$label = $selected
			? __( 'Checked for gibberish — stop checking', 'gdpr-compliant-recaptcha-for-all-forms' )
			: __( 'Check this field for gibberish', 'gdpr-compliant-recaptcha-for-all-forms' );
		return ' <button type="button" class="gdpr-gibberish-btn' . ( $selected ? ' is-selected' : '' ) . '"'
			. ' data-field="' . esc_attr( $leaf ) . '"'
			. ' data-kind="' . esc_attr( $context['signature']['kind'] ) . '"'
			. ' data-signature="' . esc_attr( $context['signature']['signature'] ) . '"'
			. ' data-selected="' . ( $selected ? '1' : '0' ) . '"'
			. ' onclick="toggleGibberishField(this)">' . esc_html( $label ) . '</button>';
	}

	/**
	 * Add or remove one field from the gibberish selection — the one write path behind
	 * the toggle above.
	 *
	 * Same shape as the sibling one-click callbacks: capability (manage_options) plus
	 * nonce, and it refuses rather than guesses. A password-like field name is refused
	 * on the SERVER too, not only hidden in the view: the request is attacker-shaped
	 * input like any other, and selecting a password field would score real passwords.
	 *
	 * @return void
	 */
	public function gibberish_field_callback(): void {
		$message_type   = filter_var( isset( $_POST['messageType'] ) ? wp_unslash( $_POST['messageType'] ) : '', FILTER_VALIDATE_INT );
		$security_nonce = isset( $_POST['security_nonce'] ) ? filter_var( wp_unslash( $_POST['security_nonce'] ), FILTER_UNSAFE_RAW ) : '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $security_nonce, 'gibberish_field_nonce_' . $message_type ) ) {
			wp_send_json_error( array( 'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		$field     = isset( $_POST['field'] ) ? sanitize_text_field( wp_unslash( $_POST['field'] ) ) : '';
		$kind      = isset( $_POST['kind'] ) ? sanitize_text_field( wp_unslash( $_POST['kind'] ) ) : '';
		$signature = isset( $_POST['signature'] ) ? sanitize_text_field( wp_unslash( $_POST['signature'] ) ) : '';
		$remove    = isset( $_POST['remove'] ) && '1' === (string) wp_unslash( $_POST['remove'] );

		if ( '' === $field || '' === $signature || ! in_array( $kind, Gibberish_Fields::KINDS, true ) ) {
			wp_send_json_error( array( 'error_message' => __( 'Incomplete request.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}
		if ( ! $remove && Credential_Fields::is_password_key( $field ) ) {
			wp_send_json_error(
				array(
					'error_message' => __( 'This looks like a password field. Passwords are random by nature, so checking one would flag every real submission.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				)
			);
		}

		// split_lines(), not parse_lines(): a line the parser cannot read must survive this
		// write. Otherwise one click here would silently delete what the operator typed
		// into the textarea and the save guard deliberately kept — two ways in, one of
		// them eating the other's work.
		$split = Gibberish_Fields::split_lines( get_option( Option::POW_GIBBERISH_FIELDS ) );
		$rules = $remove
			? Gibberish_Fields::remove_field( $split['rules'], $kind, $signature, $field )
			: Gibberish_Fields::add_field( $split['rules'], $kind, $signature, $field );
		update_option( Option::POW_GIBBERISH_FIELDS, Gibberish_Fields::to_lines( $rules, $split['leftovers'] ) );

		wp_send_json_success(
			array(
				'message'  => $remove
					? __( 'No longer checking this field.', 'gdpr-compliant-recaptcha-for-all-forms' )
					: __( 'Now checking this field for gibberish.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'selected' => $remove ? 0 : 1,
			)
		);
	}

	/**
	 * The one sentence that replaces the buttons when no rule can be bound to this
	 * message at all — a login submission, a hook-path submission, or a form whose
	 * recognition pattern the operator has since deleted.
	 *
	 * Printed instead of silence: a view that simply shows no button leaves the
	 * operator looking for a feature the documentation promised him.
	 *
	 * @param array{signature: array{kind: string, signature: string}|null, fields: string[]} $context The result of gibberish_context().
	 * @return string HTML, empty when the buttons are there.
	 */
	private static function gibberish_notice( $context ) {
		if ( null !== $context['signature'] ) {
			return '';
		}
		return '<p class="gdpr-gibberish-note">'
			. esc_html__( 'Gibberish checking cannot be set up from this message: it carries no form signature the plugin recognises.', 'gdpr-compliant-recaptcha-for-all-forms' )
			. '</p>';
	}
}
