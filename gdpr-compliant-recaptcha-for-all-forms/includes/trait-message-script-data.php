<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.

/**
 * Everything the message-page JavaScript is handed: nonces and translated strings.
 *
 * Split out of Message_Page in 6.0.0 because that class was at its 600-line cap and
 * this block is the part of it that grows with EVERY feature — each new one-click
 * action adds a nonce and two or three strings, while the class's actual job (query
 * messages, render them) does not change. Leaving it in place meant the next feature
 * would have to cut something under time pressure; the same reasoning that moved the
 * class list out of the plugin bootstrap file.
 *
 * Pure data assembly: no output, no state. Used by Message_Page.
 */
trait Message_Script_Data {

	/**
	 * The `gdprMsg` object handed to plugin/scripts/recaptcha-gdpr-messages.js.
	 *
	 * @param int|string            $message_type The list currently being viewed; every
	 *                                            nonce is scoped to it, as the callbacks
	 *                                            verify.
	 * @param array<int|string, string> $titles   The list titles, for the strings that
	 *                                            name the current list back to the user.
	 * @return array<string, mixed>
	 */
	private static function script_data( $message_type, $titles ) {
		return array(
			'ajaxUrl'     => admin_url( 'admin-ajax.php' ),
			'messageType' => (string) $message_type,
			'nonces'      => array(
				'search'       => wp_create_nonce( 'render-messages_' . $message_type ),
				'saveList'     => wp_create_nonce( 'save_list_nonce_' . $message_type ),
				'savePattern'  => wp_create_nonce( 'save_pattern_nonce_' . $message_type ),
				'blockValue'   => wp_create_nonce( 'block_value_nonce_' . $message_type ),
				'monitorRoute' => wp_create_nonce( 'monitor_route_nonce_' . $message_type ),
				'gibberish'    => wp_create_nonce( 'gibberish_field_nonce_' . $message_type ),
				// Rescue path of the learned credential-field list: the handler
				// lives in Credential_Learning, only the nonce is minted here.
				'credential'   => wp_create_nonce( Credential_Learning::AJAX_NONCE . $message_type ),
			),
			'i18n'        => array(
				// NB: sprintf( __( … ), $title ) — translate the template, then fill in.
				'confirmDeleteAll'    => sprintf(
					/* translators: %s: inbox/spam/trash title. */
					__( 'You are about to delete all messages from "%s". Are you sure?', 'gdpr-compliant-recaptcha-for-all-forms' ),
					$titles[ $message_type ]
				),
				'moved'               => __( 'Message moved successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'deleted'             => __( 'Message deleted successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'actionAdded'         => __( 'Action added successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'whitelisted'         => __( 'Whitelisting successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'patternSaved'        => __( 'Pattern saved successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'choosePattern'       => __( 'Please choose the message attributes which you want to save as pattern!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'blocked'             => __( 'Blocked successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'blockFailed'         => __( 'Could not block this value.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'credentialAsk'       => __( 'Treat this field as a password field? Its value is removed from this message and from every other saved message, and future submissions never store it. This cannot be undone for messages already received.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'credentialSaved'     => __( 'Field is now treated as a credential field.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'credentialFailed'    => __( 'Could not mark this field as a credential field.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'routeMonitored'      => __( 'Now monitoring this route.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'monitorFailed'       => __( 'Could not start monitoring this route.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'gibberishOn'         => __( 'Checked for gibberish — stop checking', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'gibberishOff'        => __( 'Check this field for gibberish', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'gibberishFailed'     => __( 'Could not change the gibberish selection.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				// %s is a literal placeholder, replaced client-side with the actual
				// domain (only known per table row, not at page-load time when this
				// script is localized) — see blockValue() in recaptcha-gdpr-messages.js.
				/* translators: %s is replaced client-side with the sender's domain, without the @, e.g. "mailinator.com". */
				'confirmSenderDomain' => __( 'Every future submission containing a sender address at %s or its subdomains will be treated as spam. If the WordPress-Login protection is on, this can lock out registered users too, possibly yourself. It is meant for disposable or spam domains — blocking a large provider such as gmail.com will also block real visitors.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
		);
	}
}
