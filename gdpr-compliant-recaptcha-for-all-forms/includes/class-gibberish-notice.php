<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/gibberish.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.

/**
 * The one-off notice telling an EXISTING installation that gibberish detection is now
 * off, and how to switch it back on for a field.
 *
 * WHY IT EXISTS AT ALL. Updating to 6.0.0 silently stops a check that was running
 * before — and "something changed behind the operator's back" is exactly the complaint
 * this release is meant to answer, not to cause. There is nothing to migrate (the
 * check never had a setting, and nobody can guess a field selection on the operator's
 * behalf; seeding the old "everything" semantics would recreate the very mode 6.0.0
 * removes), so the honest substitute is to say so, once, where he will see it.
 *
 * Deliberately NOT shown on a fresh install: there, off-by-default is simply how the
 * plugin works, and a notice about a change nobody experienced is noise.
 *
 * Same shape as the Scope_Sync legacy-stock notice (handbuch/gate.md): dismissible,
 * capability-gated, and it never touches a setting by itself.
 */
final class Gibberish_Notice {

	/**
	 * Whether the notice is still owed. Set during the version upgrade, cleared when
	 * dismissed — a plain flag, not a setting, hence absent from prepare_options().
	 *
	 * @var string
	 */
	const PENDING = Option::PREFIX . 'pow_gibberish_notice';

	/** The dismiss action, nonce-protected. */
	const ACTION = 'gdpr_dismiss_gibberish_notice';

	/**
	 * Remember that this installation existed before the selection-based gibberish
	 * detection. Called from the version gate in activate(), which is the only place
	 * that still knows the previously stored version.
	 *
	 * @param string|false $previous_version The version stored before this upgrade.
	 * @return void
	 */
	public static function remember_upgrade( $previous_version ) {
		if ( ! $previous_version || ! version_compare( (string) $previous_version, '6.0.0', '<' ) ) {
			return;
		}
		update_option( self::PENDING, '1' );
	}

	/**
	 * Wire the notice and its dismissal.
	 *
	 * @return void
	 */
	public function run() {
		add_action( 'admin_notices', array( $this, 'render' ) );
		add_action( 'admin_init', array( $this, 'handle_dismiss' ) );
	}

	/**
	 * Print the notice, once per installation, to administrators only.
	 *
	 * @return void
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) || ! get_option( self::PENDING ) ) {
			return;
		}
		$url = wp_nonce_url( add_query_arg( self::ACTION, '1' ), self::ACTION );
		echo '<div class="notice notice-info is-dismissible"><p><strong>'
			. esc_html__( 'Invisible Anti-Spam: gibberish detection is now off', 'gdpr-compliant-recaptcha-for-all-forms' )
			. '</strong><br>'
			. esc_html__( 'It used to check every field of every submission, which sometimes refused real messages over a technical field that just looks random. It now only checks fields you pick yourself: open a stored message and use the button next to the field. Proof of work, blocked values and the repeat-sender lock are unaffected.', 'gdpr-compliant-recaptcha-for-all-forms' )
			. '</p><p><a href="' . esc_url( $url ) . '">'
			. esc_html__( 'Got it', 'gdpr-compliant-recaptcha-for-all-forms' )
			. '</a></p></div>';
	}

	/**
	 * Clear the flag when the administrator acknowledges it.
	 *
	 * @return void
	 */
	public function handle_dismiss() {
		if ( ! isset( $_GET[ self::ACTION ] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, self::ACTION ) ) {
			return;
		}
		delete_option( self::PENDING );
	}
}
