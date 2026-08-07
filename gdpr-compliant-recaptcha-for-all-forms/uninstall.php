<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	die( 'Are you ok?' );
}

/** Class Uninstall
 *
 */
class Uninstall {

	/**
	 * @return void
	 */
	public static function run() {
		require_once __DIR__ . '/includes/class-option.php';

		$constants = ( new \ReflectionClass( Option::class ) )->getConstants();

		foreach ( $constants as $constant ) {
			$const_prefix = substr( $constant, 0, strlen( Option::PREFIX ) );

			if ( Option::PREFIX === $const_prefix ) {
				delete_option( $constant );
			}
		}

		// Options whose Option constant is gone because the feature was removed. The
		// loop above only sees existing constants, so without this list an old install
		// would keep a stray row in wp_options for good.
		// - gdpr_pow_pow_apply_rest: the "Apply on REST-API" switch, removed in 5.3.0
		//   together with the client-forgeable referer exemption it gated.
		$legacy_options = array( 'gdpr_pow_pow_apply_rest' );
		foreach ( $legacy_options as $legacy_option ) {
			delete_option( $legacy_option );
		}

		global $wpdb;
		$table_name_mail    = $wpdb->prefix . 'recaptcha_gdpr_message_rgm';
		$table_name_details = $wpdb->prefix . 'recaptcha_gdpr_details_rgd';
		$table_name_stamp   = $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs';

		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table_name_mail ) ) ) === $table_name_mail ) {
			$results = $wpdb->query( 'DROP TABLE ' . $table_name_mail . ';' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix, not user input.
		}

		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table_name_details ) ) ) === $table_name_details ) {
			$results = $wpdb->query( 'DROP TABLE ' . $table_name_details . ';' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix, not user input.
		}

		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table_name_stamp ) ) ) === $table_name_stamp ) {
			$results = $wpdb->query( 'DROP TABLE ' . $table_name_stamp . ';' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix, not user input.
		}
	}
}

Uninstall::run();
