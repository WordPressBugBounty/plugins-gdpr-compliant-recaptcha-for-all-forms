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
