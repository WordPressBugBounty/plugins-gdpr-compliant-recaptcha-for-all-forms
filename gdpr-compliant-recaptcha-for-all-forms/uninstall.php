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

		global $wpdb;

		// Delete every option whose NAME carries our prefix, instead of reflecting over
		// Option::class's own constants. The old reflection loop only ever saw a
		// constant that happened to be declared ON Option itself -- a constant like
		// Gibberish_Notice::PENDING (same 'gdpr_pow_' prefix, different owning class)
		// was invisible to it and leaked a row in wp_options forever (ISSUES.md,
		// "Deinstallation laesst Options-Zeilen zurueck"). A prefix match does not care
		// which class owns the constant, so it also makes the manually maintained
		// legacy-options list this file used to carry obsolete: every option a removed
		// feature ever wrote (e.g. the old "Apply on REST-API" switch,
		// gdpr_pow_pow_apply_rest, dropped in 5.3.0) already carries the prefix and is
		// caught the same way -- no per-removed-feature bookkeeping needed anymore.
		// tests/unit/OptionPrefixCoverageTest.php is the guard that every option name
		// this plugin actually reads/writes really does carry the prefix, which is what
		// this query depends on.
		//
		// Not multisite-relevant: nothing here is ever stored as a site option, only as
		// a per-site option (confirmed by grep across plugin/includes/ — no
		// add_site_option()/update_site_option() call exists), so a single wp_options
		// query is enough; WP_UNINSTALL_PLUGIN with 'delete_plugins' already runs this
		// file once per site on a multisite uninstall.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->options, not user input; the LIKE value itself IS passed through prepare().
				$wpdb->esc_like( Option::PREFIX ) . '%'
			)
		);

		// Transients this plugin sets (…_echo_values, …_scope_added, the review-request
		// "seen" cache, the overbroad-pattern-save marker, the credential-cleanup lock,
		// the fp/no-pow health buckets) are DELIBERATELY left alone here. WordPress
		// stores a transient's row under "_transient_<name>"/"_transient_timeout_<name>"
		// — never under the bare 'gdpr_pow_...' name itself — so the LIKE query above
		// never touches them anyway, and every one of them carries a short, finite TTL
		// (minutes, at most a day for the review-request cache). They expire and clean
		// themselves up on the next read regardless of whether the plugin is still
		// installed; adding a second LIKE query for '_transient_gdpr_pow_%' /
		// '_transient_timeout_gdpr_pow_%' would only save that brief, harmless wait.
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
