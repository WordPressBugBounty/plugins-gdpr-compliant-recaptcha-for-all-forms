<?php
/**
 * The fail2ban writer of Stamp: one log line per enforced spam verdict.
 *
 * SCHNITTLINIE (2026-09-25): moved out of trait-stamp-persistence.php, which stood at
 * 599 of 600 lines (BACKLOG "Eine Datei steht randvoll") when the risk class needed its
 * detail row there. Moved verbatim; WHEN it is called is decided in check_submit()
 * (class-stamp.php) and did not move.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/detection.md, Abschnitt "Persistenz und Fail2Ban".
// Index/Absprungstelle: HANDBUCH.md — Traits bekommen keine eigene Indexzeile.

/**
 * Fail2Ban logging. Composed into Stamp via Stamp_Persistence.
 */
trait Stamp_Fail2ban {

	/**
	 * Appends one fail2ban-compatible line to spam.log (and auth.log for a login).
	 *
	 * @param string $message          The event text; control characters are stripped.
	 * @param bool   $is_login_attempt Also write the auth.log line.
	 * @return void
	 */
	private function log_fail2ban_event( $message, $is_login_attempt = false ) {
		// Get the configured log directory path
		$log_path = get_option( Option::POW_FAIL_2_BAN_PATH );

		// If no path is provided, simply do nothing (no error logging)
		if ( empty( $log_path ) ) {
			return;
		}

		// Check if the directory exists; if not, attempt to create it
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- fail2ban log dir on an admin-configured path; direct mkdir is intended, WP_Filesystem adds nothing here.
		if ( ! is_dir( $log_path ) && ! mkdir( $log_path, 0755, true ) ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- intentional operator-facing diagnostic when the fail2ban path is misconfigured.
			error_log( 'Fail2Ban Log Path does not exist and could not be created: ' . $log_path );
			return;
		}

		// Ensure the directory is writable before proceeding
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- writability probe on the admin-configured fail2ban log path; direct check is intended.
		if ( ! is_writable( $log_path ) ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- intentional operator-facing diagnostic when the fail2ban path is misconfigured.
			error_log( 'Fail2Ban Log Path is not writable: ' . $log_path );
			return;
		}

		// Define log file paths
		$log_files = array(
			'spam' => $log_path . '/spam.log',
			'auth' => $log_path . '/auth.log',
		);

		// Generate timestamp in ISO 8601 format (UTC)
		// phpcs:ignore WordPress.DateTime.RestrictedFunctions.date_date -- fail2ban log timestamp; behaviour deliberately preserved (existing logs/filters parse this exact server-local format), so no gmdate() switch.
		$timestamp     = date( 'Y-m-d\TH:i:s\Z' );
		$hostname      = isset( $_SERVER['SERVER_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) ) : 'unknown_host'; // Get the server hostname
		$priority_spam = '<42>'; // Priority for spam logs
		$priority_auth = '<34>'; // Priority for authentication logs

		// Defence in depth: fail2ban parses one event per line, so nothing interpolated
		// into a line may carry CR/LF or other control characters (log-injection → forged
		// ban lines). Callers already sanitise the username, but normalise here as well,
		// and restrict the hostname (Host header on a misconfigured vhost) to safe chars.
		$message  = preg_replace( '/[\x00-\x1F\x7F]+/', ' ', (string) $message );
		$hostname = preg_replace( '/[^A-Za-z0-9.\-:_]/', '', $hostname );
		if ( '' === (string) $hostname ) {
			$hostname = 'unknown_host';
		}

		// Create the spam log entry (always logged)
		$spam_log_entry = sprintf( "%s%s %s spam: %s\n", $priority_spam, $timestamp, $hostname, $message );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- fail2ban needs an atomic append (FILE_APPEND | LOCK_EX) to a plain log file; WP_Filesystem has no append+lock equivalent.
		file_put_contents( $log_files['spam'], $spam_log_entry, FILE_APPEND | LOCK_EX );

		// If the request is a WordPress login attempt, also write to the authentication log
		if ( $is_login_attempt ) {
			$auth_log_entry = sprintf( "%s%s %s auth: %s\n", $priority_auth, $timestamp, $hostname, $message );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- fail2ban needs an atomic append (FILE_APPEND | LOCK_EX) to a plain log file; WP_Filesystem has no append+lock equivalent.
			file_put_contents( $log_files['auth'], $auth_log_entry, FILE_APPEND | LOCK_EX );
		}
	}
}
