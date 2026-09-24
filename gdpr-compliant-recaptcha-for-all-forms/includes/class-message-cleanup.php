<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/messages.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.

/**
 * Das cron-gesteuerte Aufraeumen alter Nachrichten: taeglich, nach den drei
 * Aufbewahrungsfristen POW_CRON_DELETE_INBOX / _SPAM / _TRASH.
 *
 * REINER UMZUG AUS DER HAUPTDATEI (recaptcha-gdpr-compliant.php), Zeile fuer Zeile
 * uebernommen. Der Block war dort in sich geschlossen — er haengt an keinem Zustand von
 * RCM_Main — und die Hauptdatei stand an ihrem Deckel (scripts/check-file-size.mjs).
 * Ausgelagert statt den Deckel zu heben, wie CLAUDE.md "Dateigroessen" es verlangt.
 *
 * DER HOOK-NAME IST NICHT VERHANDELBAR. Bereits eingeplante Cron-Events auf bestehenden
 * Installationen zeigen auf 'delete_old_messages_event'; wer ihn umbenennt, stellt das
 * Aufraeumen auf jeder dieser Installationen STILL ein — kein Fehler, keine Meldung, die
 * Tabelle waechst einfach weiter. Der Callback darf umziehen, der Name nicht.
 *
 * Typ 4 ("Analyse") ist hier bewusst nicht dabei: den raeumt
 * Analysis::restore_analysis_entries() opportunistisch mit auf (handbuch/messages.md).
 */
class Message_Cleanup {

	/** Constructor: registers the daily schedule and the event's callback. */
	public function __construct() {
		add_action( 'wp', array( $this, 'schedule_message_deletion' ) );
		// Hook the function to the scheduled event with parameters
		add_action( 'delete_old_messages_event', array( $this, 'delete_old_messages' ), 10 );
	}

	// Function to delete old messages based on days to keep and rgm_type
	public function delete_old_messages(): void {
		global $wpdb;
		$days_to_keep[0] = 0;
		$days_to_keep[1] = get_option( Option::POW_CRON_DELETE_INBOX );
		$days_to_keep[2] = get_option( Option::POW_CRON_DELETE_SPAM );
		$days_to_keep[3] = get_option( Option::POW_CRON_DELETE_TRASH );

		foreach ( $days_to_keep as $key => $value ) {
			if ( $value ) {
				global $wpdb;
				$rgm_type = $key;
				$days     = $days_to_keep[ $key ];
				// Calculate the date threshold (older than X days).
				//
				// The threshold has to be built from current_time(), because that is the
				// clock rgm_date was WRITTEN with (current_time('mysql'), i.e. the site's
				// local time). Computing it from UTC instead — as this line did — put the
				// cutoff off by the site's UTC offset, so messages were kept a few hours
				// too long or deleted a few hours too early. Same defect class as the
				// stamp-row one (HANDBUCH.md §12 cause 8), a milder dose: the reader has
				// to use the writer's clock. Note that no assertion catches this half of
				// the rule — see tests/unit/OneClockTest.php.
				$threshold_date = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - $days * DAY_IN_SECONDS ); // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested -- intentional: matches current_time('mysql')-written rgm_date, see comment above

				// Define the table names
				$message_table = $wpdb->prefix . 'recaptcha_gdpr_message_rgm';
				$details_table = $wpdb->prefix . 'recaptcha_gdpr_details_rgd';

				// Get message IDs based on the WHERE condition
				$message_ids = $wpdb->get_col(
					$wpdb->prepare(
						"SELECT rgm_id FROM $message_table WHERE rgm_date < %s AND rgm_type = %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input.
						$threshold_date,
						$rgm_type
					)
				);

				if ( ! empty( $message_ids ) ) {
					// Build an IN(...) placeholder list matching the number of IDs found.
					$id_placeholders = implode( ',', array_fill( 0, count( $message_ids ), '%d' ) );

					// Delete related details from the details table
					$wpdb->query(
						$wpdb->prepare(
							"DELETE FROM $details_table WHERE rgm_id IN ($id_placeholders)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- table name from $wpdb->prefix, not user input; $id_placeholders is a dynamically built '%d' list matching count($message_ids), spread as prepare() args below.
							...$message_ids
						)
					);

					// Delete old messages from the main message table
					$wpdb->query(
						$wpdb->prepare(
							"DELETE FROM $message_table WHERE rgm_id IN ($id_placeholders)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- table name from $wpdb->prefix, not user input; $id_placeholders is a dynamically built '%d' list matching count($message_ids), spread as prepare() args below.
							...$message_ids
						)
					);
				}
			}
		}
	}

	// Schedule the function to check for messages that shall be deleted
	public function schedule_message_deletion(): void {
		if ( ! wp_next_scheduled( 'delete_old_messages_event' ) ) {
			wp_schedule_event( time(), 'daily', 'delete_old_messages_event' );
		}
	}

	/** Deactivation: unschedule the event and remove the hooks.
	 *
	 * Moved here together with the registration above, so that both ends of the hook
	 * live in one file — the removal needs THIS instance, since that is what the
	 * add_action() in the constructor registered.
	 */
	public function deactivate(): void {
		// Unschedule the event and remove the hooks
		wp_clear_scheduled_hook( 'delete_old_messages_event' );
		remove_action( 'delete_old_messages_event', array( $this, 'delete_old_messages' ), 10 );
	}
}
