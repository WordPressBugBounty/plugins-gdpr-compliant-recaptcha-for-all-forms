<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Class Dashboard_Widget: Reflects the module for adding a widget to the WP-Dashboard
 */

class Dashboard_Widget {

	/** Constructor of the class
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'run' ) );
	}

	/** When the plugin is running
	 */
	public function run() {
		if ( get_option( Option::POW_DASHBOARD ) && current_user_can( 'manage_options' ) ) {
			add_action( 'wp_dashboard_setup', array( $this, 'add_gdpr_compliant_widget' ) );
		}
	}

	/** Add the widget */
	public function add_gdpr_compliant_widget() {
		wp_add_dashboard_widget(
			'ReCaptcha_GDPR_Messages',     // Widget ID
			__( 'ReCaptcha GDPR Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),     // Widget title
			array( $this, 'render_widget_content' )      // Callback function to display content
		);
	}


	public function render_widget_content() {

		// Simulated data for each folder with links
		$folders = array(
			__( 'Messages', 'gdpr-compliant-recaptcha-for-all-forms' ) => array(
				'count'       => Option::get_rows( '', 1 ),
				'count_today' => Option::get_rows( '', 1, true ),
				'link'        => admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES,
			),
			__( 'Spam', 'gdpr-compliant-recaptcha-for-all-forms' ) => array(
				'count'       => Option::get_rows( '', 2 ),
				'count_today' => Option::get_rows( '', 2, true ),
				'link'        => admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_SPAM,
			),
			__( 'Trash', 'gdpr-compliant-recaptcha-for-all-forms' ) => array(
				'count'       => Option::get_rows( '', 3 ),
				'count_today' => Option::get_rows( '', 3, true ),
				'link'        => admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_TRASH,
			),
		);

		echo '<table class="wp-list-table widefat fixed striped" style="border: none;">';
		echo '<thead><tr class="wp-list-table thead"><th class="column-title" style="font-weight: bold;">'
					. esc_html__( 'Folder', 'gdpr-compliant-recaptcha-for-all-forms' )
				. '</th><th class="column-title" style="font-weight: bold;">'
					. esc_html__( 'Entries today', 'gdpr-compliant-recaptcha-for-all-forms' )
				. '</th><th class="column-title" style="font-weight: bold;">'
					. esc_html__( 'Entries in total', 'gdpr-compliant-recaptcha-for-all-forms' )
				. '</th></tr></thead>';
		echo '<tbody>';

		foreach ( $folders as $folder => $data ) {
			echo '<tr>';
			echo '<td><a href="' . esc_url( $data['link'] ) . '">' . esc_html( $folder ) . '</a></td>';
			echo '<td>' . esc_html( $data['count_today'] ) . '</td>';
			echo '<td>' . esc_html( $data['count'] ) . '</td>';
			echo '</tr>';
		}

		echo '</tbody></table>';

		// Health counter: submissions whose classification reason was "no usable stamp
		// row" (no_pow:*) in the last 24h — the fingerprint of a broken client-PoW
		// pipeline (HANDBUCH §12). Amber above the threshold, same colours as
		// .gdpr-status-amber on the settings page (this widget has no stylesheet).
		$no_pow_count  = Option::no_pow_health_count();
		$no_pow_status = Option::health_counter_status( $no_pow_count, Option::HEALTH_NO_POW_WARN_THRESHOLD );
		$no_pow_style  = $no_pow_status['warn']
			? 'display: inline-block; margin-top: 8px; padding: 2px 8px; border-radius: 999px; font-weight: 600; background: #fdf3e1; color: #8a5a00;'
			: 'display: inline-block; margin-top: 8px; padding: 2px 8px; border-radius: 999px; font-weight: 600; background: #f2f2f2; color: #666;';

		echo '<p><span style="' . esc_attr( $no_pow_style ) . '">'
			. esc_html(
				sprintf(
					/* translators: %d: number of submissions in the last 24 hours that had no usable proof-of-work stamp */
					_n( '%d submission without a stamp row (24h)', '%d submissions without a stamp row (24h)', $no_pow_count, 'gdpr-compliant-recaptcha-for-all-forms' ),
					$no_pow_count
				)
			)
			. '</span></p>';

		// Address-change measurement (see Stamp::record_fp_status()): share of solved
		// puzzles redeemed from a different IP than they were issued to. Pure diagnosis —
		// nothing is blocked because of it — so it stays visually neutral (no amber) and
		// is hidden until something has actually been measured.
		$fp_share = Option::fp_mismatch_share(
			get_option( Option::POW_FP_MATCHED_TOTAL, 0 ),
			get_option( Option::POW_FP_MISMATCHED_TOTAL, 0 )
		);
		if ( $fp_share['total'] > 0 ) {
			echo '<p><span style="display: inline-block; padding: 2px 8px; border-radius: 999px; font-weight: 600; background: #f2f2f2; color: #666;">'
				. esc_html(
					sprintf(
						/* translators: %d: percentage of solved puzzles redeemed from a different IP address than they were issued to */
						__( '%d%% of solved puzzles came from another IP than issued', 'gdpr-compliant-recaptcha-for-all-forms' ),
						$fp_share['percent']
					)
				)
				. '</span></p>';
		}
	}
}
