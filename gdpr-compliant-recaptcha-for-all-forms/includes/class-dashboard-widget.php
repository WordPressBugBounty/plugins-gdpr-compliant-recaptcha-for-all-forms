<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

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
	}
}
