<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Class Analysis: Direct-analysis mode — injects a live front-end overlay (for admins,
 * when POW_DIRECT_ANALYSIS_MODE is on) to capture unrecognized forms and add
 * patterns/actions directly, plus the store/restore Ajax endpoints behind it.
 */

class Analysis {

	/** Nonce action for the direct-analysis endpoints (one nonce covers all three:
	 *  store, restore, save_pattern_frontend — see gdprAnalysis.storeNonce in
	 *  add_javascript()).
	 */
	const STORE_NONCE_ACTION = 'gdpr_analysis_store';

	/** Hard cap on the JSON payload accepted by store_analysis_entry(), in bytes.
	 *  Bounded by the `rgd_value VARCHAR(21844)` column width (see
	 *  recaptcha-gdpr-compliant.php activate()), not just abuse-prevention — a payload
	 *  longer than the column would otherwise get silently truncated (or rejected under
	 *  STRICT_TRANS_TABLES) by MySQL. Kept comfortably below 21844 characters.
	 */
	const MAX_PAYLOAD_BYTES = 20000;

	/** Constructor of the class
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'run' ) );
	}

	/** When the plugin is running
	 */
	public function run() {
		if ( get_option( Option::POW_DIRECT_ANALYSIS_MODE ) && current_user_can( 'manage_options' ) ) {
			add_action( 'wp_ajax_get_patterns', array( $this, 'get_patterns' ) );
			$ajax = defined( 'DOING_AJAX' ) && DOING_AJAX;
			if ( ! $ajax ) {
				add_action( 'wp_enqueue_scripts', array( $this, 'add_javascript' ), PHP_INT_MAX );
			}
			add_action( 'wp_enqueue_scripts', array( $this, 'include_ressources' ) );
			add_action( 'wp_ajax_save_pattern_frontend', array( $this, 'save_pattern_callback' ) );
			add_action( 'wp_ajax_gdpr_analysis_store', array( $this, 'store_analysis_entry' ) );
			add_action( 'wp_ajax_gdpr_analysis_restore', array( $this, 'restore_analysis_entries' ) );
		}
	}

	/** Function to get rssource to the frontend */
	public function include_ressources() {
		wp_enqueue_style( 'gdpr-compliant-style-analysis', plugins_url( '/css/style_analysis.css', __DIR__ ), array(), RCM_Main::VERSION );
	}

	/** Function to get the patterns to apply the spam check to the frontend
	 *
	 */
	public function get_patterns() {

		$existing_pattern       = get_option( Option::POW_PARAMETER_PATTERN );
		$existing_lines_pattern = null;
		$existing_action        = get_option( Option::POW_EXPLICIT_ACTION );
		$existing_lines_action  = null;
		if ( $existing_pattern ) {
			$existing_lines_pattern = preg_split( "/\r\n|\n|\r/", $existing_pattern, -1, PREG_SPLIT_NO_EMPTY );
		}
		if ( $existing_action ) {
			$existing_lines_action = preg_split( '/\r\n|\n|\r/', $existing_action, -1, PREG_SPLIT_NO_EMPTY );
		}

		$array_result = array(
			'patterns' => $existing_lines_pattern,
			'actions'  => $existing_lines_action,
		);

		// Make your array as json
		wp_send_json( $array_result );

		// Don't forget to stop execution afterward.
		wp_die();
	}

	/** Save Pattern or Ajax-Action
	 *
	 * CSRF-guarded like store_analysis_entry()/restore_analysis_entries(): one shared
	 * nonce (STORE_NONCE_ACTION, sent by the overlay JS as _ajax_nonce) covers all
	 * three direct-analysis endpoints. The capability check mirrors the hook-time
	 * gate in run() — defense in depth, and the nonce alone is not an authz check.
	 */
	public function save_pattern_callback() {
		if ( ! current_user_can( 'manage_options' ) || ! check_ajax_referer( self::STORE_NONCE_ACTION, '_ajax_nonce', false ) ) {
			wp_send_json_error(
				array(
					'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				)
			);
		}

		// Get whitelisting parameters
		$pattern  = stripslashes( sanitize_text_field( $_POST['key'] ) );
		$standard = filter_var( $_POST['standard'], FILTER_VALIDATE_BOOLEAN );

		$existing_option = null;
		if ( $standard ) {
			$existing_option = get_option( Option::POW_EXPLICIT_ACTION );
		} else {
			$existing_option = get_option( Option::POW_PARAMETER_PATTERN );
		}
		$existing_lines = preg_split( "/\r\n|\n|\r/", $existing_option );

		// Check, whether the whitelisting-parameter already exists
		if ( ! in_array( $pattern, $existing_lines, true ) ) {
			// If not add the new parameter
			$existing_lines[] = $pattern;

			// Transform to String again
			$updated_option = implode( "\n", $existing_lines );

			// Save the option
			if ( $standard ) {
				update_option( Option::POW_EXPLICIT_ACTION, $updated_option );
				$property = __( 'Apply on actions', 'gdpr-compliant-recaptcha-for-all-forms' );
			} else {
				update_option( Option::POW_PARAMETER_PATTERN, $updated_option );
				$property = __( 'Apply on pattern', 'gdpr-compliant-recaptcha-for-all-forms' );
			}

			/* translators: %s is the settings-page property name ("Apply on actions" or "Apply on pattern") the entry was saved under. */
			wp_send_json_success( array( 'message' => sprintf( __( 'Submission type added successfully. You can find and change it on the plugins settings page under the tab "Scope", in the property "%s".', 'gdpr-compliant-recaptcha-for-all-forms' ), $property ) ) );
		} else {
			// Pattern already in place
			wp_send_json_error( array( 'error_message' => __( 'Submission type already exists.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		exit;
	}

	public function add_javascript() {
		wp_enqueue_script(
			'gdpr-recaptcha-analysis',
			plugins_url( '/scripts/recaptcha-gdpr-analysis.js', __DIR__ ),
			array(),
			RCM_Main::VERSION,
			true
		);
		wp_localize_script(
			'gdpr-recaptcha-analysis',
			'gdprAnalysis',
			array(
				'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
				'storeNonce' => wp_create_nonce( self::STORE_NONCE_ACTION ),
				'i18n'       => array(
					'chooseAttributes'      => __( 'Please choose the message attributes which you want to save as pattern!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'loading'               => __( 'Loading...', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'initiating'            => __( 'Initiating analysis. Please wait...', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'choosePattern'         => __( 'Choose for pattern', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'key'                   => __( 'key', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'value'                 => __( 'value', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'saveAction'            => __( 'Save action', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'savePattern'           => __( 'Save pattern', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'techFields'            => __( 'Technical fields & good candidates for patterns are marked red', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'covered'               => __( 'Covered', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'notCovered'            => __( 'Not covered', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'submission'            => __( 'submission', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'ajax'                  => __( 'ajax', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'windowTitle'           => __( 'Direct analysis', 'gdpr-compliant-recaptcha-for-all-forms' ),
					// Guide strip (#gdpr-guide-bar state machine, see setGuideState() in
					// recaptcha-gdpr-analysis.js) — persistent status row inside the
					// analysis window, replaces the old showInfo/showSuccess/showAlert
					// popups.
					'guideArmedTitle'       => __( 'Analysis is watching', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'guideArmedSubtitle'    => __( 'Submit any form on this page to capture it.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					/* translators: %d is replaced client-side with the number of restored entries. */
					'guideRestoredSubtitle' => __( 'Restored %d earlier capture(s) — entries stay available for 30 minutes.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					/* translators: %s is replaced client-side with the captured entry's name. */
					'guideCapturedTitle'    => __( '"%s" captured', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'guideCapturedSubtitle' => __( 'Not covered by the spam check yet.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'guideReviewEntry'      => __( 'Review entry', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'guidePatternSaved'     => __( 'Pattern saved', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'guideActionSaved'      => __( 'Action saved', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'guideSavedSubtitle'    => __( 'This submission type is now covered.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'guideHintPattern'      => __( 'Select the attributes that identify this form, then click Save pattern.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'guideHintAction'       => __( 'Click Save action to add this submission type to the spam check.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				),
			)
		);
	}

	/** Ajax callback: persist (or refresh) one direct-analysis overlay entry server-side.
	 *
	 * Split into this data-returning method + a thin wp_send_json() wrapper
	 * (store_analysis_entry()) so it stays testable via `wp eval` without needing to
	 * intercept wp_die() (wp_send_json_success()/_error() always terminate the request).
	 *
	 * Why server-side at all: the direct-analysis overlay (recaptcha-gdpr-analysis.js)
	 * used to smuggle captured submissions through the form's `action` URL
	 * (`?recaptcha_analysis_data=...`), which breaks on POST-Redirect-GET, on forms
	 * without an `action` attribute, and violates the "no client-side/URL state"
	 * constraint. Entries are now stored as ordinary Typ-4 ("Analyse") messages instead
	 * of a schema change: one `rgm` row (rgm_type=4, rgm_action='direct_analysis',
	 * rgm_title=<entry name>) plus two `rgd` detail rows holding the raw JSON payload
	 * and the capturing admin's user ID.
	 *
	 * @return array{success:bool,id?:int,error_message?:string}
	 */
	public function store_analysis_entry_data() {
		if ( ! current_user_can( 'manage_options' ) || ! check_ajax_referer( self::STORE_NONCE_ACTION, '_ajax_nonce', false ) ) {
			return array(
				'success'       => false,
				'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		$payload_raw = isset( $_POST['payload'] ) && is_string( $_POST['payload'] ) ? wp_unslash( $_POST['payload'] ) : '';
		if ( '' === $payload_raw || strlen( $payload_raw ) > self::MAX_PAYLOAD_BYTES ) {
			return array(
				'success'       => false,
				'error_message' => __( 'Invalid payload.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		$decoded = json_decode( $payload_raw, true );
		if ( ! is_array( $decoded ) ) {
			return array(
				'success'       => false,
				'error_message' => __( 'Invalid payload.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		$name    = ( isset( $decoded['name'] ) && is_string( $decoded['name'] ) && '' !== $decoded['name'] )
			? sanitize_text_field( substr( $decoded['name'], 0, 255 ) )
			: 'unknown';
		$user_id = get_current_user_id();

		global $wpdb;
		$rgm_table = $wpdb->prefix . 'recaptcha_gdpr_message_rgm';
		$rgd_table = $wpdb->prefix . 'recaptcha_gdpr_details_rgd';

		// Dedup: the same admin re-submitting/re-triggering the same submission type
		// within 30 minutes updates the existing row instead of flooding rgm with a new
		// one per test run.
		// current_time('timestamp') (WP timezone), NOT time()/date() (PHP runs on UTC
		// inside WordPress): rgm_date is written via current_time('mysql'), so the
		// threshold must live in the same timezone or sites west of UTC would see
		// fresh entries as already expired.
		$threshold = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - 30 * MINUTE_IN_SECONDS ); // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested -- intentional: matches current_time('mysql')-written rgm_date, see comment above
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table names from $wpdb->prefix, not user input; values below go through $wpdb->prepare()
		$existing_rgm_id = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT rgm.rgm_id FROM $rgm_table rgm
				 INNER JOIN $rgd_table rgd ON rgd.rgm_id = rgm.rgm_id
				 WHERE rgm.rgm_type = 4
				   AND rgm.rgm_action = 'direct_analysis'
				   AND rgm.rgm_title = %s
				   AND rgm.rgm_date >= %s
				   AND rgd.rgd_attribute = '_gdpr_analysis_user'
				   AND rgd.rgd_value = %s
				 ORDER BY rgm.rgm_id DESC
				 LIMIT 1",
				$name,
				$threshold,
				(string) $user_id
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		if ( $existing_rgm_id ) {
			$wpdb->update(
				$rgd_table,
				array( 'rgd_value' => $payload_raw ),
				array(
					'rgm_id'        => (int) $existing_rgm_id,
					'rgd_attribute' => '_gdpr_analysis_payload',
				),
				array( '%s' ),
				array( '%d', '%s' )
			);
			return array(
				'success' => true,
				'id'      => (int) $existing_rgm_id,
			);
		}

		// IP resolution mirrors Stamp::get_client_ip() (private there — this duplicates
		// the same Forwarded-header/trusted-proxy pattern rather than widening that
		// method's visibility for a single extra caller).
		$forwarded_headers = array();
		foreach ( array( 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED' ) as $header_name ) {
			$value = isset( $_SERVER[ $header_name ] ) ? $_SERVER[ $header_name ] : getenv( $header_name );
			if ( is_string( $value ) && '' !== $value ) {
				$forwarded_headers[ $header_name ] = $value;
			}
		}
		$remote_addr     = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : (string) getenv( 'REMOTE_ADDR' );
		$trusted_proxies = preg_split( '/\r\n|\n|\r/', (string) get_option( Option::POW_TRUSTED_PROXIES ), -1, PREG_SPLIT_NO_EMPTY );
		$client_ip       = ClientIp::resolve( $remote_addr, $forwarded_headers, $trusted_proxies );

		$posted_site = null;
		if ( array_key_exists( 'REQUEST_URI', $_SERVER ) && array_key_exists( 'HTTP_HOST', $_SERVER ) ) {
			$posted_site = $_SERVER['HTTP_HOST'] . preg_replace( '/^(https?:\/\/)/i', '', $_SERVER['REQUEST_URI'] );
		}

		$wpdb->insert(
			$rgm_table,
			array(
				'rgm_type'   => 4,
				'rgm_date'   => current_time( 'mysql' ),
				'rgm_title'  => $name,
				'rgm_ip'     => hash( 'sha256', $client_ip ),
				'rgm_site'   => $posted_site,
				'rgm_ajax'   => ! empty( $decoded['ajax'] ) ? 1 : 0,
				'rgm_action' => 'direct_analysis',
			),
			array( '%d', '%s', '%s', '%s', '%s', '%d', '%s' )
		);
		$rgm_id = $wpdb->insert_id;

		$wpdb->insert(
			$rgd_table,
			array(
				'rgm_id'        => $rgm_id,
				'rgd_attribute' => '_gdpr_analysis_payload',
				'rgd_value'     => $payload_raw,
				'rgm_posted'    => 0,
			),
			array( '%d', '%s', '%s', '%d' )
		);
		$wpdb->insert(
			$rgd_table,
			array(
				'rgm_id'        => $rgm_id,
				'rgd_attribute' => '_gdpr_analysis_user',
				'rgd_value'     => (string) $user_id,
				'rgm_posted'    => 0,
			),
			array( '%d', '%s', '%s', '%d' )
		);

		return array(
			'success' => true,
			'id'      => (int) $rgm_id,
		);
	}

	/** Ajax wrapper around store_analysis_entry_data() — see that method for the logic. */
	public function store_analysis_entry() {
		$result = $this->store_analysis_entry_data();
		if ( $result['success'] ) {
			wp_send_json_success( array( 'id' => $result['id'] ) );
		} else {
			wp_send_json_error( array( 'error_message' => $result['error_message'] ) );
		}
	}

	/** Ajax callback: return every direct-analysis entry captured by the current admin
	 * in the last 30 minutes, so the overlay (recaptcha-gdpr-analysis.js) can rehydrate
	 * itself after a page navigation instead of losing captured submissions.
	 *
	 * Also opportunistically purges direct_analysis rows older than 24h first.
	 * RCM_Main::delete_old_messages() (recaptcha-gdpr-compliant.php) only iterates
	 * rgm_type 1-3 (Inbox/Spam/Trash) — Typ 4 ("Analyse") has no cron coverage at all,
	 * so without this the direct-analysis rows would accumulate forever. This callback
	 * doubles as that missing cleanup.
	 *
	 * Split into this data-returning method + a thin wp_send_json() wrapper
	 * (restore_analysis_entries()) for the same testability reason as
	 * store_analysis_entry_data().
	 *
	 * @return array{success:bool,entries?:array<int,array{id:int,payload:mixed}>,error_message?:string}
	 */
	public function restore_analysis_entries_data() {
		if ( ! current_user_can( 'manage_options' ) || ! check_ajax_referer( self::STORE_NONCE_ACTION, '_ajax_nonce', false ) ) {
			return array(
				'success'       => false,
				'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		global $wpdb;
		$rgm_table = $wpdb->prefix . 'recaptcha_gdpr_message_rgm';
		$rgd_table = $wpdb->prefix . 'recaptcha_gdpr_details_rgd';

		// Opportunistic self-cleanup — see docblock above for why this callback owns it.
		// Same timezone rule as in store_analysis_entry_data(): thresholds must match
		// current_time('mysql')-written rgm_date values.
		$stale_threshold = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - DAY_IN_SECONDS ); // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested -- intentional: matches current_time('mysql')-written rgm_date, see comment above
		$stale_ids       = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT rgm_id FROM $rgm_table WHERE rgm_type = 4 AND rgm_action = 'direct_analysis' AND rgm_date < %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
				$stale_threshold
			)
		);
		if ( ! empty( $stale_ids ) ) {
			$stale_ids_str = implode( ',', array_map( 'intval', $stale_ids ) );
			$wpdb->query( "DELETE FROM $rgd_table WHERE rgm_id IN ($stale_ids_str)" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; $stale_ids_str is an intval()-mapped list, not raw user input
			$wpdb->query( "DELETE FROM $rgm_table WHERE rgm_id IN ($stale_ids_str)" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; $stale_ids_str is an intval()-mapped list, not raw user input
		}

		$user_id   = get_current_user_id();
		$threshold = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - 30 * MINUTE_IN_SECONDS ); // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested -- intentional: matches current_time('mysql')-written rgm_date, see comment above
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table names from $wpdb->prefix, not user input; values below go through $wpdb->prepare()
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT rgm.rgm_id, rgd_payload.rgd_value AS payload
				 FROM $rgm_table rgm
				 INNER JOIN $rgd_table rgd_user ON rgd_user.rgm_id = rgm.rgm_id AND rgd_user.rgd_attribute = '_gdpr_analysis_user'
				 INNER JOIN $rgd_table rgd_payload ON rgd_payload.rgm_id = rgm.rgm_id AND rgd_payload.rgd_attribute = '_gdpr_analysis_payload'
				 WHERE rgm.rgm_type = 4
				   AND rgm.rgm_action = 'direct_analysis'
				   AND rgm.rgm_date >= %s
				   AND rgd_user.rgd_value = %s
				 ORDER BY rgm.rgm_id ASC
				 LIMIT 50",
				$threshold,
				(string) $user_id
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		$entries = array();
		foreach ( $rows as $row ) {
			$decoded = json_decode( $row->payload, true );
			if ( is_array( $decoded ) ) {
				$entries[] = array(
					'id'      => (int) $row->rgm_id,
					'payload' => $decoded,
				);
			}
		}

		return array(
			'success' => true,
			'entries' => $entries,
		);
	}

	/** Ajax wrapper around restore_analysis_entries_data() — see that method for the logic. */
	public function restore_analysis_entries() {
		$result = $this->restore_analysis_entries_data();
		if ( $result['success'] ) {
			wp_send_json_success( array( 'entries' => $result['entries'] ) );
		} else {
			wp_send_json_error( array( 'error_message' => $result['error_message'] ) );
		}
	}
}
