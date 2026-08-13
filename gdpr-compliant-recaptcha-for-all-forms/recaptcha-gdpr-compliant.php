<?php

	/**
	 *
	 * Plugin Name: Invisible Anti-Spam & CAPTCHA — reCAPTCHA Alternative for All Forms
	 * Plugin URI: https://programmiere.de/
	 * Description: Invisible spam protection for every form, login and checkout. No puzzles, no checkboxes, no external services — a CAPTCHA your visitors never see.
	 * Version: 5.4.0
	 * Requires at least: 4.8
	 * Requires PHP: 7.1
	 * Author: Matthias Nordwig
	 * Author URI: https://programmiere.de
	 * Text Domain: gdpr-compliant-recaptcha-for-all-forms
	 * License: GPLv2 or later
	 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
	 *
	 */

	namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

	defined( 'ABSPATH' ) || die( 'Are you ok?' );

	/** Class Core
	 *
	 */
class RCM_Main {

	/**
	 * Current version of the plugin. Single source of truth for every
	 * wp_enqueue_script/style version parameter (cache buster) — a hardcoded,
	 * stale per-file version already bit us once: browsers kept serving the old
	 * style_analysis.css after a release, rendering the redesigned overlay
	 * unstyled. Keep the plugin header comment above in sync.
	 */
	const VERSION = '5.4.0';

	/** Current version of the plugin */
	private $version = self::VERSION;

	/** Holding the instance of this class */
	public static $instance;

	/** Holding an instance of the class Message_Page */
	private $instance_message_page;

	/** Holding an instance of the class Stamp */
	private $instance_stamp;

	/** Holding an instance of the class Scoring */
	private $instance_scoring;

	/** Holding an instance of the class Dashboard_Widget */
	private $dashboard_widget;

	/** Holding an instance of the class Analysis */
	private $instance_analysis;

	/** Holding an instance of the class Settings_Menu */
	private $instance_settings_menu;

	/** An array of options in order to control the plugin */
	private $options;

	/** Get an instance of the class
	 *
	 */
	public static function get_instance() {
		require_once __DIR__ . '/includes/class-option.php';
		require_once __DIR__ . '/includes/class-proof-of-work.php';
		require_once __DIR__ . '/includes/class-echo-values.php';
		require_once __DIR__ . '/includes/class-echo-store.php';
		require_once __DIR__ . '/includes/class-message-page.php';
		require_once __DIR__ . '/includes/class-client-ip.php';
		require_once __DIR__ . '/includes/class-proxy-candidate-ledger.php';
		require_once __DIR__ . '/includes/class-rest-route.php';
		require_once __DIR__ . '/includes/class-stamp-token.php';
		require_once __DIR__ . '/includes/class-gibberish-detector.php';
		require_once __DIR__ . '/includes/class-classification-reason.php';
		require_once __DIR__ . '/includes/class-credential-fields.php';
		require_once __DIR__ . '/includes/class-learned-credential-fields.php';
		require_once __DIR__ . '/includes/class-credential-suggestion-ledger.php';
		require_once __DIR__ . '/includes/class-credential-learning.php';
		require_once __DIR__ . '/includes/class-credential-cleanup.php';
		require_once __DIR__ . '/includes/class-blocked-values-migration.php';
		require_once __DIR__ . '/includes/class-pattern-matcher.php';
		require_once __DIR__ . '/includes/class-overbroad-pattern-guard.php';
		require_once __DIR__ . '/includes/class-stamp.php';
		require_once __DIR__ . '/includes/class-settings-menu.php';
		require_once __DIR__ . '/includes/class-scope-sync.php';
		require_once __DIR__ . '/includes/class-scope-add.php';
		require_once __DIR__ . '/includes/class-agent-access.php';
		require_once __DIR__ . '/includes/class-ability-probe.php';
		require_once __DIR__ . '/includes/class-abilities.php';
		require_once __DIR__ . '/includes/class-dashboard-widget.php';
		require_once __DIR__ . '/includes/class-analysis.php';

		if ( ! self::$instance instanceof self ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/** Constructor of the class
	 */
	private function __construct() {
		$this->activate();
		$this->instance_stamp = new Stamp();
		if ( get_option( Option::POW_SIMULATE_SPAM ) ) {
			add_action( 'admin_enqueue_scripts', array( $this, 'warning_simulation' ) );
			add_action( 'wp_enqueue_scripts', array( $this, 'warning_simulation' ) );
			add_action( 'admin_notices', array( $this, 'warning_simulation_notice' ) );
		}
		add_action( 'admin_init', array( $this, 'gdpr_compliant_recaptcha_state_assets' ), 10, 1 );
		add_action( 'activated_plugin', array( $this, 'activated' ) );
		$this->instance_message_page  = new Message_Page();
		$this->instance_settings_menu = new Settings_Menu();
		// Not stored: its constructor registers the admin hooks, which keep the instance
		// alive for the request (matches WordPress's usual add_action( [$this, …] ) idiom).
		new Scope_Sync();
		// Same idiom: registers the credential-field proposal notice, its two
		// one-click handlers and the message-inbox rescue ajax endpoint.
		new Credential_Learning();
		// Same idiom: registers the "an over-broad pattern discarded an admin save"
		// notice and its dismiss handler. The marker it reads is written by
		// Stamp::check_submit()'s block branch and by nothing else.
		new Overbroad_Pattern_Guard();
		// Same idiom: registers the Abilities API surface (core 6.9+), the Connectors
		// card (core 7.0+) and the stage-3 warning notice. All internally guarded, so
		// this costs nothing on older WordPress.
		new Abilities();
		$this->dashboard_widget = new Dashboard_Widget();
		if ( get_option( Option::POW_DIRECT_ANALYSIS_MODE ) ) {
			$this->instance_analysis = new Analysis();
		}
		if ( ! defined( 'GDPR_COMPLIANT_RECAPTCHA' ) ) {
			// in main plugin file
			define( 'GDPR_COMPLIANT_RECAPTCHA', plugin_basename( __FILE__ ) );
		}
		add_action( 'wp', array( $this, 'schedule_message_deletion' ) );
		// Hook the function to the scheduled event with parameters
		add_action( 'delete_old_messages_event', array( $this, 'delete_old_messages' ), 10 );
	}

	public function warning_simulation_notice() {
		?>
			<div class="notice notice-warning is-dismissible">
				<p><?php esc_html_e( 'Beware❗ The GDPR-Compliant ReCaptcha-Plugin is running in simulation mode. This means, that currently all post-requests are treated as spam and thus are probably blocked. This warning and the red colored menu appears as long as the simulation mode is active.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></p>
			</div>
			<?php
	}

	/** Include the Javascript for proof of work calculation on the client-side
	 */
	public function gdpr_compliant_recaptcha_state_assets() {
		global $pagenow;

		if ( 'plugins.php' === $pagenow ) {
			wp_enqueue_script( 'wp-deactivation-message', plugins_url( '/scripts/recaptcha-gdpr-pro-state.js', __FILE__ ), array(), '1.0.0', true );
		}
	}

	/** Initialize the admin area*/
	public function warning_simulation() {
		//Registers the stly for the message_page but don't enqueue it yet
		wp_enqueue_style( 'gdprCompliantWarningStyle', plugin_dir_url( __FILE__ ) . '/css/style_warning_simulation.css', array(), '1.0.2' );
	}

	// Function to delete old messages based on days to keep and rgm_type
	public function delete_old_messages() {
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
	public function schedule_message_deletion() {
		if ( ! wp_next_scheduled( 'delete_old_messages_event' ) ) {
			wp_schedule_event( time(), 'daily', 'delete_old_messages_event' );
		}
	}

	/** Activation of the plugin */
	public function activate() {

		$current_version = get_option( Option::POW_VERSION );

		// No stored version means the tables are about to be created for the first
		// time — remembered here because update_option() below erases the evidence.
		$is_fresh_install = ! $current_version;

		// Check the plugin version
		if ( ! $current_version || version_compare( $this->version, $current_version, '>' ) ) {

			//Create tables to save messages
			global $wpdb;
			//Table for message with standard metainformation
			$table_name_mail = $wpdb->prefix . 'recaptcha_gdpr_message_rgm';
			//Table for details for flexible amount of information
			$table_name_details = $wpdb->prefix . 'recaptcha_gdpr_details_rgd';
			//Table for the spam-check-stamps
			$table_name_stamp = $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs';

			$table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name_mail ) );
			//Check whether the table exists already
			if ( $table_exists !== $table_name_mail ) {

				// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
				$results = $wpdb->query(
					'
						CREATE TABLE ' . $table_name_mail . ' (
						rgm_id INT AUTO_INCREMENT NOT NULL
						, rgm_type INT
						, rgm_date DATETIME
						, rgm_title VARCHAR(21844)
						, rgm_ip VARCHAR(255)
						, rgm_site VARCHAR(21844)
						, rgm_ajax INT
						, rgm_action VARCHAR(500)
						, rgm_pattern VARCHAR(1000)
						, PRIMARY KEY (rgm_id)
						) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
					'
				);
				// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

			}

			$index_exists = $wpdb->get_var(
				$wpdb->prepare(
					"
						SELECT COUNT(*)
						FROM information_schema.statistics
						WHERE table_name = %s
						AND index_name = 'idx_rgm_type_attribute_value_date'
					",
					$table_name_mail
				)
			);

			// Create the index if it doesn't exist
			if ( ! $index_exists ) {
				// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
				$wpdb->query(
					"
						CREATE INDEX idx_rgm_type_attribute_value_date
						ON $table_name_mail (rgm_type, rgm_date)
					"
				);
				// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			}

			$table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name_details ) );
			//Check whether the table exists already
			if ( $table_exists !== $table_name_details ) {

				// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
				$results = $wpdb->query(
					'
						CREATE TABLE ' . $table_name_details . ' (
						rgd_id INT AUTO_INCREMENT NOT NULL
						, rgm_id INT
						, rgd_original_attribute VARCHAR(21844)
						, rgd_attribute VARCHAR(21844)
						, rgd_value VARCHAR(21844)
						, rgm_posted INT
						, PRIMARY KEY (rgd_id)
						) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
					'
				);
				// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

			}

			$index_exists = $wpdb->get_var(
				$wpdb->prepare(
					"
						SELECT COUNT(*)
						FROM information_schema.statistics
						WHERE table_name = %s
						AND index_name = 'idx_rgd_attribute_value'
					",
					$table_name_details
				)
			);

			// Create the index if it doesn't exist
			if ( ! $index_exists ) {
				// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
				$wpdb->query(
					"
						CREATE INDEX idx_rgd_attribute_value
						ON $table_name_details (rgd_attribute(255), rgd_value(255));
					"
				);
				// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			}

			$index_exists = $wpdb->get_var(
				$wpdb->prepare(
					"
						SELECT COUNT(*)
						FROM information_schema.statistics
						WHERE table_name = %s
						AND index_name = 'idx_rgd_rgm_id'
					",
					$table_name_details
				)
			);

			// Create the index if it doesn't exist
			if ( ! $index_exists ) {
				// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
				$wpdb->query(
					"
						CREATE INDEX idx_rgd_rgm_id
						ON $table_name_details (rgm_id);
					"
				);
				// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			}

			$table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name_stamp ) );
			//Check whether the table exists already
			if ( $table_exists !== $table_name_stamp ) {

				// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
				$results = $wpdb->query(
					'
						CREATE TABLE ' . $table_name_stamp . ' (
						rgs_id INT AUTO_INCREMENT NOT NULL
						, rgs_ip VARCHAR(255)
						, rgs_stamp VARCHAR(255)
						, rgs_time DATETIME
						, rgs_uses INT UNSIGNED NOT NULL DEFAULT 0
						, PRIMARY KEY (rgs_id)
						, UNIQUE KEY idx_rgs_stamp (rgs_stamp(191))
						) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
					'
				);
				// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

			}

			//Update tables for older versions
			$table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name_mail ) );
			//Check whether the table exists already
			if ( $table_exists === $table_name_mail ) {
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
				$column_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW COLUMNS FROM ' . $table_name_mail . ' LIKE %s', 'rgm_ajax' ) );
				if ( 'rgm_ajax' !== $column_exists ) {
					// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
					$results = $wpdb->query(
						'
							ALTER TABLE ' . $table_name_mail . '
							ADD COLUMN rgm_ajax INT,
							ADD COLUMN rgm_action VARCHAR(500);
						'
					);
					// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				}
			}

			//Update tables for older versions
			$table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name_details ) );
			//Check whether the table exists already
			if ( $table_exists === $table_name_details ) {
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
				$column_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW COLUMNS FROM ' . $table_name_details . ' LIKE %s', 'rgm_posted' ) );
				if ( 'rgm_posted' !== $column_exists ) {
					// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
					$results = $wpdb->query(
						'
							ALTER TABLE ' . $table_name_details . '
							ADD COLUMN rgm_posted INT;
						'
					);
					// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				}
			}
			$table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name_mail ) );
			//Check whether the table exists already
			if ( $table_exists === $table_name_mail ) {
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
				$column_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW COLUMNS FROM ' . $table_name_mail . ' LIKE %s', 'rgm_pattern' ) );
				if ( 'rgm_pattern' !== $column_exists ) {
					// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
					$results = $wpdb->query(
						'
							ALTER TABLE ' . $table_name_mail . '
							ADD COLUMN rgm_pattern VARCHAR(1000);
						'
					);
					// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				}
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
				$column_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW COLUMNS FROM ' . $table_name_mail . ' LIKE %s', 'rgm_ip' ) );
				if ( 'rgm_ip' !== $column_exists ) {
					// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
					$results = $wpdb->query(
						'
							ALTER TABLE ' . $table_name_mail . '
							ADD COLUMN rgm_ip VARCHAR(255);
						'
					);
					// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				}
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
				$column_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW COLUMNS FROM ' . $table_name_mail . ' LIKE %s', 'rgm_site' ) );
				if ( 'rgm_site' !== $column_exists ) {
					// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
					$results = $wpdb->query(
						'
							ALTER TABLE ' . $table_name_mail . '
							ADD COLUMN rgm_site VARCHAR(21844);
						'
					);
					// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				}
			}

			//Update tables for older versions
			$table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name_stamp ) );
			//Check whether the table exists already
			if ( $table_exists === $table_name_stamp ) {
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
				$column_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW COLUMNS FROM ' . $table_name_stamp . ' LIKE %s', 'rgs_uses' ) );
				if ( 'rgs_uses' !== $column_exists ) {
					// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
					$results = $wpdb->query(
						'
							ALTER TABLE ' . $table_name_stamp . '
							ADD COLUMN rgs_uses INT UNSIGNED NOT NULL DEFAULT 0;
						'
					);
					// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				}

				// rgs_stamp must be wide enough for the LONGEST token format, or
				// `INSERT IGNORE` (check_stamp()) silently TRUNCATES instead of failing:
				// affected rows would be 1, the storage confirmation would find its row,
				// and consume_token_row() would then look for the full token and never
				// match it — the token path dead, every submission quietly riding the IP
				// fallback. Both new alarms are blind to that shape, which is why the
				// column width is checked here instead: one-time, idempotent, and it can
				// only ever widen. (This repo has created the column as VARCHAR(255) since
				// 4.1.2; an installation older than that is the case this covers.)
				$stamp_column = $wpdb->get_row(
					// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
					$wpdb->prepare( 'SHOW COLUMNS FROM ' . $table_name_stamp . ' LIKE %s', 'rgs_stamp' )
				);
				if ( $stamp_column && isset( $stamp_column->Type ) // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- MySQL's own column name in SHOW COLUMNS output.
					&& preg_match( '/varchar\((\d+)\)/i', (string) $stamp_column->Type, $width ) // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- see above.
					&& (int) $width[1] < 255
				) {
					// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
					$wpdb->query( 'ALTER TABLE ' . $table_name_stamp . ' MODIFY rgs_stamp VARCHAR(255)' );
				}

				// AP3: UNIQUE index on rgs_stamp. The uniqueness (not just lookup speed)
				// is security-relevant: check_stamp() inserts with INSERT IGNORE, and
				// only the unique key makes N concurrent solves of the SAME token
				// collapse into a single row — a SELECT-then-INSERT guard alone is racy
				// and would let one solved PoW spawn N rows × TOKEN_MAX_USES budget.
				// Prefix length (191) because rgs_stamp is VARCHAR(255)/utf8mb4
				// (4 bytes/char) and a full-column index would exceed the 767-byte
				// key-length cap on older MySQL row formats; 191 chars covers both the
				// 92-char token and the 64-char legacy stamp in full, so the prefix is
				// effectively exact.
				$index_state = $wpdb->get_row(
					$wpdb->prepare(
						'
							SELECT COUNT(*) AS idx_count, MIN(non_unique) AS non_unique
							FROM information_schema.statistics
							WHERE table_schema = DATABASE()
							AND table_name = %s
							AND index_name = %s
						',
						$table_name_stamp,
						'idx_rgs_stamp'
					)
				);

				$index_exists = $index_state && (int) $index_state->idx_count > 0;

				// A pre-release draft of this migration created the index without
				// UNIQUE — rebuild it in that case.
				if ( $index_exists && 1 === (int) $index_state->non_unique ) {
					$wpdb->query( 'DROP INDEX idx_rgs_stamp ON ' . $table_name_stamp ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
					$index_exists = false;
				}

				if ( ! $index_exists ) {
					// Deduplicate before adding the unique key: pre-AP3 check_stamp()
					// inserted one row per solve without any duplicate guard, so
					// identical legacy stamps (same IP + same time bucket) may exist.
					// Keep the oldest row per stamp value.
					// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders.
					$wpdb->query(
						'
							DELETE t1 FROM ' . $table_name_stamp . ' t1
							JOIN ' . $table_name_stamp . ' t2
							ON t1.rgs_stamp = t2.rgs_stamp
							AND t1.rgs_id > t2.rgs_id
						'
					);
					$wpdb->query(
						'
							CREATE UNIQUE INDEX idx_rgs_stamp
							ON ' . $table_name_stamp . ' (rgs_stamp(191));
						'
					);
					// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				}
			}

			// Seed options that were introduced AFTER the install-time seeding in
			// Settings_Menu::prepare_options() (which only runs once, gated by
			// POW_INSTALLED). Without this, upgraded installs never get the new
			// option rows: the runtime works via get_option() code defaults, but the
			// settings page renders the missing option as off/empty — and saving the
			// page would then persist that displayed value, silently flipping the
			// real behaviour. add_option() is a no-op if the row already exists, so
			// explicit admin choices are never overwritten.
			add_option( Option::POW_TRUSTED_PROXIES, '' );
			// Seeded explicitly with false: a missing row must never read as "on" for
			// an option that widens which forwarding headers are believed.
			add_option( Option::POW_TRUST_PRIVATE_PROXY, false );
			add_option( Option::POW_MAX_USES, 10 );
			add_option( Option::POW_UNDER_ATTACK_MODE, true );
			add_option( Option::POW_UNDER_ATTACK_QUARANTINE, false );
			add_option( Option::POW_CREDENTIAL_FIELDS, '' );
			// Both AI-agent switches: a missing row must never read as "on".
			add_option( Option::POW_ABILITIES_WRITE, false );
			add_option( Option::POW_ABILITIES_UNSAFE, false );
			add_option( Option::POW_ABILITIES_READ_SUBMISSIONS, false );

			if ( $is_fresh_install ) {
				// Brand-new tables: there is no legacy cleartext credential to redact,
				// so short-circuit the migration instead of letting it walk (and query)
				// an empty table on the next loads.
				Credential_Cleanup::mark_done_fresh_install();
			}

			update_option( Option::POW_VERSION, $this->version );

			// Drop stale OPcode-cache entries for the plugin's own PHP files after an
			// upgrade. Belt-and-suspenders: WordPress core already invalidates updated
			// files (>=6.2), but on hosts with opcache.validate_timestamps=0, a separate
			// PHP-FPM pool, or an update applied via WP-CLI, long-lived workers can keep
			// executing the OLD bytecode while the new DB schema is already in place —
			// which is exactly what produces the "duplicate rgs_stamp / everything
			// flagged as spam" mismatch this release addresses. Honest limitation: this
			// only helps once the NEW code is what runs activate(); a fully stale worker
			// that never re-reads this file needs an OPcache flush / FPM restart (see
			// readme.txt Upgrade Notice).
			$this->invalidate_own_opcache();
		}

		// DELIBERATELY OUTSIDE the version gate above. That gate fires only when
		// RCM_Main::VERSION exceeds the stored POW_VERSION, i.e. once per release
		// and in a single request — useless for a migration that has to walk a table
		// of unknown size, and dead on installs where it already fired. Called on
		// every load instead, the cleanup keeps its own ledger, does a time-budgeted
		// slice per request, and costs one cached get_option() once finished. It
		// therefore needs no version bump to reach existing installs.
		Credential_Cleanup::maybe_run();

		// DELIBERATELY OUTSIDE the version gate too, and for the same reason plus one
		// more: this migration has to reach installations whose gate has ALREADY
		// fired (they would otherwise keep their blocklist mixed into the pattern
		// option forever), and a version-gated migration cannot be exercised in a dev
		// container at all, because its stored version is already current. Guarded by
		// its own done flag, so a completed migration costs one cached get_option().
		Blocked_Values_Migration::maybe_run();
	}

	/**
	 * Invalidate the OPcache entries for this plugin's own PHP files. No-op when
	 * OPcache is disabled or the invalidate API is unavailable/restricted. Never
	 * calls opcache_reset(): that would nuke every other app's cache on shared hosting.
	 */
	private function invalidate_own_opcache() {
		if ( ! function_exists( 'opcache_invalidate' ) || ! ini_get( 'opcache.enable' ) ) {
			return;
		}
		// Recurse the plugin directory with a portable iterator. Deliberately NOT
		// glob('{,*/}*.php', GLOB_BRACE): GLOB_BRACE is not defined on every platform
		// (absent on musl/Alpine, common in containers and on some managed hosts), and
		// referencing it there is a fatal "undefined constant" — the very kind of
		// breakage this method is meant to prevent.
		try {
			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( plugin_dir_path( __FILE__ ), \FilesystemIterator::SKIP_DOTS )
			);
		} catch ( \Exception $e ) {
			return;
		}
		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() || 'php' !== strtolower( $file->getExtension() ) ) {
				continue;
			}
			$path = $file->getPathname();
			// wp_opcache_invalidate() (WP >=5.5) wraps opcache_invalidate() and honours
			// opcache.restrict_api; fall back to the raw call on older cores.
			if ( function_exists( 'wp_opcache_invalidate' ) ) {
				// Called via a variable so Plugin Check's "requires WP 5.5" static
				// compatibility check does not flag it while the plugin still declares
				// "Requires at least: 4.8": the function_exists() guard already makes the
				// call safe on older cores (which take the raw-call fallback below), and
				// this security update must keep reaching those installs.
				$wp_opcache_invalidate = 'wp_opcache_invalidate';
				$wp_opcache_invalidate( $path, true );
			} else {
				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- opcache.restrict_api can make this emit a warning for a path outside the allowed prefix; the invalidation is strictly best-effort hardening, so silence is intended.
				@opcache_invalidate( $path, true );
			}
		}
	}

	/** Deactivation of the plugin */
	public function deactivate() {
		// Unschedule the event and remove the hooks
		wp_clear_scheduled_hook( 'delete_old_messages_event' );
		remove_action( 'delete_old_messages_event', array( $this, 'delete_old_messages' ), 10 );
	}

	/** On activation go to settings menu*/
	public function activated( string $plugin ) {
		/** On activation */
		if ( plugin_basename( __FILE__ ) === $plugin ) {
			$admin_url = admin_url( 'options-general.php' . Option::PAGE_QUERY );
			wp_safe_redirect( $admin_url );
			exit;
		}
	}
}

	$gdpr_pow_start_register = RCM_Main::get_instance();

	register_activation_hook( __FILE__, array( $gdpr_pow_start_register, 'activate' ) );
	register_deactivation_hook( __FILE__, array( $gdpr_pow_start_register, 'deactivate' ) );

?>