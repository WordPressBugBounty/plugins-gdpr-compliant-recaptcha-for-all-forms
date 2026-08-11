<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Class Option: Each instance of that class is intended to hold an option for the plugin
 *
 */
class Option {

	/** @var string */
	const PREFIX = 'gdpr_pow_';

	/** @var int */
	const INT = 1;

	/** @var int */
	const STRING = 2;

	/** @var int */
	const BOOL = 3;

	/** @var int */
	const TEXT = 4;

	/** @var int */
	const ROLE_DROPDOWN = 5;

	/** @var string */
	const PAGE_QUERY = '?page=' . self::PREFIX . 'options';

	/** @var string */
	const PAGE_QUERY_MESSAGES = '?page=' . self::PREFIX . 'messages';

	/** @var string */
	const PAGE_QUERY_SPAM = '?page=' . self::PREFIX . 'spam';

	/** @var string */
	const PAGE_QUERY_TRASH = '?page=' . self::PREFIX . 'trash';

	/** @var string */
	const PAGE_QUERY_ANALYSIS = '?page=' . self::PREFIX . 'analyse';

	/** @var boolean */
	const POW_OPTIONS = self::PREFIX . 'pow_options';

	/** @var boolean */
	const POW_INSTALLED = self::PREFIX . 'pow_installed';

	/** @var String */
	const POW_VERSION = self::PREFIX . 'pow_version';

	/** @var string */
	const POW_SALT = self::PREFIX . 'pow_salt';

	/** @var string */
	const POW_DIFFICULTY = self::PREFIX . 'pow_difficulty';

	/** @var string */
	const POW_TIME_WINDOW = self::PREFIX . 'pow_time_window';

	/** @var string */
	const POW_MAX_USES = self::PREFIX . 'pow_max_uses';

	/** @var string */
	const POW_UNDER_ATTACK_MODE = self::PREFIX . 'pow_under_attack_mode';

	/** @var string */
	const POW_UNDER_ATTACK_QUARANTINE = self::PREFIX . 'pow_under_attack_quarantine';

	/** @var string */
	const POW_ECHO_LOCK_ENABLED = self::PREFIX . 'pow_echo_lock_enabled';

	/**
	 * Stage 2 of the Abilities API surface: let an AI agent EXTEND the monitored
	 * scope. Off by default and deliberately its own switch — a write path into the
	 * security boundary must never appear through an update.
	 *
	 * @var string
	 */
	const POW_ABILITIES_WRITE = self::PREFIX . 'pow_abilities_write';

	/**
	 * Stage 3: let an AI agent read stored submissions and change protection
	 * settings. Off by default, does NOT follow from POW_ABILITIES_WRITE, and
	 * carries a permanent admin notice while on.
	 *
	 * @var string
	 */
	const POW_ABILITIES_UNSAFE = self::PREFIX . 'pow_abilities_unsafe';

	/**
	 * Audit trail of scope changes made through an ability. Bookkeeping, not a
	 * setting: not in prepare_options(), autoload=no. A short-lived transient (the
	 * Scope_Sync notice pattern) would be useless here — an agent writes while the
	 * admin is by definition not at the screen.
	 *
	 * @var string
	 */
	const POW_ABILITIES_LOG = self::PREFIX . 'pow_abilities_log';

	/** @var bool */
	const POW_BLOCK_LOGIN = self::PREFIX . 'pow_block_login';

	/** @var bool */
	const POW_BLOCK = self::PREFIX . 'pow_block';

	/** @var bool */
	const POW_SAVE_SPAM = self::PREFIX . 'pow_save_spam';

	/** @var bool */
	const POW_SAVE_CLEAN = self::PREFIX . 'pow_save_clean';

	/** @var bool */
	const POW_FLAG_SPAM = self::PREFIX . 'pow_flag_spam';

	/** @var bool */
	const POW_FLAG_SAVE = self::PREFIX . 'pow_flag_save';

	/** @var string */
	const POW_FLAG_SUFFIXES = self::PREFIX . 'pow_flag_suffixes';

	/** @var string */
	const POW_FLAG_TAGS = self::PREFIX . 'pow_flag_tags';

	/** @var bool */
	const POW_SIMULATE_SPAM = self::PREFIX . 'pow_simulate_spam';

	/** @var string */
	const POW_MESSAGE_HEADS = self::PREFIX . 'pow_message_heads';

	/** @var int */
	const POW_MENU_POSITION = self::PREFIX . 'pow_menu_position';

	/** @var bool */
	const POW_DASHBOARD = self::PREFIX . 'pow_dashboard';

	/** @var string */
	const POW_IP_WHITELIST = self::PREFIX . 'pow_ip_whitelist';

	/** @var string */
	const POW_SITE_WHITELIST = self::PREFIX . 'pow_site_whitelist';

	/** @var string */
	const POW_TRUSTED_PROXIES = self::PREFIX . 'pow_trusted_proxies';

	/** @var bool */
	const POW_SAVE_CART = self::PREFIX . 'pow_save_cart';

	/** @var string */
	const POW_EXPLICIT_ACTION = self::PREFIX . 'pow_explicit_action';

	/** @var int */
	const POW_CRON_DELETE_INBOX = self::PREFIX . 'pow_cron_delete_inbox';

	/** @var int */
	const POW_CRON_DELETE_SPAM = self::PREFIX . 'pow_cron_delete_spam';

	/** @var int */
	const POW_CRON_DELETE_TRASH = self::PREFIX . 'pow_cron_delete_trash';

	/** @var Text */
	const POW_ERROR_MESSAGE = self::PREFIX . 'pow_error_message';

	/** @var Bool */
	const POW_ANALYSIS_MODE = self::PREFIX . 'pow_analysis_mode';

	/** @var Bool */
	const POW_DIRECT_ANALYSIS_MODE = self::PREFIX . 'pow_direct_analysis_mode';

	/** @var Text */
	const POW_PARAMETER_PATTERN = self::PREFIX . 'pow_parameter_pattern';

	/**
	 * Third signature class alongside actions/patterns (REST_ROUTES_PLAN.md AP3):
	 * one REST route/namespace per line, matched against the route
	 * `RestRoute::extract()` reads off a POST (see Stamp::check_rest_routes()).
	 * Segment wildcard `*` and namespace-suffix wildcard `/*` supported, see
	 * class-rest-route.php.
	 *
	 * @var string
	 */
	const POW_REST_ROUTES = self::PREFIX . 'pow_rest_routes';

	/**
	 * Ledger of default explicit-actions/patterns already OFFERED to the scope
	 * (Scope_Sync). Not user-facing; tracks which builder defaults have been seen so
	 * a newly-activated builder's action is added once, while an admin-removed entry
	 * is never re-added. See class-scope-sync.php.
	 *
	 * @var string
	 */
	const POW_SEEDED_ACTIONS = self::PREFIX . 'pow_seeded_actions';

	/** @var string */
	const POW_SEEDED_PATTERNS = self::PREFIX . 'pow_seeded_patterns';

	/**
	 * Ledger of default REST routes already OFFERED to POW_REST_ROUTES
	 * (Scope_Sync's third domain, REST_ROUTES_PLAN.md AP4). Same semantics as
	 * POW_SEEDED_ACTIONS/POW_SEEDED_PATTERNS above.
	 *
	 * @var string
	 */
	const POW_SEEDED_ROUTES = self::PREFIX . 'pow_seeded_routes';

	/**
	 * Set once the admin has dismissed (or acted on) the one-time "unmonitored form
	 * builders detected" notice for the pre-existing-install backfill. @var string
	 */
	const POW_SCOPE_NOTICE_DISMISSED = self::PREFIX . 'pow_scope_notice_dismissed';

	/** @var Text */
	const POW_HIDE_ACTION = self::PREFIX . 'pow_hide_action';

	/** @var Text */
	const POW_HIDE_PATTERN = self::PREFIX . 'pow_hide_pattern';

	/** @var Bool */
	const POW_SAVE_IP = self::PREFIX . 'pow_save_ip';

	/** @var Bool */
	const POW_SAVE_LOGIN = self::PREFIX . 'pow_save_login';

	/** @var Text */
	const POW_SKIP_FIELDS = self::PREFIX . 'pow_skip_fields';

	/** @var Text */
	const POW_FAIL_2_BAN_PATH = self::PREFIX . 'pow_fail_2_ban_path';

	/** @var string */
	const HASH = self::PREFIX . 'hash';

	/**
	 * Ledger of the one-off cleanup that redacts credential values older releases
	 * stored in cleartext (see class-credential-cleanup.php). NOT an option in the
	 * settings sense: deliberately absent from prepare_options()/activate() seeding
	 * — nothing here is a user decision, it is migration bookkeeping (layout
	 * version, per-pass cursor and done flag, frozen rgd_id upper bound), same
	 * category as the HEALTH_* constants below. Autoloaded on purpose: once both
	 * passes are done, Credential_Cleanup::maybe_run() must cost a cached
	 * get_option() and nothing else.
	 *
	 * @var string
	 */
	const POW_CREDENTIAL_CLEANUP = self::PREFIX . 'pow_credential_cleanup';

	/**
	 * Admin-maintained list of LEARNED credential field names, one per line (see
	 * class-learned-credential-fields.php). A real setting — rendered on the
	 * settings page as the transparency/correction surface — but NOT the main
	 * entrance: entries normally arrive via the one-click confirmations (admin
	 * notice / message inbox). Deliberately a separate option from
	 * POW_SKIP_FIELDS: skip means "the row never exists" and is site-scoped,
	 * credential means "the row stays, the value reads [redacted]".
	 *
	 * @var string
	 */
	const POW_CREDENTIAL_FIELDS = self::PREFIX . 'pow_credential_fields';

	/**
	 * Ledger of PROPOSED credential field names (see
	 * class-credential-suggestion-ledger.php). Bookkeeping, not a setting:
	 * absent from prepare_options()/activate() seeding, same category as
	 * POW_CREDENTIAL_CLEANUP. Fed from unauthenticated request data, therefore
	 * capped in every direction; nothing ever moves from here to
	 * POW_CREDENTIAL_FIELDS without an explicit admin click.
	 *
	 * @var string
	 */
	const POW_CREDENTIAL_SUGGESTIONS = self::PREFIX . 'pow_credential_suggestions';

	/**
	 * Fingerprint diagnosis counters (see Stamp::record_fp_status()): how many accepted
	 * solves came back from the SAME address the token was issued to, how many from a
	 * different one, and when the last mismatch was seen (unix timestamp).
	 *
	 * Bookkeeping, not settings: absent from prepare_options()/activate() seeding, same
	 * category as POW_CREDENTIAL_CLEANUP, and written with autoload=no — they are read
	 * on two admin screens, never on a front-end request. Monotonic totals on purpose
	 * (no rolling window): the ratio answers a STRUCTURAL question — "is a cache/proxy
	 * in front of this site?" — where inertia is harmless and a window would only add
	 * moving parts. Resettable from the settings status strip.
	 *
	 * @var string
	 */
	const POW_FP_MATCHED_TOTAL = self::PREFIX . 'pow_fp_matched_total';

	/** @var string */
	const POW_FP_MISMATCHED_TOTAL = self::PREFIX . 'pow_fp_mismatched_total';

	/** @var string */
	const POW_FP_LAST_MISMATCH_AT = self::PREFIX . 'pow_fp_last_mismatch_at';

	/**
	 * Storage-failure diagnosis (see Stamp::record_store_failure()): how often an
	 * ACCEPTED solve could not be persisted into `…_stamp_rgs`, when that last happened
	 * (unix timestamp), and the database error that came with it.
	 *
	 * Why this exists at all: `INSERT IGNORE` (check_stamp()) downgrades a real failure
	 * — missing table, half-applied migration, read-only or full database — to a warning
	 * and returns the same 0 a legitimate duplicate returns. Before this counter, such a
	 * site answered every handshake with {accepted:true} while never writing a single
	 * row, so EVERY submission was classified no_pow:token_no_row and the site owner had
	 * nothing to look at (HANDBUCH.md §12 cause 7).
	 *
	 * Bookkeeping, not settings: absent from prepare_options()/activate() seeding,
	 * written with autoload=no, read on the settings screen only.
	 *
	 * @var string
	 */
	const POW_STORE_FAILED_TOTAL = self::PREFIX . 'pow_store_failed_total';

	/** @var string */
	const POW_STORE_LAST_FAILED_AT = self::PREFIX . 'pow_store_last_failed_at';

	/** @var string */
	const POW_STORE_LAST_ERROR = self::PREFIX . 'pow_store_last_error';

	/**
	 * Lookback window (hours) of the "submissions without a stamp row" health counter.
	 *
	 * @var int
	 */
	const HEALTH_NO_POW_WINDOW_HOURS = 24;

	/**
	 * At how many no-stamp submissions within HEALTH_NO_POW_WINDOW_HOURS the health
	 * counter turns amber. NOT an option: plain internal constant, deliberately not in
	 * prepare_options()/activate() (making it user-configurable is a follow-up, not this
	 * change). 10/day is a deliberately low bar — a healthy site sees the occasional
	 * scripted no-stamp POST, but a broken client-PoW pipeline produces this for
	 * *every* human submission, so double-digit counts mean "look at the console".
	 *
	 * @var int
	 */
	const HEALTH_NO_POW_WARN_THRESHOLD = 10;

	/** @var string */
	private $name;

	/** @var int */
	private $type;

	/** @var int */
	private $default;

	/** @var int */
	private $hint;

	/** @var string|int */
	private $value = '';

	/** @var string|int */
	private $symbol = '';

	/** @var string|int */
	private $group = '';

	/** @var string One-sentence short description, always visible (see Settings_Menu). */
	private $short = '';

	/**
	 * @param string $name
	 * @param int $type
	 * @param string $short One-sentence short description, always visible under the label.
	 */
	public function __construct( $name, $type, $default_value, $hint, $group, $symbol = '', $short = '' ) {
		$this->name    = $name;
		$this->type    = $type;
		$this->default = $default_value;
		$this->value   = $default_value;
		$this->hint    = $hint;
		$this->group   = $group;
		$this->symbol  = $symbol;
		$this->short   = $short;
	}

	/**
	 * @return string
	 */
	public function get_name() {
		return $this->name;
	}

	/**
	 * @return int
	 */
	public function get_type() {
		return $this->type;
	}

	/**
	 * @return string|int
	 */
	public function get_default() {
		return $this->default;
	}

	/**
	 * @return string|int
	 */
	public function get_hint() {
		return $this->hint;
	}

	/**
	 * @return int|string
	 */
	public function get_value() {
		return $this->value;
	}

	/**
	 * @return int|string
	 */
	public function get_symbol() {
		return $this->symbol;
	}

	/**
	 * @return int|string
	 */
	public function get_group() {
		return $this->group;
	}

	/**
	 * @return string
	 */
	public function get_short() {
		return $this->short;
	}

	/**
	 * @param $value
	 * @return void
	 */
	public function set_value( $value ) {
		$this->value = $value;
	}

	/**Get all messages */
	public static function get_rows( $search, $message_type, $today = false, $hidden_actions = array( '-' ), $existing_actions = array( '-' ), $existing_patterns = array(), $hidden_patterns = array() ) {
		global $wpdb;
		$hidden_actions_placeholders   = implode( ', ', array_fill( 0, count( $hidden_actions ), '%s' ) );
		$existing_actions_placeholders = implode( ', ', array_fill( 0, count( $existing_actions ), '%s' ) );
		$search_like                   = '%' . $search . '%';
		$parameters                    = array_merge(
			array( $message_type ),
			$hidden_actions,
			$existing_actions,
			array( $search_like, $search_like )
		);

		$sql_array = array();
		//For each pattern build a sub-seelect to check whether the conditions match
		foreach ( $existing_patterns as $pattern ) {
			$pattern    = self::generate_paths( json_decode( $pattern, true ), '' );
			$conditions = array();
			foreach ( $pattern as $param_path => $value ) {
				if ( null === $value ) {
					$conditions[] = "(rgd.rgd_attribute LIKE '" . esc_sql( $param_path ) . "')";
				} else {
					$conditions[] = "(rgd.rgd_attribute LIKE '" . esc_sql( $param_path ) . "' AND rgd.rgd_value = '" . esc_sql( $value ) . "')";
				}
			}

			$sql_array[] = ' AND rgd.rgm_id NOT IN (
                    SELECT rgd.rgm_id
                    FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd rgd
                    WHERE ' . implode( ' OR ', $conditions ) . '
                    GROUP BY rgd.rgm_id
                    HAVING COUNT(DISTINCT rgd.rgd_attribute) = ' . count( $pattern ) . '
                )';
		}
		$hidden_sql_array = array();
		//For each pattern build a sub-seelect to check whether the conditions match
		foreach ( $hidden_patterns as $pattern ) {
			$pattern    = self::generate_paths( json_decode( $pattern, true ), '' );
			$conditions = array();
			foreach ( $pattern as $param_path => $value ) {
				if ( null === $value ) {
					$conditions[] = "(rgd.rgd_attribute LIKE '" . esc_sql( $param_path ) . "')";
				} else {
					$conditions[] = "(rgd.rgd_attribute LIKE '" . esc_sql( $param_path ) . "' AND rgd.rgd_value = '" . esc_sql( $value ) . "')";
				}
			}

			$hidden_sql_array[] = ' AND rgd.rgm_id NOT IN (
                    SELECT rgd.rgm_id
                    FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd rgd
                    WHERE ' . implode( ' OR ', $conditions ) . '
                    GROUP BY rgd.rgm_id
                    HAVING COUNT(DISTINCT rgd.rgd_attribute) = ' . count( $pattern ) . '
                )';
		}

		$filter_today = '';
		if ( $today ) {
			$filter_today = ' AND DATE(rgm.rgm_date) = CURDATE() ';
		}
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQL.NotPrepared -- $hidden_actions_placeholders/$existing_actions_placeholders only ever contain comma-separated "%s" tokens (their count matches the actual values later merged into $parameters); $sql_array/$hidden_sql_array are pre-built LIKE fragments from admin-defined JSON patterns (Option::generate_paths), not raw request input; $filter_today is one of two hardcoded literals. The sniff cannot statically verify the dynamic %s count, hence the false-positive replacement-count warning too.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'
                    SELECT COUNT(*) as count
                    FROM(
                        SELECT DISTINCT rgm.rgm_id
                        FROM ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm rgm
                        JOIN ' . $wpdb->prefix . "recaptcha_gdpr_details_rgd rgd
                        ON rgm.rgm_id = rgd.rgm_id
                        WHERE rgm.rgm_type = %s
                        AND COALESCE(rgm.rgm_action, '') NOT IN ($hidden_actions_placeholders)
                        AND COALESCE(rgm.rgm_action, '') NOT IN ($existing_actions_placeholders)
                        AND ( rgd.rgd_attribute LIKE %s
                            OR rgd.rgd_value LIKE %s
                            )
                        " . implode( '', $sql_array ) . implode( '', $hidden_sql_array ) . "
                        $filter_today
                    ) counter
                ",
				$parameters
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, WordPress.DB.PreparedSQL.NotPrepared
		$count = 0;
		foreach ( $rows as $row ) {
			$count = $row->count;
		}

		return $count;
	}

	/**Compare whether a JSON obj1 is completely inherited in a JSON object 2 */
	public static function compare_json_objects( $obj1, $obj2, $ignore_null = false ) {
		if ( $obj1 && count( $obj1 ) ) {
			foreach ( $obj1 as $key => $value ) {
				if ( isset( $obj2[ $key ] ) ) {
					if ( $value && ( is_array( $value ) ) && is_array( $obj2[ $key ] ) ) {
						if ( ! self::compare_json_objects( $value, $obj2[ $key ], $ignore_null ) ) {
							return false;
						}
					} elseif ( ! ( $ignore_null && ( null === $value ) ) ) {
						if ( $value !== $obj2[ $key ] ) {
							return false;
						}
					}
				} else {
					return false;
				}
			}
			return true;
		} else {
			return false;
		}
	}

	/**Converts an array of nested Attribute names into a JSON-object */
	public static function convert_to_json_object( $mysql_result, $attribute_name, $value_name ) {
		$json_object = array();
		foreach ( $mysql_result as $row ) {
			$keys           = explode( '->', $row->{ $attribute_name } );
			$current_object = &$json_object;

			foreach ( $keys as $key ) {
				// If the key does not exist, create an empty array or object
				if ( ! isset( $current_object[ $key ] ) ) {
					$current_object[ $key ] = array();
				}

				// Move to the next level of the JSON object
				$current_object = &$current_object[ $key ];
			}

			// Assign the value to the lowest level of the nested attribute
			$current_object = $row->{ $value_name };
		}

		return $json_object;
	}

	/** Transforms a nested object into a string-representation */
	public static function generate_paths( $data, $current_path ) {
		$values = array();

		foreach ( $data as $key => $value ) {
			$path = $current_path . ( $current_path ? '->' : '' ) . $key;

			if ( is_array( $value ) || is_object( $value ) ) {
				// Recurse into nested arrays/objects
				$nested_values = self::generate_paths( $value, $path );
				// Merge the nested values with the current values array
				$values = array_merge( $values, $nested_values );
			} else {
				// Add the path and the corresponding value to the values array as an associative pair
				$values[ $path ] = $value;
			}
		}

		return $values;
	}

	public static function hash_values( $x ) {
		return hash( 'sha256', $x, false );
	}

	/**
	 * Count messages of a given rgm_type saved within the last $days days.
	 * Used by the settings status strip (e.g. spam blocked this week).
	 *
	 * @param int $type Message type (rgm_type column, e.g. 2 for spam).
	 * @param int $days Lookback window in days.
	 * @return int
	 */
	public static function count_messages_since_days( $type, $days ) {
		global $wpdb;
		$count = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm WHERE rgm_type = %s AND rgm_date >= NOW() - INTERVAL %d DAY',
				$type,
				$days
			)
		);
		return (int) $count;
	}

	/**
	 * Count classification-reason rows of the `no_pow:*` family recorded within the last
	 * $hours hours — submissions where the client-side PoW never produced a usable stamp
	 * row (the #1 support case, see HANDBUCH §12). Feeds the health counter in the
	 * settings status strip and the dashboard widget.
	 *
	 * The query filters on rgd_attribute equality + a rgd_value prefix LIKE, which the
	 * existing composite index idx_rgd_attribute_value on (rgd_attribute(255),
	 * rgd_value(255)) covers — no new index needed. No rgm_type filter: a no-stamp
	 * submission counts regardless of which folder it landed in.
	 *
	 * NB: this only sees *stored* messages. With POW_SAVE_SPAM disabled nothing is
	 * persisted and the counter reads 0 — see HANDBUCH §12.
	 *
	 * @param int $hours Lookback window in hours.
	 * @return int
	 */
	public static function count_no_pow_reasons_since_hours( $hours ) {
		global $wpdb;
		$count = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd rgd'
				. ' INNER JOIN ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm rgm ON rgm.rgm_id = rgd.rgm_id'
				. ' WHERE rgd.rgd_attribute = %s AND rgd.rgd_value LIKE %s AND rgm.rgm_date >= NOW() - INTERVAL %d HOUR',
				'_gdpr_reason',
				// Underscore escaped: `_` is a single-character SQL wildcard, and the
				// prefix must match literally even if a future reason code differs only
				// in that position.
				'no\_pow:%',
				$hours
			)
		);
		return (int) $count;
	}

	/**
	 * Pure threshold decision for a health counter: does $count warrant a warning?
	 * Deliberately separate from the counting query above so it carries no WordPress
	 * dependency and is directly unit-testable (tests/unit/OptionHealthCounterTest.php).
	 *
	 * @param int $count     Observed value.
	 * @param int $threshold Value at (and above) which the counter warns.
	 * @return array{warn: bool, class: string} Warn flag plus the status-strip CSS class.
	 */
	public static function health_counter_status( $count, $threshold ) {
		$warn = (int) $count >= (int) $threshold;
		return array(
			'warn'  => $warn,
			'class' => $warn ? 'gdpr-status-amber' : '',
		);
	}

	/**
	 * Pure decision for the "solved puzzles are not being stored" alarm
	 * (POW_STORE_* counters, written by Stamp::record_store_failure()).
	 *
	 * Shown only while the failure is RECENT: every visitor handshake retries the write,
	 * so a site that stopped failing stops reporting on its own, and one long-past
	 * hiccup does not stick a red pill on the settings screen forever. Conversely a
	 * still-broken site re-arms it with the next visitor. Same window as the no-stamp
	 * health counter, for one story on that strip.
	 *
	 * Red, not amber: unlike the no-stamp counter (which a bit of scripted traffic
	 * raises legitimately), this one cannot fire at all on a healthy site — the server
	 * has verified its own accepted solve is not in the table.
	 *
	 * No WordPress dependency (hence the literal 3600 instead of HOUR_IN_SECONDS) so it
	 * stays in the WP-free unit suite — tests/unit/OptionHealthCounterTest.php.
	 *
	 * @param int $total        POW_STORE_FAILED_TOTAL.
	 * @param int $last_at      POW_STORE_LAST_FAILED_AT (unix timestamp, 0 = never).
	 * @param int $now          Current unix timestamp.
	 * @param int $window_hours How long a failure keeps the alarm lit.
	 * @return array{show: bool, class: string} Whether to show it, plus the CSS class.
	 */
	public static function store_failure_status( $total, $last_at, $now, $window_hours = self::HEALTH_NO_POW_WINDOW_HOURS ) {
		$total   = max( 0, (int) $total );
		$last_at = max( 0, (int) $last_at );
		$age     = (int) $now - $last_at;
		$show    = $total > 0 && $last_at > 0 && $age >= 0 && $age <= max( 1, (int) $window_hours ) * 3600;

		return array(
			'show'  => $show,
			'class' => $show ? 'gdpr-status-red' : '',
		);
	}

	/**
	 * Share of accepted solves that came back from a different address than the token
	 * was issued to, in whole percent. Pure arithmetic over the two fingerprint
	 * counters (POW_FP_*_TOTAL), so the display can be unit-tested — see
	 * tests/unit/OptionHealthCounterTest.php.
	 *
	 * Returns 0 when nothing has been measured yet: with no data, "0 %" is the honest
	 * reading of the question ("do solves arrive from elsewhere?" — none did), and the
	 * callers hide the whole item at total 0 anyway. Negative/garbage inputs are
	 * floored at 0 rather than producing a nonsensical percentage.
	 *
	 * @param int $matched    POW_FP_MATCHED_TOTAL.
	 * @param int $mismatched POW_FP_MISMATCHED_TOTAL.
	 * @return array{total:int,percent:int} Measured solves and the mismatch share.
	 */
	public static function fp_mismatch_share( $matched, $mismatched ) {
		$matched    = max( 0, (int) $matched );
		$mismatched = max( 0, (int) $mismatched );
		$total      = $matched + $mismatched;

		return array(
			'total'   => $total,
			'percent' => $total > 0 ? (int) round( ( $mismatched * 100 ) / $total ) : 0,
		);
	}
}
