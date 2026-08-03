<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

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
	const POW_APPLY_REST = self::PREFIX . 'pow_apply_rest';

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
					$conditions[] = "(rgd.rgd_attribute LIKE '{$param_path}')";
				} else {
					$conditions[] = "(rgd.rgd_attribute LIKE '{$param_path}' AND rgd.rgd_value = '{$value}')";
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
					$conditions[] = "(rgd.rgd_attribute LIKE '{$param_path}')";
				} else {
					$conditions[] = "(rgd.rgd_attribute LIKE '{$param_path}' AND rgd.rgd_value = '{$value}')";
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
}
