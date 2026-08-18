<?php
/**
 * The counting half of Option: how many messages of a kind are stored, how many
 * submissions arrived without a solved puzzle, and how those figures read.
 *
 * SCHNITTLINIE (Welle 4, PLAN-DATEIGROESSE.md): see the `use Option_Counters;` docblock
 * in class-option.php for why this is a trait and what stayed behind. In short: the
 * option model (keys + instance) is a registry that legitimately grows one line per
 * option; this — the folder queries, the path helpers they need, the transient bucket
 * counter and the two pure status decisions — is logic that merely grew up next to it.
 *
 * ONE CLOCK. No statement in here may ask the database what time it is: every threshold
 * is computed in PHP from current_time() and handed to MySQL as a ready-made literal,
 * because rgm_date is written with current_time('mysql') and a host whose MySQL SESSION
 * timezone differs from WordPress's would otherwise count the wrong rows (HANDBUCH.md
 * §12 cause 8). The plugin-wide net for that rule is tests/unit/OneClockTest.php, which
 * walks every PHP file under plugin/ and therefore covers this one from the day it
 * exists.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse (Traits
// bekommen keine eigene Indexzeile; sie sind Teil ihrer Klasse).

/**
 * Message and health counting. Composed into Option.
 */
trait Option_Counters {

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
			$decoded_pattern = json_decode( $pattern, true );
			if ( ! is_array( $decoded_pattern ) ) {
				// Not valid JSON (e.g. a stray textarea edit predating the save-time
				// guard) -- skip this line rather than build a sub-select with an empty
				// OR-list ("WHERE  GROUP BY", a SQL syntax error). generate_paths()
				// itself now also tolerates this, but skipping here avoids the broken
				// fragment in the first place.
				continue;
			}
			$pattern    = self::generate_paths( $decoded_pattern, '' );
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
			$decoded_pattern = json_decode( $pattern, true );
			if ( ! is_array( $decoded_pattern ) ) {
				// See the matching guard above.
				continue;
			}
			$pattern    = self::generate_paths( $decoded_pattern, '' );
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
			// rgm_date is written via current_time('mysql') (WP local time). CURDATE() reads
			// the MySQL SESSION's timezone instead, so on any host where that differs from
			// WordPress's the "today" filter would include/exclude the wrong rows. The
			// threshold is computed in PHP from current_time() and handed to MySQL as a
			// ready-made literal via prepare(), so MySQL never evaluates "now" itself.
			$filter_today = ' AND rgm.rgm_date >= %s ';
			$parameters[] = gmdate( 'Y-m-d 00:00:00', current_time( 'timestamp' ) ); // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested -- intentional: matches current_time('mysql')-written rgm_date, see comment above
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

		// Every caller feeds this the result of json_decode() on an admin-configured
		// pattern line (get_rows() below, Message_Page::get_messages()) -- a line that
		// predates a save-time guard, or was edited outside the plugin, can be anything
		// but valid JSON, and json_decode() then returns null/scalar/bool, not an
		// array. `foreach` on that would throw "argument must be of type array|object" --
		// a PHP warning landing in an Ajax JSON body ahead of the real response
		// (HANDBUCH.md §12 Ursache 1 damage class, confirmed live for this exact call
		// under display_errors=1 before this guard existed). An empty result here also
		// matters to the two call sites: they skip building a SQL fragment for it
		// entirely when it comes back empty, rather than emitting one with an empty
		// OR-list.
		if ( ! is_array( $data ) && ! is_object( $data ) ) {
			return $values;
		}

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
		// rgm_date is written via current_time('mysql') (WP local time); NOW() reads the
		// MySQL SESSION's timezone instead, so on a host where that differs from WordPress's
		// the count would drift. Threshold computed in PHP from current_time() and passed as
		// a ready-made literal via prepare(), so MySQL never evaluates "now" itself.
		$threshold = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - $days * DAY_IN_SECONDS ); // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested -- intentional: matches current_time('mysql')-written rgm_date, see comment above
		$count     = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm WHERE rgm_type = %s AND rgm_date >= %s',
				$type,
				$threshold
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
		// rgm_date is written via current_time('mysql') (WP local time); NOW() reads the
		// MySQL SESSION's timezone instead, so on a host where that differs from WordPress's
		// the count would drift. Threshold computed in PHP from current_time() and passed as
		// a ready-made literal via prepare(), so MySQL never evaluates "now" itself.
		$threshold = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - $hours * HOUR_IN_SECONDS ); // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested -- intentional: matches current_time('mysql')-written rgm_date, see comment above
		$count     = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd rgd'
				. ' INNER JOIN ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm rgm ON rgm.rgm_id = rgd.rgm_id'
				. ' WHERE rgd.rgd_attribute = %s AND rgd.rgd_value LIKE %s AND rgm.rgm_date >= %s',
				'_gdpr_reason',
				// Underscore escaped: `_` is a single-character SQL wildcard, and the
				// prefix must match literally even if a future reason code differs only
				// in that position.
				'no\_pow:%',
				$threshold
			)
		);
		return (int) $count;
	}

	/**
	 * Count one submission that was classified "no proof of work", independently of
	 * whether it was stored.
	 *
	 * WHY THIS EXISTS NEXT TO count_no_pow_reasons_since_hours(). That one counts
	 * `_gdpr_reason` rows, which only exist when save_message() ran — and for spam that
	 * is gated behind POW_SAVE_SPAM. On a site with spam storage switched off it
	 * therefore reads 0 forever, and 0 reads like "healthy" exactly where the operator
	 * has nothing else to look at either. The "everything is suddenly spam" case is the
	 * most common support case there is; a counter that goes blind precisely on the
	 * sites that need it most is worse than no counter.
	 *
	 * DSGVO-neutral by construction, same shape as Stamp::increment_spam_counter():
	 * one transient per time bucket, holding a number. No per-client data, nothing that
	 * could identify a visitor, and it expires on its own.
	 *
	 * Non-atomic get+set, the same accepted trade-off as the under-attack counter: a
	 * lost increment under concurrency moves a diagnostic number by one and never a
	 * security decision.
	 *
	 * @return void
	 */
	public static function increment_no_pow_health_counter() {
		$key   = self::health_bucket_key( time() );
		$count = (int) get_transient( $key );
		// TTL one hour beyond the window, so the oldest bucket the sum reads is still
		// alive when it is read.
		set_transient( $key, $count + 1, ( self::HEALTH_NO_POW_WINDOW_HOURS + 1 ) * HOUR_IN_SECONDS );
	}

	/**
	 * Sum of the storage-independent counter over the lookback window.
	 *
	 * @return int
	 */
	public static function no_pow_health_counter_sum() {
		$now   = time();
		$total = 0;
		for ( $hours_ago = 0; $hours_ago < self::HEALTH_NO_POW_WINDOW_HOURS; $hours_ago++ ) {
			$total += (int) get_transient( self::health_bucket_key( $now - ( $hours_ago * HOUR_IN_SECONDS ) ) );
		}

		return $total;
	}

	/**
	 * Transient key of the bucket a timestamp falls into.
	 *
	 * @param int $timestamp Unix timestamp.
	 * @return string
	 */
	private static function health_bucket_key( $timestamp ) {
		return self::PREFIX . 'no_pow_health_' . ProofOfWork::time_bucket( (int) $timestamp, self::HEALTH_BUCKET_MINUTES );
	}

	/**
	 * The figure the status strip and the dashboard widget show: the LARGER of the two
	 * no-stamp counters.
	 *
	 * MAXIMUM, not sum. Both count the same events — a submission classified no_pow —
	 * they just see different subsets of them: the stored-rows query misses everything
	 * that was not saved, the bucket counter misses everything from before it existed
	 * or from outside its transient lifetime. Adding them would double-count every
	 * submission both of them saw, which on a normal site is most of them. The maximum
	 * is the sharpest lower bound the two can jointly justify.
	 *
	 * @return int
	 */
	public static function no_pow_health_count() {
		return max(
			self::count_no_pow_reasons_since_hours( self::HEALTH_NO_POW_WINDOW_HOURS ),
			self::no_pow_health_counter_sum()
		);
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
}
