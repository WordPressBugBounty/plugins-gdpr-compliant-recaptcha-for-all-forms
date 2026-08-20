<?php
/**
 * The PERSISTENCE half of Stamp: what happens once the verdict exists — writing the
 * message and its detail rows, carrying the verdict onto the analysis row, and the
 * fail2ban line.
 *
 * SCHNITTLINIE (Welle 5b, PLAN-DATEIGROESSE.md): class-stamp.php was one file of 2920
 * lines, i.e. over the 2853 cap its ledger entry froze it at. Its own head docblock
 * already named the seam — the class spans three area files — so the cut follows that
 * text rather than inventing one:
 *   - class-stamp.php               — the GATE half (constructor, run(), login path,
 *                                     handbuch/gate.md; the triage block itself moved
 *                                     on later, to trait-stamp-triage.php), the POW
 *                                     half (get_stamp(), check_stamp(), check_request(),
 *                                     consume_*) and check_submit() with its stages.
 *   - trait-stamp-persistence.php   — THIS file: the persistence half of
 *                                     handbuch/detection.md. save_for_analysis(),
 *                                     save_message() with its field-tree flattening
 *                                     (generate_paths(), check_skipped_fields(),
 *                                     access_object_or_array()), the analysis-verdict
 *                                     upserts and log_fail2ban_event().
 *
 * WHY check_submit() STAYS BEHIND, together with the gate and the PoW verification.
 * Those three read and write the SAME instance state, and that state is the semantics:
 * check_request() is called from the middle of the classification chain, the six stages
 * mutate $plugin_spam/$classification_reason/the counters in "first cause wins" order
 * (tests/unit/StampClassificationOrderTest.php pins it), and the gate consumes the same
 * token/row logic as the PoW half. Cutting anywhere in there would distribute exactly
 * the state the file-size plan argues against distributing. The persistence methods, by
 * contrast, only ever READ that state after it is final.
 *
 * A TRAIT, NOT A SECOND CLASS — same decision and same reason as trait-blocklist-values.php
 * (Welle 4) and the six trait-settings-*.php (Welle 3). save_message() reads
 * $plugin_spam, $classification_reason, $clean_scoring, $pow_probe, $analysis_row_id and
 * $rest_route in exactly the shape check_submit() left them in during THIS request; a
 * second class would have to be handed all six across a file boundary, and the handover
 * would be the new place for them to disagree. A trait is compiled into Stamp: every
 * call still reads $this->save_message(), every property is the same one, visibility is
 * unchanged, and PHPStan still attributes findings to class-stamp.php (which is why
 * phpstan-baseline.neon needs no edit). The split is a move, not a rebuild.
 *
 * Consequence for the loader: a trait must be loaded BEFORE the class that uses it — see
 * the require_once order in plugin/recaptcha-gdpr-compliant.php and tests/bootstrap.php.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/detection.md, Abschnitt "Persistenz und Fail2Ban".
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse (Traits
// bekommen keine eigene Indexzeile; sie sind Teil ihrer Klasse).

/**
 * Saving a submission and everything that writes to disk. Composed into Stamp.
 */
trait Stamp_Persistence {

	private function save_for_analysis() {
		$ajax      = defined( 'DOING_AJAX' ) && DOING_AJAX;
		$action    = isset( $this->whole_request_data ['action'] ) ? sanitize_text_field( $this->whole_request_data ['action'] ) : '';
		$client_ip = $this->get_client_ip();

		// The request shapes the analysis mode must never record: the plugin's OWN
		// settings save. Hard-coded on purpose — this is not an admin-configurable list.
		$excluded_patterns_for_analysis = array(
			array(
				'page'        => 'gdpr_pow_options',
				'action'      => 'update',
				'option_page' => 'gdpr_pow_header_section',
			),
		);

		// Compared with Pattern_Matcher::matches(), i.e. the SAME field-pattern comparison
		// the live gate uses. Until 2026-08-12 this one line called a second, similar
		// implementation of its own (Option::compare_json_objects(), whose only caller it
		// was). The two agreed on the hard-coded signature above — three non-empty strings,
		// no null, no nesting, verified branch by branch including the empty-request,
		// '0'/false/null-value and array-value edges — and diverged everywhere else
		// (null-as-existence, stdClass nesting, count() on an object). That latent
		// divergence is exactly the failure class Pattern_Matcher was extracted to make
		// constructively impossible, so the second implementation was deleted rather than
		// documented. Behaviour pinned in tests/unit/StampAnalysisExclusionTest.php.
		$pattern_listed = false;
		foreach ( $excluded_patterns_for_analysis as $existing_pattern ) {
			if ( $existing_pattern ) {
				$pattern_listed = Pattern_Matcher::matches( $existing_pattern, $this->whole_request_data );
				if ( $pattern_listed ) {
					break;
				}
			}
		}

		$excluded_actions_for_analysis = array( 'render_messages', 'render_message', 'delete_message', 'heartbeat', 'save_pattern', 'check_stamp', 'save_list_parameter', 'change_message_type' );
		if ( isset( $_SERVER['REQUEST_METHOD'] )
			&& 'POST' === $_SERVER['REQUEST_METHOD']
			&& get_option( Option::POW_ANALYSIS_MODE )
			&& (
					( ! $ajax && ! $pattern_listed )
					|| ( $ajax && ! in_array( $action, $excluded_actions_for_analysis, true ) )
			)
		) {
			$this->analysis_row_id = $this->save_message( $this->whole_request_data, $action, $ajax, 4, $this->hash_values( $client_ip ) );
		}
	}

	/** Resolves a '->'-separated path into a nested array/object and returns a reference to the target value
	 *
	 */
	private function &access_object_or_array( &$obj, $path ) {
		$path_segments  = explode( '->', $path );
		$current_object = &$obj;
		foreach ( $path_segments as $segment ) {
			// If the segment is a numeric key, convert it to an integer
			$segment = is_numeric( $segment ) ? (int) $segment : $segment;

			if ( is_array( $current_object ) && array_key_exists( $segment, $current_object ) ) {
				// If the segment is a valid key in the array, move to the next level
				$current_object = &$current_object[ $segment ];
			} elseif ( is_object( $current_object ) && property_exists( $current_object, $segment ) ) {
				// If the segment is a valid property in the object, move to the next level
				$current_object = &$current_object->$segment;
			} else {
				return null;
			}
		}
		// Modify the value by adding the prefix
		return $current_object;
	}

	/** Transforms an array into a string-representation */

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

	/** Transforms an array into a string-representation
	 *
	 * Returns array( $values, $query, $title, $first ). The marker-driven credential
	 * handling that used to be threaded through here (three extra parameters and a
	 * fifth return element) is gone: save_message() redacts credential values up
	 * front, so nothing has to be dropped while flattening. The POW_SKIP_FIELDS
	 * logic ($pre_forbidden_fields) is unrelated and unchanged — it is an explicit
	 * admin choice to not store a field at all.
	 */
	private function generate_paths( $my_id, $data, $current_path, $pre_forbidden_fields, $referrer_without_protocol, $query, $first, $custom_titles, $title ) {
		$values = array();

		foreach ( $data as $key => $value ) {
			$path = $current_path . ( $current_path ? '->' : '' ) . $key;
			if ( is_array( $value ) || is_object( $value ) ) {
				// Recurse into nested arrays/objects
				$nested_values = $this->generate_paths( $my_id, $value, $path, $pre_forbidden_fields, $referrer_without_protocol, $query, $first, $custom_titles, $title );
				// Merge the nested values with the current values array
				$values = array_merge( $values, $nested_values[0] );
				$query  = $nested_values[1];
				$title  = $nested_values[2];
				$first  = $nested_values[3];
			} else {
				$skipped_field = false;
				if ( count( $pre_forbidden_fields ) ) {
					$skipped_field = $this->check_skipped_fields( $pre_forbidden_fields, $path, $referrer_without_protocol );
				}
				if ( ! $skipped_field ) {
					if ( $first ) {
						$first = false;
					} else {
						$query .= ',';
					}
					$query .= '(%d, %s, %s, %d)';
					if ( isset( $custom_titles[ htmlentities( $path ) ] ) ) {
						$title .= $value . ' | ';
					}
					// Add the path and the corresponding value to the values array alternately.
					// rgm_posted stays false for a redacted value: it would otherwise become a
					// clickable pattern-/block-candidate on the replacement literal, and such
					// a pattern would match every future message carrying a redacted field.
					$values[] = $my_id;
					$values[] = $path;
					$values[] = $value;
					$values[] = Credential_Fields::REDACTED_VALUE !== $value;
				}
			}
		}

		return array( $values, $query, $title, $first );
	}

	/** Check whether a fields shall be skipped */
	private function check_skipped_fields( $pre_forbidden_fields, $field, $referrer_without_protocol ) {
		if ( count( $pre_forbidden_fields ) ) {
			foreach ( $pre_forbidden_fields as $key => $value ) {
				if ( strpos( $referrer_without_protocol, $value['site'] ) && htmlentities( $field ) === $value['field'] ) {
					return true;
				}
			}
		}
		return false;
	}

	/** Save a message
	 *
	 * $origin is the submission path handed down from check_submit(); only
	 * pre_process_login() sets it ('login'). It replaces the former reconstruction of
	 * "this was a login" from hashPWFields + wp-submit, which silently failed whenever
	 * the client JS had not run or the POST was minimal.
	 */
	/**
	 * Write `_gdpr_reason` / `_gdpr_scoring` onto the type-4 analysis row of THIS
	 * request, after check_submit() has decided.
	 *
	 * Same upsert convention as Analysis::upsert_route_row(): existence is asked
	 * EXPLICITLY rather than inferred from $wpdb->update()'s return value, because
	 * MySQL reports 0 affected rows both for "no such row" and for "row exists, value
	 * unchanged" — treating that 0 as "insert one" duplicates the row on every repeat.
	 *
	 * A null value REMOVES the row rather than leaving a stale one. On this path that
	 * matters for `_gdpr_scoring`: a message that is clean carries a scoring line and a
	 * message that is spam does not, so a row left over from a different verdict would
	 * describe a judgment that was not made.
	 *
	 * Costs nothing when analysis mode is off: $analysis_row_id is null and this
	 * returns immediately, before touching the database.
	 *
	 * @return void
	 */
	private function update_analysis_verdict() {
		if ( null === $this->analysis_row_id ) {
			return;
		}

		$this->upsert_analysis_detail( '_gdpr_reason', $this->classification_reason );
		$this->upsert_analysis_detail( '_gdpr_scoring', $this->clean_scoring );
	}

	/**
	 * Insert, update or delete one technical detail row of the analysis entry.
	 *
	 * @param string      $attribute Technical attribute name (leading underscore).
	 * @param string|null $value     Value, or null to remove the row.
	 * @return void
	 */
	private function upsert_analysis_detail( $attribute, $value ) {
		global $wpdb;

		$table = $wpdb->prefix . 'recaptcha_gdpr_details_rgd';
		$where = array(
			'rgm_id'        => (int) $this->analysis_row_id,
			'rgd_attribute' => $attribute,
		);

		if ( null === $value || '' === $value ) {
			$wpdb->delete( $table, $where, array( '%d', '%s' ) );
			return;
		}

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, values via prepare()
		$exists = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT rgd_id FROM $table WHERE rgm_id = %d AND rgd_attribute = %s LIMIT 1",
				(int) $this->analysis_row_id,
				$attribute
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		if ( $exists ) {
			$wpdb->update( $table, array( 'rgd_value' => $value ), $where, array( '%s' ), array( '%d', '%s' ) );
			return;
		}

		$wpdb->insert(
			$table,
			array(
				'rgm_id'        => (int) $this->analysis_row_id,
				'rgd_attribute' => $attribute,
				'rgd_value'     => $value,
				'rgm_posted'    => 0,
			),
			array( '%d', '%s', '%s', '%d' )
		);
	}

	/**
	 * Is THIS REQUEST WooCommerce shopping-cart activity? Decides the POW_SAVE_CART
	 * exemption in save_message() — and asks $_REQUEST ($this->whole_request_data), not
	 * the $fields the caller handed in.
	 *
	 * WHY THE REQUEST AND NOT $fields. On the live path $fields is request_data = $_POST,
	 * while the pattern that makes a cart request MONITORED matches whole_request_data =
	 * $_REQUEST (capture_request_data(), class-stamp.php). On `GET /?add-to-cart=123` the
	 * pattern therefore fired and this exemption did not: switching "Save WooCommerce
	 * shopping carts" OFF still left those messages coming — a broken promise (measured
	 * 2026-08-19). Three reasons the exemption is the side that moves:
	 *   - WooCommerce itself defines cart activity over `$_REQUEST['add-to-cart']`
	 *     (class-wc-form-handler.php), so the key in the QUERY *is* a cart request.
	 *   - save_for_analysis() already passes whole_request_data to save_message(), so the
	 *     analysis path has always read $_REQUEST here. The live path was the outlier;
	 *     this unifies the two rather than adding a third behaviour.
	 *   - The monitored SCOPE stays as it is, because the MATCHER is not touched here.
	 *     Narrowing that one to $_POST would be a coverage decision, not a fix — owner's
	 *     call, own BACKLOG item ("Methoden-Gate für Muster- und Action-Abgleich").
	 *
	 * THE SIDE EFFECT, named rather than hidden: with the option OFF, a spam POST that
	 * carries `add-to-cart` only in its query string is no longer stored either. The
	 * VERDICT does not change — save_message() governs persistence, never block/no-block.
	 * WARNING for whoever adds WooCommerce's default ajax path (`wc-ajax=add_to_cart`)
	 * to the monitored scope: it would run PAST this exemption, carrying neither
	 * `add-to-cart` nor `update_cart`. That shape has to be learnt here at the same time.
	 *
	 * @return bool True if this request is WooCommerce cart activity.
	 */
	private function is_shopping_cart_request() {
		$request = is_array( $this->whole_request_data ) ? $this->whole_request_data : array();
		return isset( $request['add-to-cart'] )
			|| ( isset( $request['update_cart'] ) && isset( $request['woocommerce-cart-nonce'] ) );
	}

	public function save_message( $fields, $action, $ajax, $message_type, $ip, $origin = '' ) {
		if (
			// Check whether the message stems from a login and shall be saved
			! ( ! get_option( Option::POW_SAVE_LOGIN ) && 'login' === $origin )
			&& ( //Check for WooCommerce shopping carts and whether they shall be saved
				get_option( Option::POW_SAVE_CART )
				|| ! $this->is_shopping_cart_request()
			)
		) {
			$posted_site = null;
			if ( array_key_exists( 'REQUEST_URI', $_SERVER ) && array_key_exists( 'HTTP_HOST', $_SERVER ) ) {
				$posted_site = $_SERVER['HTTP_HOST'] . preg_replace( '/^(https?:\/\/)/i', '', $_SERVER['REQUEST_URI'] );
			}
			// Decode the client-injected hashPWFields marker into credential field
			// paths. marker_paths_from_raw() is total and takes the unauthenticated
			// request value as-is (non-string, broken base64, non-JSON → empty list),
			// so no guards are needed here any more.
			$marker_paths = Credential_Fields::marker_paths_from_raw( isset( $fields['hashPWFields'] ) ? $fields['hashPWFields'] : null );

			// The admin-confirmed credential field names — the third line next to the
			// name heuristic and the marker, and the only one that covers a password
			// field with an inconspicuous name posted WITHOUT the plugin's JS.
			$learned_names = Credential_Learning::learned_names();

			// Learn from THIS submission for the later ones: a marker path that no
			// rule recognises becomes a proposal (the field NAME only, never a
			// value). Records nothing else and adds nothing by itself — confirming a
			// proposal is an explicit, capability-gated admin click, because the
			// marker comes from unauthenticated request data.
			Credential_Learning::observe( $marker_paths, $learned_names );

			// Credential redaction pre-pass — the ONE place credential values are
			// removed, and deliberately in the persistence path only (check_submit()
			// keeps working on raw values, see its docblock). It runs BEFORE
			// strip_plugin_fields(), before the title build and before both write
			// loops, so everything downstream — including generate_paths(), which
			// flattens exactly this structure — only ever sees redacted values.
			// The name heuristic inside redact() is the primary line and covers
			// submissions the plugin's JS never touched (no-JS logins, hand-built
			// bodies); the marker is an additional signal on top.
			$fields = Credential_Fields::redact( $fields, $marker_paths, $learned_names );

			// Only AFTER hashPWFields has been consumed for the credential paths
			// above: drop the plugin's own injected fields so they never become
			// persisted detail rows (and thus never candidates for a recognition
			// pattern built from a saved message). Must not run before this point —
			// stripping hashPWFields earlier would throw away the marker signal
			// before it could be used.
			$fields               = self::strip_plugin_fields( $fields );
			$lines                = preg_split( '/\r\n|\n|\r/', get_option( Option::POW_SKIP_FIELDS ), -1, PREG_SPLIT_NO_EMPTY );
			$pre_forbidden_fields = array();
			if ( count( $lines ) > 0 ) {
				foreach ( $lines as $key => $value ) {
					$args = explode( ':', $value );
					if ( 2 === count( $args ) ) {
						$pre_forbidden_fields[ $key ]['site']  = trim( $args[0] );
						$pre_forbidden_fields[ $key ]['field'] = trim( $args[1] );
					}
				}
			}
			global $wpdb;
			$wpdb->query( 'START TRANSACTION' );
			if ( ! $message_type ) {
				if ( $this->plugin_spam ) {
					$message_type = 2;
				} else {
					$message_type = 1;
				}
			}

			//Set the customizable title for the message headers on the message page
			$custom_titles = null;
			$lines         = preg_split( '/\r\n|\n|\r/', get_option( Option::POW_MESSAGE_HEADS ), -1, PREG_SPLIT_NO_EMPTY );
			if ( count( $lines ) > 0 ) {
				foreach ( $lines as $line ) {
					$value                   = wp_kses_post( $line );
					$custom_titles[ $value ] = $value;
				}
			}
			$table  = $wpdb->prefix . 'recaptcha_gdpr_message_rgm';
			$data   = array(
				'rgm_type'   => $message_type,
				'rgm_date'   => current_time( 'mysql' ),
				'rgm_ajax'   => $ajax,
				'rgm_action' => $action,
				'rgm_ip'     => $ip,
				'rgm_site'   => $posted_site,
			);
			$format = array( '%d', '%s', '%d', '%s', '%s', '%s' );
			$wpdb->insert( $table, $data, $format );
			$my_id = $wpdb->insert_id;

			$query            = 'INSERT INTO ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd (
                                                            rgm_id,
                                                            rgd_attribute,
                                                            rgd_value,
                                                            rgm_posted
                                                            )
                    VALUES 
                    ';
			$technical_fields = array();
			$values           = array();
			$title            = '';
			$first            = true;
			// Remove the protocol (http:// or https://) from the referring URL
			$referrer_without_protocol = null;
			if ( array_key_exists( 'HTTP_REFERER', $_SERVER ) ) {
				$referrer_without_protocol = preg_replace( '/^(https?:\/\/)/i', '', $_SERVER['HTTP_REFERER'] );
			}
			$technical_fields['from_site']    = $referrer_without_protocol;
			$technical_fields['post_on_site'] = $posted_site;
			$technical_fields['is_ajax']      = $ajax ? __( 'true', 'gdpr-compliant-recaptcha-for-all-forms' ) : __( 'false', 'gdpr-compliant-recaptcha-for-all-forms' );
			if ( $action ) {
				$technical_fields['action'] = $action;
			}
			if ( get_option( Option::POW_SAVE_IP ) ) {
				$technical_fields['IP adress'] = $this->get_client_ip();
			}
			// WHY this submission was classified as spam (null = clean → no row at all,
			// see Classification_Reason). Additive technical field, written like the
			// ones above with rgm_posted = false, so it never shows up as a "block this
			// pattern" candidate in the message UI. The leading underscore matters:
			// Echo_Values::is_technical_key() treats any `_`-prefixed key as technical,
			// so the reason can never itself seed or match an echo/wildcard value.
			if ( null !== $this->classification_reason ) {
				$technical_fields['_gdpr_reason'] = $this->classification_reason;
			}

			// WHAT THE STAMP TABLE HELD while the "no proof of work" verdict was made
			// (measure_pow_probe(); null on every other classification → no row at all).
			// The reason above names the path that failed, this names the evidence: a
			// row for the token that was too old, one that was spent, or none anywhere.
			// Same conventions as _gdpr_reason in every respect, including the leading
			// underscore that keeps Echo_Values::is_technical_key() from ever letting it
			// seed or match a value.
			if ( null !== $this->pow_probe ) {
				$technical_fields['_gdpr_pow_probe'] = $this->pow_probe;
			}

			// WHY this submission was NOT classified as spam (null = it was → no row at
			// all; the two are mutually exclusive, see $clean_scoring). Same conventions
			// as _gdpr_reason above in every respect: additive, rgm_posted = false, and
			// the leading underscore that makes Echo_Values::is_technical_key() treat it
			// as technical, so the scoring string can never itself seed or match an
			// echo/wildcard value.
			if ( null !== $this->clean_scoring ) {
				$technical_fields['_gdpr_scoring'] = $this->clean_scoring;
			}

			// WHICH REST route this submission targeted (REST_ROUTES_PLAN.md AP5), or no
			// row at all on a non-REST request — same convention as _gdpr_reason above:
			// additive, rgm_posted = false, leading underscore (Echo_Values::is_technical_key()
			// skips `_`-prefixed keys, so this can never itself seed or match an echo/
			// wildcard value), no schema change. Recorded for BOTH type-4 analysis rows
			// AND normally classified messages — analysis mode is precisely how an admin
			// discovers a REST route worth monitoring (Message_Page::render_message()'s
			// "Monitor this route" button reads this row).
			if ( null !== $this->get_rest_route() ) {
				$technical_fields['_gdpr_route'] = $this->get_rest_route();
			}

			foreach ( $fields as $key => $value ) {
				if ( is_array( $value ) || is_object( $value ) ) {
					$nested_values = $this->generate_paths( $my_id, $value, $key, $pre_forbidden_fields, $referrer_without_protocol, $query, $first, $custom_titles, $title );
					$values        = array_merge( $values, $nested_values[0] );
					$query         = $nested_values[1];
					$title         = $nested_values[2];
					$first         = $nested_values[3];
				} else {
					$skipped_field = false;
					if ( count( $pre_forbidden_fields ) ) {
						$skipped_field = $this->check_skipped_fields( $pre_forbidden_fields, $key, $referrer_without_protocol );
					}
					if ( ! $skipped_field ) {
						// rgm_posted false for a redacted value — see generate_paths().
						$values[] = $my_id;
						$values[] = $key;
						$values[] = $value;
						$values[] = Credential_Fields::REDACTED_VALUE !== $value;
						if ( isset( $custom_titles[ $key ] ) ) {
							$title .= $value . ' | ';
						}
						if ( $first ) {
							$first = false;
						} else {
							$query .= ',';
						}
						$query .= '(%d, %s, %s, %d)';
					}
				}
			}

			foreach ( $technical_fields as $key => $value ) {
				$values[] = $my_id;
				$values[] = $key;
				$values[] = $value;
				$values[] = false;
				if ( $first ) {
					$first = false;
				} else {
					$query .= ',';
				}
				$query .= '(%d, %s, %s, %d)';
			}

			if ( '' !== $title ) {
				$title = substr( $title, 0, -3 );
			}
			$wpdb->update( $table, array( 'rgm_title' => $title ), array( 'rgm_id' => $my_id ) );

			$wpdb->query(
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $query is an internally-built INSERT with only (%d,%s,%s,%d) placeholder tuples (never request data); it is passed through $wpdb->prepare() with $values here, i.e. de-facto prepared.
				$wpdb->prepare( $query, $values )
			);
			$wpdb->query( 'COMMIT' );

			return $my_id;
		}

		return null;
	}
}
