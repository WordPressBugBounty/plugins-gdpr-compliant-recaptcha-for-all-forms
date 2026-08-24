<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/messages.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Message_List: the read half of Message_Page — the message table itself
 * (search, pagination, the action bar), the queries behind it, and read-only rendering
 * helpers for the detail view (route_line(), 6.0.0). Nothing here writes.
 *
 * Schnittlinie und Begruendung fuer das Trait: siehe trait-message-actions.php.
 */
trait Message_List {
	/** Add the page for saved messages */
	public function render_messages() {
		$search;
		$message_type;
		$search_nonce;
		if ( ! (
				isset( $_POST['search'] )
				&& isset( $_POST['messageType'] )
				&& isset( $_POST['search_nonce'] )
				)
			) {
			$array_result = array(
				'success'       => 0,
				'error_message' => __( 'Multiple render action is invalid!', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
			wp_send_json( $array_result );
			exit;
		} else {

			$search       = sanitize_text_field( wp_unslash( $_POST['search'] ) );
			$message_type = filter_var( wp_unslash( $_POST['messageType'] ), FILTER_VALIDATE_INT );
			$search_nonce = filter_var( wp_unslash( $_POST['search_nonce'] ), FILTER_UNSAFE_RAW );
			// A nonce guards against CSRF but is not an authorisation check; this page
			// exposes captured submissions (incl. personal data), so require manage_options.
			if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $search_nonce, 'render-messages_' . $message_type ) ) {
				$array_result = array(
					'success'       => 0,
					'error_message' => __( 'Multiple render action is invalid!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				);
				wp_send_json( $array_result );
				exit;
			}
			$this->listed_actions    = isset( $_POST['listedActions'] ) ? filter_var( wp_unslash( $_POST['listedActions'] ), FILTER_VALIDATE_BOOLEAN ) : null;
			$this->listed_patterns   = isset( $_POST['listedPatterns'] ) ? filter_var( wp_unslash( $_POST['listedPatterns'] ), FILTER_VALIDATE_BOOLEAN ) : null;
			$this->whitelisted_sites = isset( $_POST['whitelistedSites'] ) ? filter_var( wp_unslash( $_POST['whitelistedSites'] ), FILTER_VALIDATE_BOOLEAN ) : null;
			$this->whitelisted_ips   = isset( $_POST['whitelistedIPs'] ) ? filter_var( wp_unslash( $_POST['whitelistedIPs'] ), FILTER_VALIDATE_BOOLEAN ) : null;
			$this->hidden_actions    = isset( $_POST['hiddenActions'] ) ? filter_var( wp_unslash( $_POST['hiddenActions'] ), FILTER_VALIDATE_BOOLEAN ) : null;
			$this->hidden_patterns   = isset( $_POST['hiddenPatterns'] ) ? filter_var( wp_unslash( $_POST['hiddenPatterns'] ), FILTER_VALIDATE_BOOLEAN ) : null;
		}

		$existing_actions_list  = get_option( Option::POW_EXPLICIT_ACTION );
		$existing_actions_lines = array_filter( preg_split( "/\r\n|\n|\r/", $existing_actions_list ) );

		$existing_patterns_list  = get_option( Option::POW_PARAMETER_PATTERN );
		$existing_patterns_lines = array_filter( preg_split( "/\r\n|\n|\r/", $existing_patterns_list ) );

		$existing_whitelist_sites_list  = get_option( Option::POW_SITE_WHITELIST );
		$existing_whitelist_sites_lines = array_filter( preg_split( "/\r\n|\n|\r/", $existing_whitelist_sites_list ) );

		$existing_whitelist_ips_list  = get_option( Option::POW_IP_WHITELIST );
		$existing_whitelist_ips_lines = preg_split( "/\r\n|\n|\r/", $existing_whitelist_ips_list );
		$existing_whitelist_ips_lines = array_map( array( 'VENDOR\RECAPTCHA_GDPR_COMPLIANT\Option', 'hash_values' ), $existing_whitelist_ips_lines );

		$hidden_actions_list  = get_option( Option::POW_HIDE_ACTION );
		$hidden_actions_lines = array_filter( preg_split( "/\r\n|\n|\r/", $hidden_actions_list ) );

		$hidden_patterns_list  = get_option( Option::POW_HIDE_PATTERN );
		$hidden_patterns_lines = array_filter( preg_split( "/\r\n|\n|\r/", $hidden_patterns_list ) );

		$rows     = Option::get_rows(
			$search,
			$message_type,
			false,
			4 === $message_type && $hidden_actions_list && ! $this->hidden_actions ? $hidden_actions_lines : array( '-' ),
			4 === $message_type && $existing_actions_list && ! $this->listed_actions ? $existing_actions_lines : array( '-' ),
			4 === $message_type && $existing_patterns_list && ! $this->listed_patterns ? $existing_patterns_lines : array(),
			4 === $message_type && $hidden_patterns_list && ! $this->hidden_patterns ? $hidden_patterns_lines : array()
		);
		$per_page = 25;
		$pages    = ceil( $rows / $per_page );

		$page = 1;
		if ( isset( $_POST['page'] ) ) {
			$page_raw = filter_var( $_POST['page'], FILTER_VALIDATE_INT, FILTER_NULL_ON_FAILURE );
			if ( $pages >= $page_raw && $page_raw > 0 ) {
				$page = $page_raw;
			}
		}

		$start    = ( $page - 1 ) * $per_page;
		$messages = $this->get_messages(
			$search,
			$message_type,
			$start,
			$per_page,
			4 === $message_type && $hidden_actions_list && ! $this->hidden_actions ? $hidden_actions_lines : array( '-' ),
			4 === $message_type && $existing_actions_list && ! $this->listed_actions ? $existing_actions_lines : array( '-' ),
			4 === $message_type && $existing_patterns_list && ! $this->listed_patterns ? $existing_patterns_lines : array(),
			4 === $message_type && $hidden_patterns_list && ! $this->hidden_patterns ? $hidden_patterns_lines : array(),
		);

		$html      = '';
		$paginator = $this->get_paginator( $rows, $page, $pages );
		$count     = 0;
		foreach ( $messages as $message ) {

			$rgm_id     = esc_attr( $message->rgm_id );
			$rgm_title  = esc_attr( $message->rgm_title );
			$rgm_date   = esc_attr( $message->rgm_date );
			$rgm_ajax   = esc_attr( $message->rgm_ajax );
			$rgm_action = esc_attr( $message->rgm_action );
			// Separate JS-string-safe escaping for the value emitted inside the
			// single-quoted argument of the inline onSubmit handlers below. esc_attr()
			// only encodes for the HTML-attribute layer; the browser HTML-decodes
			// &#039; back to ' before the JS engine parses the handler, so a quote in
			// rgm_action would break out of the JS string. esc_js() escapes the quote
			// for the JS-string context (CVE-2026-16145).
			$rgm_action_js = esc_js( $message->rgm_action );
			$rgm_ip        = esc_attr( $message->rgm_ip );
			$rgm_site      = esc_attr( $message->rgm_site );

			$message_details       = $this->get_message_details( $rgm_id, $message_type );
			$message_details_array = Option::convert_to_json_object( $message_details, 'rgd_attribute', 'rgd_value' );

			// Check, whether the whitelisting-parameter already exists. Compare the RAW
			// action against the raw option lines: $rgm_action is esc_attr()-encoded, so
			// an action containing & or ' (e.g. "a&b") would never match its own stored
			// line and the "Enhance spam check"/"Hide action" buttons would keep
			// reappearing after listing it.
			$rgm_action_raw   = trim( (string) $message->rgm_action );
			$action_listed    = '' !== $rgm_action_raw && in_array( $rgm_action_raw, $existing_actions_lines, true );
			$site_whitelisted = trim( $rgm_site ) && in_array( trim( $rgm_site ), $existing_whitelist_sites_lines, true );
			$ip_whitelisted   = trim( $rgm_ip ) && in_array( trim( $rgm_ip ), $existing_whitelist_ips_lines, true );
			$html            .= '
                <table id="resultTable">
                <col style="width:40px">
                <tr>
                <td class="check_message_col"> <input type="checkbox" name="check_message" class="check_message" id="check_message_' . $rgm_id . '" /></td>
                <td><button class="akkordeonButton" id="akkordeonButton_' . $rgm_id . '">
                            ' . $rgm_date . ' ' . $rgm_title . '
                </button>
                <div class="akkordeonEinheit">
                    <div id="messageDetails' . $rgm_id . '">
                    </div>
                    <input type="hidden" name="messageNonce" id="messageNonce' . $rgm_id . '" value="' . wp_create_nonce( 'get-detail-' . $rgm_id . $message_type ) . '" />
            ';
			$html            .= '<table><th>';
			if ( 1 !== $message_type && 4 !== $message_type ) {
				$html .= '
                        <td>
                        <form id="messageForm' . $rgm_id . '" onSubmit="moveMessage( event, \'messageForm\', ' . $rgm_id . ', 1 );">
                            <input type="hidden" name="messsageID" id="messsageID" value="' . $rgm_id . '" />
                            <input type="hidden" name="moveNonce" id="moveNonce" value="' . wp_create_nonce( 'move-message-' . $rgm_id . $message_type . '1' ) . '" />
                            <input type="submit" class="trashButton button-secondary" id="trashButton" name="trashButton" value="' . __( 'Move to Messages', 'gdpr-compliant-recaptcha-for-all-forms' ) . '" />
                        </form>
                        </td>
                ';
			}
			if ( 2 !== $message_type && 4 !== $message_type ) {
				$html .= '
                        <td>
                        <form id="spamForm' . $rgm_id . '" onSubmit="moveMessage( event, \'spamForm\', ' . $rgm_id . ', 2 );">
                            <input type="hidden" name="messsageID" id="messsageID" value="' . $rgm_id . '" />
                            <input type="hidden" name="moveNonce" id="moveNonce" value="' . wp_create_nonce( 'move-message-' . $rgm_id . $message_type . '2' ) . '" />
                            <input type="submit" class="trashButton button-secondary" id="trashButton" name="trashButton" value="' . __( 'Move to Spam', 'gdpr-compliant-recaptcha-for-all-forms' ) . '" />
                        </form>
                        </td>
                ';
			}
			if ( 3 !== $message_type && 4 !== $message_type ) {
				$html .= '
                        <td>
                        <form id="trashForm' . $rgm_id . '" onSubmit="moveMessage( event, \'trashForm\', ' . $rgm_id . ', 3 );">
                            <input type="hidden" name="messsageID" id="messsageID" value="' . $rgm_id . '" />
                            <input type="hidden" name="moveNonce" id="moveNonce" value="' . wp_create_nonce( 'move-message-' . $rgm_id . $message_type . '3' ) . '" />
                            <input type="submit" class="trashButton button-secondary" id="trashButton" name="trashButton" value="' . __( 'Move to Trash', 'gdpr-compliant-recaptcha-for-all-forms' ) . '" />
                        </form>
                        </td>
                ';
			}
			if ( $rgm_ajax && $rgm_action && ! $action_listed ) {
				$html .= '
                    <td>
                    <form id="whiteList' . $rgm_id . '" onSubmit="saveListParameter(event, \'' . $rgm_action_js . '\', \'list_Button_' . $rgm_id . '\', false);">
                        <input type="hidden" name="messsageID" id="messsageID" value="' . $rgm_id . '" />
                        <input type="submit" id="list_Button_' . $rgm_id . '" class="listButton button-primary" name="listButton" value="' . __( 'Enhance spam check on type of action', 'gdpr-compliant-recaptcha-for-all-forms' ) . '" />
                    </form>
                    </td>
                    <td>
                    <form id="hideList' . $rgm_id . '" onSubmit="saveListParameter(event, \'' . $rgm_action_js . '\', \'hide_Button_' . $rgm_id . '\', true);">
                        <input type="hidden" name="messsageID" id="messsageID" value="' . $rgm_id . '" />
                        <input type="submit" id="hide_Button_' . $rgm_id . '" class="hideButton button-primary" name="hideButton" value="' . __( 'Hide action', 'gdpr-compliant-recaptcha-for-all-forms' ) . '" />
                    </form>
                    </td>
                ';
			}
			if ( 4 === $message_type && ! $rgm_ajax ) {
				$html .= '
                    <td>
                    <form id="patternForm' . $rgm_id . '" onSubmit="savePattern(event, \'' . $rgm_id . '\', \'pattern_Button_' . $rgm_id . '\', false);">
                        <input type="hidden" name="messsageID" id="messsageID" value="' . $rgm_id . '" />
                        <input type="submit" id="pattern_Button_' . $rgm_id . '" class="patternButton button-primary" name="patternButton" value="' . __( 'Enhance spam check on type of submission', 'gdpr-compliant-recaptcha-for-all-forms' ) . '" />
                    </form>
                    </td>
                    <td>
                    <form id="hidePatternForm' . $rgm_id . '" onSubmit="savePattern(event, \'' . $rgm_id . '\', \'hide_Pattern_Button_' . $rgm_id . '\', true);">
                        <input type="hidden" name="messsageID" id="messsageID" value="' . $rgm_id . '" />
                        <input type="submit" id="hide_Pattern_Button_' . $rgm_id . '" class="hidePatternButton button-primary" name="hidePatternButton" value="' . __( 'Hide pattern', 'gdpr-compliant-recaptcha-for-all-forms' ) . '" />
                    </form>
                    </td>
                ';
			}
			if ( 3 === $message_type || 4 === $message_type ) {
				$html .= '
                        <td>
                        <form id="deleteForm' . $rgm_id . '" onSubmit="deleteSingleMessage( event, \'deleteForm\', ' . $rgm_id . ' );">
                            <input type="hidden" name="messsageID" id="messsageID" value="' . $rgm_id . '" />
                            <input type="hidden" name="deleteNonce" id="deleteNonce" value="' . wp_create_nonce( 'delete-message-' . $rgm_id . $message_type ) . '" />
                            <input type="submit" class="trashButton button-primary" id="trashButton" name="trashButton" value="' . __( 'Delete', 'gdpr-compliant-recaptcha-for-all-forms' ) . '" />
                        </form>
                        </td>
                ';
			}
			$html .= '</th></table>';
			$html .= '</div></td>
            </tr>
            </table>';
		}
		$array_result = array(
			'success'   => 1,
			'result'    => $html,
			'paginator' => $paginator,
		);

		wp_send_json( $array_result );
	}

	/* Show a request to evaluate the plugin if not yet shown*/
	private function show_evaluation_request( $message_type, $rows ) {
		// Firstly check the preconditions
		if ( 2 === $message_type // Are we on the spam page for spam messages?
			&& $rows > 10 // Is the number of spam messages greater than 10?
		) {

			$review_link     = '<a href="https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/reviews/#new-post">Help us and rate it</a>';
			$faq_link        = '<a href="' . Settings_Menu::SUPPORT_FORUM_URL . '">Get help in the support forum</a>';
			$line_break      = '<br>';
			$smiley          = '<span class="large-smiley">&#128578;</span>';
			$thinking_smiley = '<span class="large-smiley">&#129300;</span>';

			/* translators: %1$s: happy smiley icon, %2$s: review link, %3$s: line break, %4$s: thinking smiley icon, %5$s: support forum link. */
			$message            = __( '%1$s Happy with the plugin? %2$s %3$s %4$s Problems, questions, hints, improvements? %5$s', 'gdpr-compliant-recaptcha-for-all-forms' );
			$message_with_links = sprintf( $message, $smiley, $review_link, $line_break, $thinking_smiley, $faq_link );

			add_settings_error(
				Option::PREFIX . 'options',
				'my-plugin-success',
				$message_with_links,
				'info'
			);
			settings_errors( Option::PREFIX . 'options' );
		}
	}

	/* Returns the action bar*/
	private function get_action_bar( $message_type ) {
		?>
		<input type="checkbox" class="check_messages" />
		<select name="messageAction" id="messageAction">
			<option value="bulk"><?php esc_html_e( 'Bulk actions', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></option>
		<?php
		if ( 1 !== $message_type && 4 !== $message_type ) {
			?>
			<option value="messageForm_1"><?php esc_html_e( 'Move to Messages', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></option>
			<?php
		}
		if ( 2 !== $message_type && 4 !== $message_type ) {
			?>
			<option value="spamForm_2"><?php esc_html_e( 'Move to Spam', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></option>
			<?php
		}
		if ( 3 !== $message_type && 4 !== $message_type ) {
			?>
			<option value="trashForm_3"><?php esc_html_e( 'Move to Trash', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></option>
			<?php
		}
		if ( 3 === $message_type || 4 === $message_type ) {
			?>
			<option value="deleteForm"><?php esc_html_e( 'Delete', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></option>
			<?php
		}
		?>
		</select>
		<input type="button" class="ApplyButton button button-primary" id="ApplyButton" name="ApplyButton" value="<?php esc_attr_e( 'Apply', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>" onClick="doMessageAction(event);" />
		<input type="button" class="DeleteAllButton button button-primary" id="DeleteAllButton" name="DeleteAllButton" value="<?php esc_attr_e( 'Delete all', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>" onClick="doDeleteAll(event);" />
		<?php esc_html_e( 'Search', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>: <input type="text" class="messageSearch" name="messageSearch" />
		<?php
	}

	/* Returns a paginator*/
	private function get_paginator( $rows, $page, $pages ) {
		$html  = $rows . ' ' . __( 'messages', 'gdpr-compliant-recaptcha-for-all-forms' ) . ' ';
		$html .= '<input type="button" onClick="messageSearch(1);" value="<<" ' . ( $page > 1 ? '' : 'disabled ' ) . '/>';
		$html .= '<input type="button" onClick="messageSearch( ' . ( ( $page - 1 ) < 1 ? 1 : ( $page - 1 ) ) . ' );" value="<" ' . ( $page > 1 ? '' : 'disabled ' ) . '/>';
		$html .= ' ' . $page . ' ' . __( 'out of', 'gdpr-compliant-recaptcha-for-all-forms' ) . ' ' . $pages . ' ';
		$html .= '<input type="button" onClick="messageSearch( ' . ( ( $page + 1 ) > $pages ? $pages : ( $page + 1 ) ) . ' );" value=">" ' . ( $page < $pages ? '' : 'disabled ' ) . '/>';
		$html .= '<input type="button" onClick="messageSearch(' . $pages . ');" value=">>" ' . ( $page < $pages ? '' : 'disabled ' ) . '/>';
		return $html;
	}

	/**Get all messages */
	private function get_messages( $search, $message_type, $start, $pages, $hidden_actions = array( '-' ), $existing_actions = array( '-' ), $existing_patterns = array(), $hidden_patterns = array() ) {
		global $wpdb;

		$hidden_actions_placeholders   = implode( ', ', array_fill( 0, count( $hidden_actions ), '%s' ) );
		$existing_actions_placeholders = implode( ', ', array_fill( 0, count( $existing_actions ), '%s' ) );
		$parameters                    = array_merge(
			array( $message_type ),
			$hidden_actions,
			$existing_actions,
			array( $search, $search, $start, $pages )
		);
		$sql_array                     = array();
		//For each pattern build a sub-select to check whether the conditions match
		foreach ( $existing_patterns as $pattern ) {
			$decoded_pattern = json_decode( $pattern, true );
			if ( ! is_array( $decoded_pattern ) ) {
				// Not valid JSON (e.g. a stray textarea edit predating the save-time
				// guard) -- skip this line rather than build a sub-select with an empty
				// OR-list ("WHERE  GROUP BY", a SQL syntax error). Same guard as
				// Option::get_rows() above/below this call; generate_paths() itself now
				// also tolerates a non-array/object $data, this just avoids the broken
				// SQL fragment in the first place.
				continue;
			}
			$pattern    = Option::generate_paths( $decoded_pattern, '' );
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
			$pattern    = Option::generate_paths( $decoded_pattern, '' );
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

		$query = 'SELECT DISTINCT rgm.*
        FROM ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm rgm
        JOIN ' . $wpdb->prefix . "recaptcha_gdpr_details_rgd rgd
          ON rgm.rgm_id = rgd.rgm_id
        WHERE rgm.rgm_type = %d
          AND COALESCE(rgm.rgm_action, '') NOT IN ($hidden_actions_placeholders)
          AND COALESCE(rgm.rgm_action, '') NOT IN ($existing_actions_placeholders)
          AND ( rgd.rgd_attribute LIKE CONCAT('%',%s,'%')
                OR rgd.rgd_value LIKE CONCAT('%',%s,'%')
              )
          " . implode( '', $sql_array ) . implode( '', $hidden_sql_array ) . '
        ORDER BY rgm.rgm_date DESC
        LIMIT %d, %d';

		$prepared_query = call_user_func_array( array( $wpdb, 'prepare' ), array_merge( array( $query ), $parameters ) );

		// Anfrage ausführen,
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $prepared_query is the result of $wpdb->prepare() (invoked via call_user_func_array with dynamic placeholder count).
		$results = $wpdb->get_results( $prepared_query );
		return $results;
	}

	/**Get all message details */
	private function get_message_details( $message_id, $message_type ) {
		global $wpdb;
		// Anfrage ausführen
		$results = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT rgm.rgm_ajax, rgd.*
                            FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd rgd
                            JOIN ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm rgm
                              ON rgm.rgm_id = rgd.rgm_id
                            WHERE rgd.rgm_id = %d
                              AND rgm.rgm_type = %d
                           ',
				$message_id,
				$message_type
			)
		);

		return $results;
	}

	/**
	 * The "REST route:" line above the field table.
	 *
	 * WHY IT SAYS WHETHER THE ROUTE IS WATCHED. The line reports how the submission
	 * technically arrived — which is NOT the same as what brought it in for checking,
	 * and reads like a statement about protection when it is not. An operator seeing
	 * `contact-form-7/v1/contact-forms/121/feedback` here while his site watches the
	 * `{"_wpcf7":null}` pattern has no way to tell which of the two is doing the work
	 * (owner, 2026-08-24 — it took two rounds of questions to resolve, so the answer
	 * belongs on the line itself).
	 *
	 * THE WORDING IS TYPE-DEPENDENT, and that is not cosmetic. For a normal message
	 * (types 1-3) "recognised another way" is always true: it exists only because some
	 * term brought it in — a pattern, an action, the blocklist, the login path. An
	 * ANALYSIS row (type 4) is different: save_for_analysis() records BEFORE the gate,
	 * deliberately including requests no signature matched at all. Telling that
	 * operator his submission "was recognised another way" would be plainly false, and
	 * those rows are exactly the ones people click this button on.
	 *
	 * THE BUTTON IS ONLY OFFERED WHEN IT WOULD ADD SOMETHING. Note what the reason is
	 * NOT: monitor_route_callback() rejects only an EXACT duplicate line
	 * (`trim( $existing_line ) === $route`), so a route already covered by a wildcard
	 * would have been accepted and appended as a redundant line. The old button was
	 * therefore not a refused dead end but a quiet way to litter the route list; the
	 * matching is an OR over lines, so nobody loses coverage by its absence, and anyone
	 * who wants the concrete line anyway has the textarea.
	 *
	 * @param string     $route        The route this message arrived on.
	 * @param int|string $message_type The list being viewed; 4 is the analysis view.
	 * @return string HTML.
	 */
	private static function route_line( $route, $message_type ) {
		$watched = RestRoute::matches( $route, (string) get_option( Option::POW_REST_ROUTES ) );
		$html    = '<p class="gdpr-route-line">'
			. esc_html__( 'REST route:', 'gdpr-compliant-recaptcha-for-all-forms' )
			. ' <code>' . esc_html( $route ) . '</code> ';
		if ( $watched ) {
			return $html . '<span class="gdpr-route-watched">'
				. esc_html__( '— this route is monitored', 'gdpr-compliant-recaptcha-for-all-forms' )
				. '</span></p>';
		}
		$note = 4 === (int) $message_type
			? esc_html__( '— not monitored', 'gdpr-compliant-recaptcha-for-all-forms' )
			: esc_html__( '— not monitored; this submission was recognised another way', 'gdpr-compliant-recaptcha-for-all-forms' );
		return $html . '<span class="gdpr-route-unwatched">' . $note . '</span>'
			. ' <button type="button" class="gdpr-monitor-route-btn" data-route="' . esc_attr( $route ) . '" onclick="monitorRoute(this)">'
			. esc_html__( 'Monitor this route', 'gdpr-compliant-recaptcha-for-all-forms' )
			. '</button></p>';
	}
}
