<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Class Message_Page: Reflects the module for the administration of messages
 */

class Message_Page {

	private $listed_actions    = null;
	private $listed_patterns   = null;
	private $whitelisted_sites = null;
	private $whitelisted_ips   = null;
	private $hidden_actions    = null;
	private $hidden_patterns   = null;

	/** Constructor of the class
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'run' ) );
		add_action( 'wp_ajax_render_messages', array( $this, 'render_messages' ) );
		add_action( 'wp_ajax_render_message', array( $this, 'render_message' ) );
		add_action( 'wp_ajax_change_message_type', array( $this, 'change_message_type' ) );
		add_action( 'wp_ajax_delete_message', array( $this, 'delete_message' ) );
		add_action( 'wp_ajax_save_list_parameter', array( $this, 'save_list_parameter_callback' ) );
		add_action( 'wp_ajax_save_pattern', array( $this, 'save_pattern_callback' ) );
		add_action( 'wp_ajax_gdpr_block_value', array( $this, 'block_value_callback' ) );
	}


	/** Wenn the plugin is run
	 */
	public function run() {
		add_action( 'admin_init', array( $this, 'admin_init' ) );
		add_action( 'admin_menu', array( $this, 'admin_menu' ) );
	}

	/** Initialize the admin area*/
	public function admin_init() {
		//Registers the stly for the message_page but don't enqueue it yet
		wp_register_style( 'messagePageStyle', plugins_url( '/css/style_message_page.css', __DIR__ ), array(), '1.0.2' );
	}

	/** Add the admin menu for messages
	 *
	 */
	public function admin_menu() {
		$main_menu_entry     = __( 'ReCaptcha GDPR Messages', 'gdpr-compliant-recaptcha-for-all-forms' );
		$messages_menu_entry = __( 'Messages', 'gdpr-compliant-recaptcha-for-all-forms' );
		$spam_menu_entry     = __( 'Spam', 'gdpr-compliant-recaptcha-for-all-forms' );
		$trash_menu_entry    = __( 'Trash', 'gdpr-compliant-recaptcha-for-all-forms' );
		$analyse_menu_entry  = __( 'Analytic Box', 'gdpr-compliant-recaptcha-for-all-forms' );

		$messages_count = Option::get_rows( '', 1 );
		$spam_count     = Option::get_rows( '', 2 );
		$trash_count    = Option::get_rows( '', 3 );
		$analyse_count  = Option::get_rows( '', 4 );
		$overall_count  = $messages_count + $spam_count + $trash_count + $analyse_count;

		// phpcs:ignore Universal.Operators.StrictComparisons.LooseNotEqual -- get_option() may return the stored value as a string ("-1") or int; loose comparison is intentional to keep existing behavior.
		if ( get_option( Option::POW_MENU_POSITION ) != -1 ) {

			$page = add_menu_page(
				$main_menu_entry,
				$main_menu_entry . $this->entry_counter( $overall_count ),
				'manage_options',
				Option::PREFIX . 'messages',
				array( $this, 'message_page' ),
				'dashicons-email-alt2',
				get_option( Option::POW_MENU_POSITION ) ? get_option( Option::POW_MENU_POSITION ) : 0
			);
			add_action( "admin_print_styles-{$page}", array( $this, 'message_page_styles' ) );

			$page = add_submenu_page(
				Option::PREFIX . 'messages',
				$messages_menu_entry,
				$messages_menu_entry . $this->entry_counter( $messages_count ),
				'manage_options',
				Option::PREFIX . 'messages',
				array( $this, 'message_page' )
			);
			add_action( "admin_print_styles-{$page}", array( $this, 'message_page_styles' ) );

			$page = add_submenu_page(
				Option::PREFIX . 'messages',
				$spam_menu_entry,
				$spam_menu_entry . $this->entry_counter( $spam_count ),
				'manage_options',
				Option::PREFIX . 'spam',
				array( $this, 'spam_page' )
			);
			add_action( "admin_print_styles-{$page}", array( $this, 'message_page_styles' ) );

			$page = add_submenu_page(
				Option::PREFIX . 'messages',
				$trash_menu_entry,
				$trash_menu_entry . $this->entry_counter( $trash_count ),
				'manage_options',
				Option::PREFIX . 'trash',
				array( $this, 'trash_page' )
			);
			add_action( "admin_print_styles-{$page}", array( $this, 'message_page_styles' ) );

			$page = add_submenu_page(
				Option::PREFIX . 'messages',
				$analyse_menu_entry,
				$analyse_menu_entry . $this->entry_counter( $analyse_count ),
				'manage_options',
				Option::PREFIX . 'analyse',
				array( $this, 'analyse_page' )
			);
			add_action( "admin_print_styles-{$page}", array( $this, 'message_page_styles' ) );

		}
	}

	/** Renders the bubble counter for a menu entry */
	private function entry_counter( $counter ) {
		return '<span class="update-plugins count-' . $counter . '"><span class="plugin-count">' . $counter . '</span></span>';
	}

	/**Add style only for message page */
	public function message_page_styles() {
		wp_enqueue_style( 'messagePageStyle' );
	}

	/*Initialize message_page*/
	public function message_page() {
		$this->render_message_page( 1 );
	}

	/*Initialize spam_page*/
	public function spam_page() {
		$this->render_message_page( 2 );
	}

	/*Initialize trash_page*/
	public function trash_page() {
		$this->render_message_page( 3 );
	}

	/*Initialize analyse_page*/
	public function analyse_page() {
		$this->render_message_page( 4 );
	}

	/** Add the page for saved messages */
	public function render_message_page( $message_type ) {
		$titles = array(
			1 => __( 'Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
			2 => __( 'Spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
			3 => __( 'Trash', 'gdpr-compliant-recaptcha-for-all-forms' ),
			4 => __( 'Analytic Box', 'gdpr-compliant-recaptcha-for-all-forms' ),
		);
		$search = null;
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- capability-gated admin page load (manage_options); read-only display filter, no state change.
		if ( array_key_exists( 'search', $_POST ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- see above; sanitized read of the search term for listing only.
			$search = sanitize_text_field( wp_unslash( $_POST['search'] ) );
		}
		$rows = Option::get_rows( $search, $message_type );
		$this->show_evaluation_request( $message_type, $rows );
		?>
		<h1><?php echo esc_html( $titles[ $message_type ] ); ?></h1>
		<div class="centered-spinner" hidden>
				<center>
					<strong><?php esc_html_e( 'Loading', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>...</strong><br><br>
					<img src="/wp-includes/js/tinymce/skins/lightgray/img/loader.gif" alt="<?php esc_attr_e( 'Loading', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>">
				</center>
		</div>
		<?php
		if ( 4 === $message_type ) {
			?>
			<div class="filter">
				<div class="filter_head">
					<label>    
					<h3>Filters</h3>
					Show messages that are already in scope of specific rules</label>
				</div><br>
				<div class="filter_checkboxes">
					<label>
						<input type="checkbox" id="listedActions" onchange="messageSearch(1);">
						<?php
						/* translators: %s: emoji icon markup representing the filter. */
						echo wp_kses_post( sprintf( __( 'Explicit actions %s', 'gdpr-compliant-recaptcha-for-all-forms' ), '<label style="font-size: 30px;"><b>⚙️✔️</b></label>' ) );
						?>
					</label>
					<label>
						<input type="checkbox" id="listedPatterns" onchange="messageSearch(1);">
						<?php
						/* translators: %s: emoji icon markup representing the filter. */
						echo wp_kses_post( sprintf( __( 'Explicit patterns %s', 'gdpr-compliant-recaptcha-for-all-forms' ), '<label style="font-size: 30px;"><b>🔍✔️</b></label>' ) );
						?>
					</label>
					<label>
						<input type="checkbox" id="whitelistedSites" onchange="messageSearch(1);">
						<?php
						/* translators: %s: emoji icon markup representing the filter. */
						echo wp_kses_post( sprintf( __( 'Whitelisted sites %s', 'gdpr-compliant-recaptcha-for-all-forms' ), '<label style="font-size: 30px;"><b>📄</b></label>' ) );
						?>
					</label>
					<label>
						<input type="checkbox" id="whitelistedIPs" onchange="messageSearch(1);">
						<?php
						/* translators: %s: emoji icon markup representing the filter. */
						echo wp_kses_post( sprintf( __( 'Whitelisted IPs %s', 'gdpr-compliant-recaptcha-for-all-forms' ), '<label style="font-size: 30px;"><b>🌐</b></label>' ) );
						?>
					</label>
					<label>
						<input type="checkbox" id="hiddenActions" onchange="messageSearch(1);">
						<?php
						/* translators: %s: emoji icon markup representing the filter. */
						echo wp_kses_post( sprintf( __( 'Hidden actions %s', 'gdpr-compliant-recaptcha-for-all-forms' ), '<label style="font-size: 30px;"><b>⚙️🚫</b></label>' ) );
						?>
					</label>
					<label>
						<input type="checkbox" id="hiddenPatterns" onchange="messageSearch(1);">
						<?php
						/* translators: %s: emoji icon markup representing the filter. */
						echo wp_kses_post( sprintf( __( 'Hidden patterns %s', 'gdpr-compliant-recaptcha-for-all-forms' ), '<label style="font-size: 30px;"><b>🔍🚫</b></label>' ) );
						?>
					</label>
					<br>
				</div>
			</div><br>
			<?php
		}
		?>
		<div class="action_bar">
			<?php $this->get_action_bar( $message_type ); ?>
		</div>
		<div class = "paginator"></div>
		<br><div id="results"></div><br>
		<div class = "paginator"></div>
		<?php
		wp_enqueue_script(
			'gdpr-recaptcha-messages',
			plugins_url( '/scripts/recaptcha-gdpr-messages.js', __DIR__ ),
			array(),
			RCM_Main::VERSION,
			true
		);
		wp_localize_script(
			'gdpr-recaptcha-messages',
			'gdprMsg',
			array(
				'ajaxUrl'     => admin_url( 'admin-ajax.php' ),
				'messageType' => (string) $message_type,
				'nonces'      => array(
					'search'      => wp_create_nonce( 'render-messages_' . $message_type ),
					'saveList'    => wp_create_nonce( 'save_list_nonce_' . $message_type ),
					'savePattern' => wp_create_nonce( 'save_pattern_nonce_' . $message_type ),
					'blockValue'  => wp_create_nonce( 'block_value_nonce_' . $message_type ),
				),
				'i18n'        => array(
					// NB: sprintf( __( … ), $title ) — translate the template, then fill in.
					'confirmDeleteAll' => sprintf(
						/* translators: %s: inbox/spam/trash title. */
						__( 'You are about to delete all messages from "%s". Are you sure?', 'gdpr-compliant-recaptcha-for-all-forms' ),
						$titles[ $message_type ]
					),
					'moved'            => __( 'Message moved successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'deleted'          => __( 'Message deleted successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'actionAdded'      => __( 'Action added successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'whitelisted'      => __( 'Whitelisting successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'patternSaved'     => __( 'Pattern saved successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'choosePattern'    => __( 'Please choose the message attributes which you want to save as pattern!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'blocked'          => __( 'Blocked successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'blockFailed'      => __( 'Could not block this value.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				),
			)
		);
	}

	public function render_message() {
		$message_type;
		$message_id;
		$message_nonce;
		if ( ! (
				isset( $_POST['messageID'] )
				&& isset( $_POST['messageType'] )
				&& isset( $_POST['message_nonce'] )
				)
		) {
			$array_result = array(
				'success'       => 0,
				'error_message' => __( 'Render action is invalid!', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
			wp_send_json( $array_result );
			exit;
		} else {
			$message_type  = filter_var( $_POST['messageType'], FILTER_SANITIZE_NUMBER_INT );
			$message_id    = filter_var( $_POST['messageID'], FILTER_SANITIZE_NUMBER_INT );
			$message_nonce = filter_var( $_POST['message_nonce'], FILTER_UNSAFE_RAW );
			if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $message_nonce, 'get-detail-' . $message_id . $message_type ) ) {
				$array_result = array(
					'success'       => 0,
					'error_message' => __( 'Render action is invalid!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				);
				wp_send_json( $array_result );
				exit;
			}
		}
		$details  = $this->get_message_details( $message_id, $message_type );
		$rgm_ajax = false;
		if ( isset( $details[0] ) ) {
			$rgm_ajax = esc_attr( $details[0]->rgm_ajax );
		}
		// Classification reason (technical row `_gdpr_reason`, written by
		// Stamp::save_message() for spam-classified messages only). It is rendered once,
		// as a labelled badge above the table — so the raw row is skipped in the loop
		// below. Deliberately a carve-out for this one attribute: every other technical
		// field (from_site/post_on_site/is_ajax, the type-4 analysis fields) keeps
		// rendering as a plain row exactly as before.
		$reason_value = null;
		foreach ( $details as $detail ) {
			if ( '_gdpr_reason' === $detail->rgd_attribute ) {
				$reason_value = (string) $detail->rgd_value;
				break;
			}
		}

		$html_details = '';
		if ( null !== $reason_value ) {
			$html_details .= '<p class="gdpr-reason-line">'
				. esc_html__( 'Blocked because:', 'gdpr-compliant-recaptcha-for-all-forms' )
				. ' <span class="gdpr-reason-badge">'
				. esc_html( Classification_Reason::label( $reason_value ) )
				. '</span></p>';
		}
		$html_details .= '
            <table class="widefat striped message">
                <thead>
                    <tr class="table-header">
        ';
		// phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual -- $message_type is a sanitized numeric string (FILTER_SANITIZE_NUMBER_INT); loose comparison intentional.
		if ( 4 == $message_type && ! $rgm_ajax ) {
			$html_details .= '<th>' . __( 'Choose<br> pattern', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</th>';
		}
		$html_details .= '<th>' . __( 'Field', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</th>';
		// phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual -- $message_type is a sanitized numeric string (FILTER_SANITIZE_NUMBER_INT); loose comparison intentional.
		if ( 4 == $message_type && ! $rgm_ajax ) {
			$html_details .= '<th>' . __( 'Choose<br> pattern', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</th>';
		}
		$html_details .= '
                        <th>' . __( 'Value', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</th>
                    </tr>
                </thead>
                <tbody>
        ';
		// Own registrable domain(s), so the one-click "Block this domain" button is
		// never offered for the site's own referrer/page URL (self-DoS guard).
		$own_domains = Echo_Store::site_domains();
		//Set the details page for each message
		foreach ( $details as $detail ) {
			// Already shown as the badge above — do not repeat it as a raw row.
			if ( '_gdpr_reason' === $detail->rgd_attribute ) {
				continue;
			}
			$html_details .= '<tr class="table-body">';
			// phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual -- $message_type is a sanitized numeric string (FILTER_SANITIZE_NUMBER_INT); loose comparison intentional.
			if ( 4 == $message_type && ! $rgm_ajax ) {
				if ( $detail->rgm_posted ) {
					$html_details .= '<td class="check_returnAttribute_' . $message_id . '"> <input type="checkbox" value="' . esc_attr( $detail->rgd_attribute ) . '" onchange="document.getElementById(\'check_return_value_' . $message_id . '_' . $detail->rgd_id . '\').checked *= this.checked" name="check_return_attribute" peer="check_return_value_' . $message_id . '_' . $detail->rgd_id . '" class="check_return_attribute_' . $message_id . '" id="check_return_attribute_' . $message_id . '_' . $detail->rgd_id . '" /></td>';
				} else {
					$html_details .= '<td class="check_returnAttribute_' . $message_id . '"> </td>';
				}
			}
			$html_details .= '<td class="returnAttribute">' . esc_attr( $detail->rgd_attribute ) . ':</td>';
			// phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual -- $message_type is a sanitized numeric string (FILTER_SANITIZE_NUMBER_INT); loose comparison intentional.
			if ( 4 == $message_type && ! $rgm_ajax ) {
				if ( $detail->rgm_posted ) {
					$html_details .= '<td class="check_returnValue_' . $message_id . '"> <input type="checkbox" value="' . esc_attr( $detail->rgd_value ) . '" onchange="document.getElementById(\'check_return_attribute_' . $message_id . '_' . $detail->rgd_id . '\').checked += this.checked " name="check_return_value" class="check_return_value_' . $message_id . '" id="check_return_value_' . $message_id . '_' . $detail->rgd_id . '" /></td>';
				} else {
					$html_details .= '<td class="check_returnValue_' . $message_id . '"> </td>';
				}
			}
			$html_details .= '<td class="returnAttribute">' . esc_attr( $detail->rgd_value );
			// One-click block buttons (BACKLOG baustein 2), only for user-posted
			// content fields (rgm_posted) outside the analysis view — never for the
			// technical from_site/post_on_site rows carrying the site's own URL.
			// ($message_type is a sanitized numeric string, FILTER_SANITIZE_NUMBER_INT.)
			if ( 4 !== (int) $message_type && $detail->rgm_posted ) {
				$value = (string) $detail->rgd_value;
				$email = Echo_Values::extract_email( $value );
				if ( null !== $email ) {
					$html_details .= ' <button type="button" class="gdpr-block-btn" data-kind="sender" data-value="' . esc_attr( $email ) . '" onclick="blockValue(this)">' . esc_html__( 'Block this sender', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</button>';
				}
				$domain_to_block = null;
				foreach ( Echo_Values::extract_urls( $value ) as $url ) {
					$candidate = Echo_Values::registrable_domain( $url, $own_domains );
					if ( null !== $candidate ) {
						$domain_to_block = $candidate;
						break;
					}
				}
				if ( null !== $domain_to_block ) {
					$html_details .= ' <button type="button" class="gdpr-block-btn" data-kind="domain" data-value="' . esc_attr( $domain_to_block ) . '" onclick="blockValue(this)">' . esc_html__( 'Block this domain', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</button>';
				}
			}
			$html_details .= '</td>
                </tr>';
		}
		$html_details .= '</tbody></table>';
		$array_result  = array(
			'success' => 1,
			'result'  => $html_details,
		);

		wp_send_json( $array_result );
	}

	/** List Ajax-Action*/
	public function save_list_parameter_callback() {

		// Check capability + security nonce. Editing the explicit-actions / hide lists
		// writes plugin configuration, so require manage_options (consistent with
		// block_value_callback and save_pattern_callback), not merely the edit_pages
		// the admin page is rendered under.
		$message_type   = filter_var( isset( $_POST['messageType'] ) ? wp_unslash( $_POST['messageType'] ) : '', FILTER_VALIDATE_INT );
		$security_nonce = isset( $_POST['security_nonce'] ) ? filter_var( wp_unslash( $_POST['security_nonce'] ), FILTER_UNSAFE_RAW ) : '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $security_nonce, 'save_list_nonce_' . $message_type ) ) {
			$array_result = array(
				'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
			wp_send_json_error( $array_result );
			exit;
		}

		// Get whitelisting parameters
		$list_key = isset( $_POST['listKey'] ) ? sanitize_text_field( wp_unslash( $_POST['listKey'] ) ) : '';
		// Sanitize the boolean using filter_var()
		$hide = isset( $_POST['hide'] ) ? filter_var( wp_unslash( $_POST['hide'] ), FILTER_VALIDATE_BOOLEAN ) : false;

		$existing_option = null;
		if ( $hide ) {
			$existing_option = get_option( Option::POW_HIDE_ACTION );
		} else {
			$existing_option = get_option( Option::POW_EXPLICIT_ACTION );
		}

		$existing_lines = preg_split( "/\r\n|\n|\r/", $existing_option );

		// Check, whether the listing-parameter already exists
		if ( ! in_array( $list_key, $existing_lines, true ) ) {
			// If not add the new parameter
			$existing_lines[] = $list_key;

			// Transform to String again
			$updated_option = implode( "\n", $existing_lines );

			// Save the option
			if ( $hide ) {
				update_option( Option::POW_HIDE_ACTION, $updated_option );
			} else {
				update_option( Option::POW_EXPLICIT_ACTION, $updated_option );
			}
			$this->render_messages();
		} else {
			// Whitelisting parametert already in place
			wp_send_json_error( array( 'error_message' => __( 'Ajax-action already listed.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		exit;
	}

	/** Save Pattern*/
	public function save_pattern_callback() {

		// Check capability + security nonce. Managing spam patterns writes plugin
		// configuration, so require manage_options (not merely the edit_pages the
		// admin page is rendered under) — this narrows the SQLi attack surface from
		// Editor+ to admins (CVE-2026-16094 / CVE-2026-16146, defense in depth on top
		// of the esc_sql() at the LIKE sinks in Option::get_rows()/get_messages()).
		$message_type   = filter_var( isset( $_POST['messageType'] ) ? wp_unslash( $_POST['messageType'] ) : '', FILTER_VALIDATE_INT );
		$security_nonce = isset( $_POST['security_nonce'] ) ? filter_var( wp_unslash( $_POST['security_nonce'] ), FILTER_UNSAFE_RAW ) : '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $security_nonce, 'save_pattern_nonce_' . $message_type ) ) {
			$array_result = array(
				'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
			wp_send_json_error( $array_result );
			exit;
		}

		// Get whitelisting parameters. wp_unslash() reverses WordPress' magic-quote
		// slashing so the stored JSON pattern stays valid; sanitize_text_field()
		// cleans it. The SQL safety itself is enforced at the LIKE sinks via esc_sql().
		$pattern = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';
		$hide    = isset( $_POST['hide'] ) ? filter_var( wp_unslash( $_POST['hide'] ), FILTER_VALIDATE_BOOLEAN ) : false;

		$existing_option = null;
		if ( $hide ) {
			$existing_option = get_option( Option::POW_HIDE_PATTERN );
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
			if ( $hide ) {
				update_option( Option::POW_HIDE_PATTERN, $updated_option );
			} else {
				update_option( Option::POW_PARAMETER_PATTERN, $updated_option );
			}
			$this->render_messages();
		} else {
			// Pattern already in place
			wp_send_json_error( array( 'error_message' => __( 'Pattern already exists.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		exit;
	}

	/**
	 * One-click "Block this sender"/"Block this domain" (BACKLOG baustein 2): append
	 * a wildcard value line {"*":"value"} to POW_PARAMETER_PATTERN. Capability-gated
	 * (manage_options) + nonce. CRITICAL self-DoS guard: refuses to block a value on
	 * the site's own registrable domain.
	 */
	public function block_value_callback() {
		$message_type   = filter_var( isset( $_POST['messageType'] ) ? wp_unslash( $_POST['messageType'] ) : '', FILTER_VALIDATE_INT );
		$security_nonce = isset( $_POST['security_nonce'] ) ? filter_var( wp_unslash( $_POST['security_nonce'] ), FILTER_UNSAFE_RAW ) : '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $security_nonce, 'block_value_nonce_' . $message_type ) ) {
			wp_send_json_error( array( 'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
			exit;
		}

		$kind        = isset( $_POST['kind'] ) ? sanitize_text_field( wp_unslash( $_POST['kind'] ) ) : '';
		$raw         = isset( $_POST['value'] ) ? sanitize_text_field( wp_unslash( $_POST['value'] ) ) : '';
		$own_domains = Echo_Store::site_domains();
		$value       = null;

		if ( 'sender' === $kind ) {
			$email = Echo_Values::extract_email( $raw );
			if ( null === $email ) {
				wp_send_json_error( array( 'error_message' => __( 'No valid sender address found.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
				exit;
			}
			// Self-DoS guard: refuse an address on the site's own domain.
			$at            = strrpos( $email, '@' );
			$sender_domain = false !== $at ? Echo_Values::registrable_domain( substr( $email, $at + 1 ), array() ) : null;
			if ( null !== $sender_domain && in_array( $sender_domain, $own_domains, true ) ) {
				wp_send_json_error( array( 'error_message' => __( 'Refusing to block an address on your own domain.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
				exit;
			}
			$value = $email;
		} elseif ( 'domain' === $kind ) {
			// registrable_domain() returns null for the own domain(s), an IP, or a
			// non-domain — the same self-DoS guard, plus input validation.
			$value = Echo_Values::registrable_domain( $raw, $own_domains );
			if ( null === $value ) {
				wp_send_json_error( array( 'error_message' => __( 'Cannot block this value (empty, an IP address, or your own domain).', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
				exit;
			}
		} else {
			wp_send_json_error( array( 'error_message' => __( 'Invalid block request.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
			exit;
		}

		$line     = (string) wp_json_encode( array( '*' => $value ) );
		$existing = (string) get_option( Option::POW_PARAMETER_PATTERN );
		$lines    = '' === trim( $existing ) ? array() : preg_split( "/\r\n|\n|\r/", $existing, -1, PREG_SPLIT_NO_EMPTY );

		foreach ( $lines as $existing_line ) {
			if ( trim( $existing_line ) === $line ) {
				wp_send_json_error( array( 'error_message' => __( 'This value is already blocked.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
				exit;
			}
		}

		$lines[] = $line;
		update_option( Option::POW_PARAMETER_PATTERN, implode( "\n", $lines ) );
		wp_send_json_success(
			array(
				'message' => __( 'Blocked successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'value'   => $value,
			)
		);
		exit;
	}

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
			$faq_link        = '<a href="https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/">Get help in the support forum</a>';
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
			$pattern    = Option::generate_paths( json_decode( $pattern, true ), '' );
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
			$pattern    = Option::generate_paths( json_decode( $pattern, true ), '' );
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

	/**Delete message*/
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- WordPress ajax callback (wp_ajax_delete_message) signature; $messages is unused because the payload is read from $_POST.
	public function delete_message( $messages ) {
		if ( ! (
				isset( $_POST['search'] )
				&& isset( $_POST['search_nonce'] )
				&& isset( $_POST['messageType'] )
				)
			) {
			$array_result = array(
				'success'       => 0,
				'error_message' => __( 'Delete action is invalid!', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
			wp_send_json( $array_result );
			exit;
		}

		global $wpdb;
		$message;
		$message_type   = filter_var( wp_unslash( $_POST['messageType'] ), FILTER_VALIDATE_INT );
		$security_nonce = filter_var( wp_unslash( $_POST['search_nonce'] ), FILTER_UNSAFE_RAW );

		// Authorisation + CSRF gate BEFORE any DELETE. The "delete all" branch below
		// runs whenever $_POST['messages'] is not a valid JSON array, so a missing or
		// blank messages param must never reach a DELETE without a verified capability
		// and nonce. Previously only the presence of search_nonce was checked (its value
		// was first verified in the closing render_messages() call — after the delete),
		// which let any logged-in user (down to Subscriber) wipe a whole message type.
		// The search_nonce is the same 'render-messages_' . $message_type token that the
		// closing render_messages() already requires, so the admin UI keeps working.
		if ( ! current_user_can( 'manage_options' )
			|| ! wp_verify_nonce( $security_nonce, 'render-messages_' . $message_type ) ) {
			wp_send_json_error( array( 'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
			exit;
		}

		$wpdb->query( 'START TRANSACTION' );
		$raw_messages   = isset( $_POST['messages'] ) ? wp_unslash( $_POST['messages'] ) : '';
		$array_variable = json_decode( $raw_messages );

		if ( $array_variable ) {
			foreach ( $array_variable as $raw_message ) {
				parse_str( $raw_message, $message );

				if ( ! (
						isset( $message['deleteNonce'] )
						&& isset( $message['messsageID'] )
						&& wp_verify_nonce( $message['deleteNonce'], 'delete-message-' . $message['messsageID'] . $message_type )
						)
				) {
					$array_result = array(
						'success'       => 0,
						'error_message' => __( 'Delete action is invalid!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					);
					wp_send_json( $array_result );
				}
				$message_id = filter_var( $message['messsageID'], FILTER_VALIDATE_INT );

				// Anfrage ausführen
				$wpdb->query(
					$wpdb->prepare(
						'DELETE FROM ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm
                                    WHERE rgm_id = %d
                                    AND rgm_type = %d
                                ',
						$message_id,
						$message_type
					)
				);

				// Anfrage ausführen
				$wpdb->query(
					$wpdb->prepare(
						'DELETE FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd
                                    WHERE rgm_id = %d
                                ',
						$message_id
					)
				);

			}
		} else {
			// Anfrage ausführen
			$wpdb->query(
				$wpdb->prepare(
					'DELETE FROM ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm
                                WHERE rgm_type = %d
                            ',
					$message_type
				)
			);

			// Anfrage ausführen
			$wpdb->query(
				'DELETE rgd FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd rgd
                            LEFT JOIN ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm rgm ON rgd.rgm_id = rgm.rgm_id
                            WHERE rgm.rgm_id IS NULL'
			);
		}
		$wpdb->query( 'COMMIT' );
		$this->render_messages();
	}

	/**Change the type of the message 1 = clean, 2= spam, 3= trash*/
	public function change_message_type() {

		if ( ! (
				isset( $_POST['search'] )
				&& isset( $_POST['search_nonce'] )
				&& isset( $_POST['messageType'] )
				&& isset( $_POST['changeType'] )
				&& isset( $_POST['messages'] )
				)
			) {
			$array_result = array(
				'success'       => 0,
				'error_message' => __( 'Change action is invalid!', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
			wp_send_json( $array_result );
			exit;
		}

		global $wpdb;
		$message;
		$message_type   = filter_var( wp_unslash( $_POST['messageType'] ), FILTER_VALIDATE_INT );
		$change_type    = filter_var( wp_unslash( $_POST['changeType'] ), FILTER_VALIDATE_INT );
		$security_nonce = filter_var( wp_unslash( $_POST['search_nonce'] ), FILTER_UNSAFE_RAW );

		// Authorisation + CSRF gate before any state change. Per-item moveNonce is still
		// verified in the loop below, but the top-level search_nonce was previously only
		// checked for presence, not validity, and no capability was required.
		if ( ! current_user_can( 'manage_options' )
			|| ! wp_verify_nonce( $security_nonce, 'render-messages_' . $message_type ) ) {
			wp_send_json_error( array( 'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
			exit;
		}

		$raw_messages   = isset( $_POST['messages'] ) ? wp_unslash( $_POST['messages'] ) : '';
		$array_variable = json_decode( $raw_messages );

		foreach ( $array_variable as $raw_message ) {
			parse_str( $raw_message, $message );
			if ( ! (
					isset( $message['moveNonce'] )
					&& isset( $message['messsageID'] )
					&& wp_verify_nonce( $message['moveNonce'], 'move-message-' . $message['messsageID'] . $message_type . $change_type )
					)
			) {
				$array_result = array(
					'success'       => 0,
					'error_message' => __( 'Change action is invalid!', 'gdpr-compliant-recaptcha-for-all-forms' ),
				);
				wp_send_json( $array_result );
			}
			$message_id = filter_var( $message['messsageID'], FILTER_VALIDATE_INT );

			$wpdb->query(
				$wpdb->prepare(
					'UPDATE ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm
                                SET rgm_type = %d
                                WHERE rgm_id = %d
                                  AND rgm_type = %d
                            ',
					$change_type,
					$message_id,
					$message_type
				)
			);

		}

		$this->render_messages();
	}
}
?>