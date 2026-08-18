<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Class Message_Page: Reflects the module for the administration of messages
 */

class Message_Page {

	// Die zwei ausgelagerten Haelften dieser Klasse (Welle 3, PLAN-DATEIGROESSE.md).
	// Traits statt zweiter Klassen, damit jede `array( $this, ... )`-Registrierung im
	// Konstruktor und jeder Zugriff auf die privaten Listen-Caches unveraendert bleibt.
	use Message_Actions;
	use Message_List;

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
		add_action( 'wp_ajax_gdpr_monitor_route', array( $this, 'monitor_route_callback' ) );
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
					'search'       => wp_create_nonce( 'render-messages_' . $message_type ),
					'saveList'     => wp_create_nonce( 'save_list_nonce_' . $message_type ),
					'savePattern'  => wp_create_nonce( 'save_pattern_nonce_' . $message_type ),
					'blockValue'   => wp_create_nonce( 'block_value_nonce_' . $message_type ),
					'monitorRoute' => wp_create_nonce( 'monitor_route_nonce_' . $message_type ),
					// Rescue path of the learned credential-field list: the handler
					// lives in Credential_Learning, only the nonce is minted here.
					'credential'   => wp_create_nonce( Credential_Learning::AJAX_NONCE . $message_type ),
				),
				'i18n'        => array(
					// NB: sprintf( __( … ), $title ) — translate the template, then fill in.
					'confirmDeleteAll'    => sprintf(
						/* translators: %s: inbox/spam/trash title. */
						__( 'You are about to delete all messages from "%s". Are you sure?', 'gdpr-compliant-recaptcha-for-all-forms' ),
						$titles[ $message_type ]
					),
					'moved'               => __( 'Message moved successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'deleted'             => __( 'Message deleted successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'actionAdded'         => __( 'Action added successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'whitelisted'         => __( 'Whitelisting successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'patternSaved'        => __( 'Pattern saved successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'choosePattern'       => __( 'Please choose the message attributes which you want to save as pattern!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'blocked'             => __( 'Blocked successfully!', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'blockFailed'         => __( 'Could not block this value.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'credentialAsk'       => __( 'Treat this field as a password field? Its value is removed from this message and from every other saved message, and future submissions never store it. This cannot be undone for messages already received.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'credentialSaved'     => __( 'Field is now treated as a credential field.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'credentialFailed'    => __( 'Could not mark this field as a credential field.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'routeMonitored'      => __( 'Now monitoring this route.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'monitorFailed'       => __( 'Could not start monitoring this route.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					// %s is a literal placeholder, replaced client-side with the actual
					// domain (only known per table row, not at page-load time when this
					// script is localized) — see blockValue() in recaptcha-gdpr-messages.js.
					/* translators: %s is replaced client-side with the sender's domain, without the @, e.g. "mailinator.com". */
					'confirmSenderDomain' => __( 'Every future submission containing a sender address at %s or its subdomains will be treated as spam. If the WordPress-Login protection is on, this can lock out registered users too, possibly yourself. It is meant for disposable or spam domains — blocking a large provider such as gmail.com will also block real visitors.', 'gdpr-compliant-recaptcha-for-all-forms' ),
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

		// REST route this submission targeted (technical row `_gdpr_route`, written by
		// Stamp::save_message(), REST_ROUTES_PLAN.md AP5). Same carve-out as the reason
		// badge above: pulled out and rendered once with a one-click "Monitor this route"
		// button, the raw row is skipped in the loop below. Present on BOTH type-4
		// analysis rows and normally classified messages — analysis mode is precisely
		// how an admin discovers a REST route worth monitoring.
		$route_value = null;
		foreach ( $details as $detail ) {
			if ( '_gdpr_route' === $detail->rgd_attribute ) {
				$route_value = (string) $detail->rgd_value;
				break;
			}
		}

		// Gibberish scoring components (technical row `_gdpr_scoring`, written by
		// Stamp::save_message() for non-spam messages only — it never coexists with
		// `_gdpr_reason`). Same carve-out as the reason/route lines above: rendered
		// once as a labelled line, the raw row is skipped in the loop below. Purpose:
		// today there is no way to see WHY a message was NOT flagged.
		$scoring_value = null;
		foreach ( $details as $detail ) {
			if ( '_gdpr_scoring' === $detail->rgd_attribute ) {
				$scoring_value = (string) $detail->rgd_value;
				break;
			}
		}

		// What the stamp table held while a "no proof of work" verdict was made (technical
		// row `_gdpr_pow_probe`, written by Stamp::save_message() only for those verdicts).
		// Same carve-out as the three lines above: rendered once as a labelled line, raw
		// row skipped in the loop below. This is THE line to ask a reporter for — the
		// reason names the path that failed, this names the evidence.
		$probe_value = null;
		foreach ( $details as $detail ) {
			if ( '_gdpr_pow_probe' === $detail->rgd_attribute ) {
				$probe_value = (string) $detail->rgd_value;
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

			// THE CAUSE, not just the kind. Four different failures share the label
			// "No proof of work", and the badge alone cannot tell a blocked bot from a
			// caching layer breaking the handshake for every real visitor. The detail was
			// recorded in `_gdpr_reason` all along — it was simply never shown, because
			// label() strips everything after the colon. Rendering it here changes no
			// stored value and no corpus label; it only stops the one datum that settles a
			// diagnosis from sitting invisibly in the database.
			$reason_detail = Classification_Reason::detail_label( $reason_value );
			if ( '' !== $reason_detail ) {
				$html_details .= '<p class="gdpr-reason-detail">'
					. esc_html( $reason_detail )
					. '</p>';
			}

			// The bridge between where the problem is SEEN and where it can be
			// ANSWERED. Someone whose forms are being flagged lives on this screen, not
			// in the settings; without this line the self-test is a feature they have to
			// already know about. Only offered for the "No proof of work" family, which
			// is what the test actually diagnoses.
			if ( Classification_Reason::CODE_NO_POW === Classification_Reason::code( $reason_value ) ) {
				$html_details .= '<p class="gdpr-reason-action">'
					. '<a href="' . esc_url( admin_url( 'options-general.php' ) . '?page=' . Option::PREFIX . 'options#gdpr-self-test' ) . '">'
					. esc_html__( 'Run the self-test', 'gdpr-compliant-recaptcha-for-all-forms' )
					. '</a> '
					. esc_html__( '— it performs this same check against your own site and says in one sentence what is wrong.', 'gdpr-compliant-recaptcha-for-all-forms' )
					. '</p>';
			}

			// The same bridge for the OTHER verdict a site owner cannot act on from here.
			// "Known spam value" means an EARLIER submission was classified as spam and put
			// its sender values into the repeat-sender lock; everything after it is rejected
			// without ever being judged on its own content. Was that first classification a
			// false alarm, the sender stays blocked until the lock is released — and nothing
			// here said where, the control being called "Repeat-sender lock" one tab over.
			// Exactly what a 1-star review called "no way to correct it" (2026-08-18) while
			// the button had existed for releases. Hours from the constant, never a literal.
			if ( Classification_Reason::CODE_ECHO_LOCK === Classification_Reason::code( $reason_value ) ) {
				$lock_hours    = (int) round( Echo_Store::TTL_SECONDS / HOUR_IN_SECONDS );
				$html_details .= '<p class="gdpr-reason-action">'
					. '<a href="' . esc_url( admin_url( 'options-general.php' ) . '?page=' . Option::PREFIX . 'options#gdpr-reset-echo' ) . '">'
					. esc_html__( 'Release the held values', 'gdpr-compliant-recaptcha-for-all-forms' )
					. '</a> '
					. esc_html(
						sprintf(
							/* translators: %d: hours a value stays in the repeat-sender lock */
							_n(
								'— a value from an earlier spam submission blocks this sender on every form for %d hour. Release it if that earlier classification was wrong.',
								'— a value from an earlier spam submission blocks this sender on every form for %d hours. Release it if that earlier classification was wrong.',
								$lock_hours,
								'gdpr-compliant-recaptcha-for-all-forms'
							),
							$lock_hours
						)
					)
					. '</p>';
			}
		}
		if ( null !== $probe_value ) {
			$html_details .= '<p class="gdpr-probe-line">'
				. esc_html__( 'Measured at that moment:', 'gdpr-compliant-recaptcha-for-all-forms' )
				. ' <code>' . esc_html( $probe_value ) . '</code>'
				. '<br><span class="gdpr-probe-hint">'
				. esc_html__( 'Solved puzzles found for this submission\'s token and for its address, with their age in seconds and how often they had already been used. token_rows=0 together with ip_rows=0 means nothing was stored at all — quote this line when reporting the problem.', 'gdpr-compliant-recaptcha-for-all-forms' )
				. '</span></p>';
		}
		if ( null !== $route_value ) {
			$html_details .= '<p class="gdpr-route-line">'
				. esc_html__( 'REST route:', 'gdpr-compliant-recaptcha-for-all-forms' )
				. ' <code>' . esc_html( $route_value ) . '</code>'
				. ' <button type="button" class="gdpr-monitor-route-btn" data-route="' . esc_attr( $route_value ) . '" onclick="monitorRoute(this)">'
				. esc_html__( 'Monitor this route', 'gdpr-compliant-recaptcha-for-all-forms' )
				. '</button></p>';
		}
		if ( null !== $scoring_value ) {
			$html_details .= '<p class="gdpr-scoring-line">'
				. esc_html__( 'Not classified as spam. Content scoring:', 'gdpr-compliant-recaptcha-for-all-forms' )
				. ' <code>' . esc_html( $scoring_value ) . '</code>'
				. '</p>';
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
		// Already-learned credential names, read once for the whole table (the
		// "Treat as credential field" button is pointless on a field that is
		// redacted already).
		$learned_names = Credential_Learning::learned_names();
		//Set the details page for each message
		foreach ( $details as $detail ) {
			// Already shown as the badge/route/scoring line above — do not repeat as a raw row.
			if ( '_gdpr_reason' === $detail->rgd_attribute || '_gdpr_route' === $detail->rgd_attribute
				|| '_gdpr_scoring' === $detail->rgd_attribute || '_gdpr_pow_probe' === $detail->rgd_attribute ) {
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

					// Sender-domain wildcard rule (BACKLOG "Absender-Domain-Blockliste"):
					// offered only when the domain behind the last @ passes the SAME
					// check the matcher and block_value_callback() apply — otherwise the
					// button would promise a block that can never match, or lock the
					// operator out of the site's own domain. data-value carries the full
					// address; the server re-extracts the domain itself.
					$at_email            = strrpos( $email, '@' );
					$offer_sender_domain = false !== $at_email
						&& Echo_Values::is_blockable_sender_domain( substr( $email, $at_email + 1 ), $own_domains );
					if ( $offer_sender_domain ) {
						$html_details .= ' <button type="button" class="gdpr-block-btn" data-kind="sender_domain" data-value="' . esc_attr( $email ) . '" title="' . esc_attr__( 'Blocks every future submission containing an address at this domain.', 'gdpr-compliant-recaptcha-for-all-forms' ) . '" onclick="blockValue(this)">' . esc_html__( 'Block this sender\'s domain', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</button>';
					}
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
				// Rescue path (b) of the learned credential-field list: a password
				// sitting readable in the inbox because neither the name heuristic nor
				// the client marker caught it. One click adds the name AND redacts
				// this message on the spot (Credential_Learning). Offered only where
				// it could help: names the plugin already knows are redacted anyway,
				// and the names its own diagnostics depend on must never be redacted.
				$segments = explode( '->', (string) $detail->rgd_attribute );
				$leaf     = Learned_Credential_Fields::normalize_name( $segments[ count( $segments ) - 1 ] );
				if ( null !== $leaf
					&& ! Credential_Fields::is_password_path( (string) $detail->rgd_attribute )
					&& ! Learned_Credential_Fields::is_diagnostic_name( $leaf )
					&& ! in_array( $leaf, $learned_names, true )
				) {
					$html_details .= ' <button type="button" class="gdpr-credential-btn" data-attribute="' . esc_attr( $detail->rgd_attribute ) . '" data-message="' . esc_attr( $message_id ) . '" onclick="treatAsCredential(this)">' . esc_html__( 'Treat as credential field', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</button>';
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
}
