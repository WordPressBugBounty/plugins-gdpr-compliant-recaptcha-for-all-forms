<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.
/**
 * Class Settings_Menu: Renders and saves the plugin's settings page (status strip,
 * pill tabs, option cards with help popovers — see options_page()).
 */

class Settings_Menu {

	// Die sechs ausgelagerten Sektionen dieser Klasse (Welle 3, PLAN-DATEIGROESSE.md).
	// Traits werden zur Kompilierzeit in die Klasse kopiert, muessen also VOR ihr geladen
	// sein (require_once-Reihenfolge in recaptcha-gdpr-compliant.php). Schnittlinie und
	// Begruendung stehen im Kopf jeder Trait-Datei.
	use Settings_Defaults;
	use Settings_Options;
	use Settings_Options_Storage;
	use Settings_Status;
	use Settings_Save;
	use Settings_Page;

	/** String that represents the name of the plugin */
	private $plugin_name;

	/** Feld der Optionen */
	private $options;

	/**
	 * The POW_PARAMETER_PATTERN text an over-broad-pattern warning kept out of the
	 * database, so the value-loading loop can render it back instead of the stored value.
	 *
	 * REQUEST-SCOPED ON PURPOSE — no transient, no option. Leaving the page loses the
	 * text, exactly like any other unsaved form; persisting it would create a second,
	 * invisible source of truth for what the pattern option "is". See
	 * Overbroad_Pattern_Guard.
	 *
	 * @var string|null
	 */
	private $pending_pattern_value = null;

	/**
	 * The over-broad lines of that same submission (line => screens it hits), for the
	 * confirmation block inside the form.
	 *
	 * @var array<string, string[]>
	 */
	private $pending_pattern_lines = array();

	/**
	 * The same two, for POW_BLOCKED_VALUES: a block RULE that discards a whole form is held
	 * back once and named, exactly like an over-broad monitoring pattern. Separate
	 * properties rather than a shared pair, for the same reason the two confirmations have
	 * separate POST fields (Overbroad_Pattern_Guard::ACK_VALUE_FIELD): one save carries both
	 * textareas, and one of them being held back must say nothing about the other.
	 *
	 * @var string|null
	 */
	private $pending_blocked_value = null;

	/**
	 * @see $pending_blocked_value
	 *
	 * @var array<string, string[]>
	 */
	private $pending_blocked_lines = array();

	/** Option based action */
	const RCM_ACTION = Option::PREFIX . 'action';

	/** What to do with the action */
	const UPDATE = 'update';

	/** Constructor of the class
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'run' ) );
		// Second surface for the self-test (Ability_Probe). The first one is the
		// Abilities API, which only an AI agent can call — while the person who
		// actually needs the answer is the admin looking at a screen full of spam.
		add_action( 'wp_ajax_' . self::AJAX_SELF_TEST, array( $this, 'self_test_callback' ) );
		add_action( 'wp_ajax_' . self::AJAX_DIAG_TASK, array( $this, 'diag_task_callback' ) );
	}

	/** Ajax action + nonce of the settings-page self-test button. */
	const AJAX_SELF_TEST = 'gdpr_pow_self_test';

	/** Ajax action + nonce of the two diagnostic resets. */
	const AJAX_DIAG_TASK = 'gdpr_pow_diag_task';

	/** Panel id of the synthetic Diagnostics tab (not derived from an option group). */
	const TAB_DIAGNOSTICS = 'gdpr-tab-diagnostics';

	/** Query argument AND nonce action of the one-click "adopt this proxy address". */
	const ACTION_ADOPT_PROXY = 'gdpr_pow_adopt_proxy';

	/** Query argument that marks the redirect after a successful adoption. */
	const ARG_PROXY_ADOPTED = 'gdpr-proxy-adopted';

	/**
	 * Run the plugin's own handshake against this site and answer in plain language
	 * (Ability_Probe::run(), the same verdicts the Abilities API returns).
	 *
	 * Admin-only and nonce-guarded: the probe performs two loopback HTTP requests and
	 * a bounded server-side hash search, so it must not be reachable by anyone who
	 * happens to know the action name.
	 *
	 * @return void
	 */
	public function self_test_callback() {
		$nonce = isset( $_POST['security_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['security_nonce'] ) ) : '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $nonce, self::AJAX_SELF_TEST ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		$result = Ability_Probe::run();

		// A green self-test is PROOF that a solve was stored — the probe redeems a real
		// puzzle over HTTP and check_stamp only answers `accepted` once the row is
		// confirmed. So it is also the one moment at which "storage is broken" can be
		// declared over. Without this the red box hangs around for up to 24 hours after
		// the admin fixed the cause, with no way to say so — and an alarm nobody can
		// clear is one people learn to ignore.
		if ( 'ok' === $result['verdict'] ) {
			delete_option( Option::POW_STORE_FAILED_TOTAL );
			delete_option( Option::POW_STORE_LAST_FAILED_AT );
			delete_option( Option::POW_STORE_LAST_ERROR );
		}

		wp_send_json_success(
			array(
				'verdict' => $result['verdict'],
				'code'    => $result['code'],
				'message' => $result['message'],
				'notes'   => isset( $result['details']['notes'] ) ? (array) $result['details']['notes'] : array(),
			)
		);
	}

	/**
	 * Display an admin notice in the backend.
	 *
	 * @param string $message The message to be displayed.
	 */
	public static function display_admin_notice( $message ) {
		if ( ! is_admin() || get_option( Option::POW_INSTALLED ) ) {
			return;
		}
		add_action(
			'admin_notices',
			function () use ( $message ) {
				echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( $message ) . '</p></div>';
			}
		);
	}

	/** Builds the option matrix, seeds it on a fresh install, applies a submitted save
	 * and loads the current values for rendering.
	 *
	 * The matrix itself lives in the two option traits (trait-settings-options.php,
	 * trait-settings-options-storage.php). array_merge() keeps the insertion order of
	 * both halves, and that insertion order IS the tab order of the page (get_groups()).
	 */
	public function prepare_options() {
		$this->options = array_merge( $this->options_detection_and_spam(), $this->options_storage_and_setup() );

		//Check whether the installation was done already
		if ( ! get_option( Option::POW_INSTALLED ) ) {

			update_option( Option::POW_INSTALLED, true );

			foreach ( $this->options as $id => $option ) {

				update_option( $id, $option->get_default() );

			}
		}

		//Name the plugin
		$this->plugin_name = __( 'Invisible Anti-Spam', 'gdpr-compliant-recaptcha-for-all-forms' );

		$this->update_settings();

		foreach ( $this->options as $id => $option ) {

			$type = $option->get_type();
			if ( Option::ROLE_DROPDOWN === $type ) {
				// Retrieve the raw option value as an array
				$raw_option_value = get_option( $id, array() );
				// Filter the array values as strings

				$filtered_value = array_map(
					function ( $value ) {
						return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' );
					},
					$raw_option_value
				);
				$option->set_value( $filtered_value );
			} else {
				// Fall back to the option-matrix default when no row exists in the DB
				// (options added after install are only seeded on upgrade, see
				// RCM_Main::activate()). Without the fallback a missing option renders
				// as off/empty although the runtime uses its code default — and saving
				// the page would persist that wrong displayed value.
				$raw_value = get_option( $id, $option->get_default() );
				// A pattern value that update_settings() held back over an over-broad-line
				// warning is rendered as SUBMITTED, not as stored — otherwise the warning
				// would silently throw the administrator's input away, which is a worse
				// surprise than the one it exists to prevent. Request-scoped, see the
				// property's docblock.
				if ( Option::POW_PARAMETER_PATTERN === $id && null !== $this->pending_pattern_value ) {
					$raw_value = $this->pending_pattern_value;
				}
				if ( Option::POW_BLOCKED_VALUES === $id && null !== $this->pending_blocked_value ) {
					$raw_value = $this->pending_blocked_value;
				}
				if ( Option::INT === $type || Option::BOOL === $type ) {
					$option->set_value( intval( filter_var( $raw_value, $this->get_option_filter( $type ) ) ) );
				} else {
					// TEXT/STRING: keep the raw value — escaping happens at output
					// (esc_attr/esc_textarea in render_control()). The former
					// FILTER_SANITIZE_FULL_SPECIAL_CHARS here HTML-encoded quotes on
					// load, so e.g. JSON patterns displayed as {&quot;…&quot;} and the
					// encoded text got written back on the next save (value corruption).
					$option->set_value( strval( $raw_value ) );
				}
			}
		}

		$this->display_options();
	}

	/** Wenn the plugin is run
	 */
	public function run() {
		add_filter( sprintf( 'plugin_action_links_%s', plugin_basename( __FILE__ ) ), array( $this, 'get_action_links' ) );
		add_action( 'admin_menu', array( $this, 'admin_menu' ) );
		add_action( 'admin_init', array( $this, 'prepare_options' ) );
		// Both halves of the trusted-proxy suggestion. Both check manage_options as their
		// first act, so the ledger is fed only by requests we can attribute to an
		// administrator of this site — an anonymous visitor cannot influence what gets
		// proposed at all. (wp-admin/admin.php additionally runs auth_redirect() before
		// admin_init, but the capability check is what this relies on.)
		add_action( 'admin_init', array( $this, 'maybe_adopt_proxy_candidate' ) );
		add_action( 'admin_init', array( $this, 'observe_proxy_candidate' ) );
		add_filter( 'plugin_action_links_' . GDPR_COMPLIANT_RECAPTCHA, array( $this, 'add_settings_link' ) );
	}

	/**  Get links for settings page
	 *
	 */
	public function get_action_links( $links ) {
		return array_merge( array( 'settings' => sprintf( '<a href="options-general.php%s">%s</a>', Option::PAGE_QUERY, __( 'Settings', 'gdpr-compliant-recaptcha-for-all-forms' ) ) ), $links );
	}

	/** Add the admin menu for the plugin
	 *
	 */
	public function admin_menu() {
		$page = add_submenu_page(
			'options-general.php',
			$this->plugin_name,
			__( 'ReCaptcha GDPR Compliant', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'manage_options',
			Option::PREFIX . 'options',
			array( $this, 'options_page' )
		);
		add_action( "admin_print_styles-{$page}", array( $this, 'enqueue_settings_page_ressources' ) );
	}

	// Add a "Settings" link to the plugin action links
	public function add_settings_link( $links ) {
		$url           = get_admin_url() . 'options-general.php?page=' . Option::PREFIX . 'options';
		$settings_link = '<a href="' . $url . '">' . __( 'Settings', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</a>';
		array_unshift( $links, $settings_link );
		return $links;
	}

	/**Add style only for settings page */
	public function enqueue_settings_page_ressources() {
		wp_enqueue_style( 'gdpr-settingsPageStyle' );
		wp_enqueue_script( 'gdpr-settingsPageScript' );
	}

	/** Registers styles/scripts for the settings page (no WP-Settings-API indirection
	 * anymore — options_page() renders the form directly, see there).
	 */
	public function display_options() {
		wp_register_style( 'gdpr-settingsPageStyle', plugins_url( '/css/style_admin.css', __DIR__ ), array(), RCM_Main::VERSION );
		wp_register_script( 'gdpr-settingsPageScript', plugins_url( '/scripts/recaptcha-gdpr-settings.js', __DIR__ ), array(), RCM_Main::VERSION, true );
	}

	/**
	 * Record one sighting of a likely reverse proxy in front of this site.
	 *
	 * The gate, all three parts required: the peer is private/loopback, a forwarding
	 * header on the same request carries a PUBLIC address (so a real visitor was
	 * forwarded, not just internal traffic), and POW_TRUSTED_PROXIES is still empty. The
	 * candidate handed to the ledger is the PEER, never anything out of the header.
	 *
	 * Runs on admin_init, i.e. only on requests by a logged-in administrator: an
	 * anonymous request cannot feed this at all. Writes only when the ledger says
	 * something changed, which the slot logic bounds to one write per five minutes.
	 *
	 * @return void
	 */
	public function observe_proxy_candidate() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$stored = get_option( Option::POW_PROXY_CANDIDATE );

		// Configured: there is nothing left to propose, and keeping the address stored
		// would be data held for no purpose.
		if ( '' !== trim( (string) get_option( Option::POW_TRUSTED_PROXIES ) ) ) {
			if ( false !== $stored ) {
				delete_option( Option::POW_PROXY_CANDIDATE );
			}
			return;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- validated as an IP inside ClientIp/Proxy_Candidate_Ledger before any use.
		$peer = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		if ( ! ClientIp::is_private( $peer ) ) {
			return;
		}

		$header = self::forwarding_header_with_public_address();
		if ( '' === $header ) {
			return;
		}

		$result = Proxy_Candidate_Ledger::observe(
			Proxy_Candidate_Ledger::normalize( $stored ),
			$peer,
			$header,
			time()
		);

		if ( $result['changed'] ) {
			update_option( Option::POW_PROXY_CANDIDATE, $result['ledger'], false );
		}
	}

	/**
	 * One-click adoption of the proposed proxy address.
	 *
	 * Three guards, and the third is the one that makes the URL harmless: capability,
	 * nonce, and the requested address must be exactly the address the ledger already
	 * holds as a ripe candidate. The parameter can therefore only CONFIRM what the server
	 * observed — a crafted link cannot introduce an address of its own.
	 *
	 * @return void
	 */
	public function maybe_adopt_proxy_candidate() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- presence check only; check_admin_referer() below verifies the nonce before anything is written.
		if ( ! isset( $_GET[ self::ACTION_ADOPT_PROXY ] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		check_admin_referer( self::ACTION_ADOPT_PROXY );

		$requested = sanitize_text_field( wp_unslash( $_GET[ self::ACTION_ADOPT_PROXY ] ) );
		$ledger    = Proxy_Candidate_Ledger::normalize( get_option( Option::POW_PROXY_CANDIDATE ) );

		if ( ! Proxy_Candidate_Ledger::is_ripe( $ledger, time() )
			|| ! Proxy_Candidate_Ledger::matches_candidate( $ledger, $requested ) ) {
			return;
		}

		// Append rather than replace: the list may already hold lines this admin typed,
		// and a one-click convenience must never delete configuration.
		$lines = preg_split( '/\r\n|\n|\r/', (string) get_option( Option::POW_TRUSTED_PROXIES, '' ) );
		$lines = is_array( $lines ) ? array_values(
			array_filter(
				array_map( 'trim', $lines ),
				static function ( $line ) {
					return '' !== $line;
				}
			)
		) : array();
		if ( ! in_array( $ledger['ip'], $lines, true ) ) {
			$lines[] = $ledger['ip'];
		}

		update_option( Option::POW_TRUSTED_PROXIES, implode( "\n", $lines ) );
		delete_option( Option::POW_PROXY_CANDIDATE );

		wp_safe_redirect(
			admin_url( 'options-general.php' . Option::PAGE_QUERY . '&' . self::ARG_PROXY_ADOPTED . '=1' )
		);
		exit;
	}

	/**
	 * Name of the first forwarding header on THIS request whose value carries a public
	 * address — the indicator that a proxy forwarded a real visitor here.
	 *
	 * The value itself is read only to answer that yes/no question (ClientIp::
	 * has_public_address()); it is never stored, printed or resolved to an address. Only
	 * X-Forwarded-For is ever honoured for resolution, but any of the five names is
	 * evidence that a hop exists.
	 *
	 * @return string Display form of the header name, or '' if none qualifies.
	 */
	private static function forwarding_header_with_public_address() {
		foreach ( ClientIp::DIAGNOSTIC_HEADERS as $header_name ) {
			if ( empty( $_SERVER[ $header_name ] ) ) {
				continue;
			}
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- only tested for the presence of a public IP; never stored, printed or resolved.
			$value = sanitize_text_field( wp_unslash( $_SERVER[ $header_name ] ) );
			if ( ClientIp::has_public_address( $value ) ) {
				return str_replace( '_', '-', substr( $header_name, 5 ) );
			}
		}

		return '';
	}

	/**
	 * Where the address on the status strip came from — in the operator's words, not
	 * the code's.
	 *
	 * The address on its own is not the useful half. "203.0.113.5" tells nobody whether
	 * the plugin took it from the connection or from a header it decided to believe,
	 * and that difference is the whole content of a proxy support case. Three answers,
	 * matching the three states ClientIp::resolve() can be in.
	 *
	 * @return string
	 */
	private static function client_ip_source() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- validated in ClientIp; never output.
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		$resolved    = Stamp::resolve_client_ip();

		if ( $resolved === $remote_addr ) {
			return __( 'from the connection', 'gdpr-compliant-recaptcha-for-all-forms' );
		}

		if ( '' === trim( (string) get_option( Option::POW_TRUSTED_PROXIES ) ) ) {
			// Only one way to get here: the private-proxy opt-in is on and did the work.
			// Named separately from the configured-proxy case on purpose — an operator
			// who forgot the switch is on should see that it is what decided.
			return __( 'from X-Forwarded-For, via the private-network proxy setting', 'gdpr-compliant-recaptcha-for-all-forms' );
		}

		return __( 'from X-Forwarded-For, via a trusted proxy', 'gdpr-compliant-recaptcha-for-all-forms' );
	}

	/**
	 * Whether the CURRENT request's peer is a private/loopback address.
	 *
	 * Observation of this one request, nothing stored, and the value is never printed —
	 * only whether it is private. Used to decide whether the proxy hint should mention
	 * the private-proxy fallback at all.
	 *
	 * @return bool
	 */
	private static function is_private_peer() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- validated inside ClientIp::is_private(); never output or stored.
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';

		return ClientIp::is_private( $remote_addr );
	}
}
