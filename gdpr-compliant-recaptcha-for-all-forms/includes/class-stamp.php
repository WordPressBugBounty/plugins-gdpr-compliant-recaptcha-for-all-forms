<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Class Stamp: Each instance of that class is intended to hold the Stamp and all checks around it
 *
 */
class Stamp {

	/**
	 * Maximum submissions a single solved PoW token may pay for (AP3 submission-
	 * binding, see ANTISPAM_HARDENING_PLAN.md / AP3_TOKEN_DESIGN.md). Deliberately
	 * NOT an option ("Bewusst NICHT umgesetzt": no extra knob to overload the
	 * settings page with) — 3 absorbs double-POST form builders and a resubmit
	 * after a validation error, while the client's own auto-renew (fired after
	 * every intercepted non-plugin POST) means an honest user almost never needs
	 * more than 1. Economically this caps a bot's amortized cost at one solved PoW
	 * per <=3 submissions instead of per IP-window (AP2, up to POW_MAX_USES) or
	 * unlimited (pre-AP2). AP4 (adaptive difficulty) is the intended lever for
	 * pushing per-submission cost further, not this constant.
	 */
	private const TOKEN_MAX_USES = 3;

	/**
	 * Site-wide "under attack" auto-boost (AP4 of the anti-spam hardening plan).
	 * A coarse, non-identifying spam-rate metric (see increment_spam_counter() /
	 * is_under_attack()) automatically raises the puzzle difficulty for every
	 * visitor while it's spiking — no per-client tracking involved, GDPR-neutral
	 * by construction (nothing but a bucketed counter is stored).
	 */

	/**
	 * Number of spam classifications (current + previous 5-minute bucket, i.e.
	 * a rolling ~10-minute window) that trigger the under-attack boost. Chosen
	 * to react within one bucket pair to a real burst while staying well above
	 * the occasional false positive a quiet site sees organically.
	 */
	private const UNDER_ATTACK_THRESHOLD = 15;

	/**
	 * Extra leading zero bits added to the base difficulty while under attack.
	 * +3 bits ~= 2^3 = 8x the average hash-search cost for every visitor.
	 * Public: read by Settings_Menu for the status-strip effective-difficulty display.
	 */
	public const UNDER_ATTACK_BONUS = 3;

	/**
	 * Hard difficulty ceiling, regardless of base + bonus. Bounds the worst-case
	 * wait time an old/low-power device's browser has to burn, so an aggressive
	 * base setting combined with the under-attack bonus can't make the puzzle
	 * unsolvable in practice on older hardware.
	 * Public: read by Settings_Menu for the status-strip effective-difficulty display.
	 */
	public const DIFFICULTY_CAP = 20;

	/**
	 * The plugin's OWN injected request fields. Server-side twin of
	 * stripPluginFields() in scripts/recaptcha-gdpr-analysis.js — keep both lists in
	 * sync. Stripped in save_message() so they never become persisted detail rows:
	 * a recognition pattern built from a saved message that includes e.g.
	 * `gdpr_pow_token` would only match POSTs that CARRY the token, so a bot simply
	 * omitting the field would fall out of the spam check entirely. NB: hashPWFields
	 * doubles as save_message()'s password-field skip list, so the strip must only
	 * happen after that list has been consumed (see save_message()).
	 */
	public const PLUGIN_FIELDS = array( 'gdpr_pow_token', 'hashPWFields' );

	/** String that holds the spam-information */
	private $plugin_spam;

	/** JSON that holds the data of the request */
	private $request_data;
	private $whole_request_data;

	/** Constructor of the class
	 */
	public function __construct() {
		$this->capture_request_data();
		// Register the plugin's OWN token endpoints unconditionally, BEFORE any
		// whitelist/referrer gating below. get_stamp only issues a stateless token and
		// check_stamp verifies a PoW — neither decides whether a submission is spam, so
		// this cannot weaken the spam check. Gating them (as before) meant a get_stamp
		// admin-ajax POST carrying an HTTP_REFERER under /wp-admin/ skipped registration
		// entirely, so WordPress answered with its "0"/400 unknown-action fallback and
		// the client could never obtain a token (frontend re-init/hung-tab loops).
		$this->register_token_endpoints();
		// Keep the registered-user-email exclude cache fresh: attach the invalidation
		// hooks unconditionally (like the token endpoints above) so a user create/
		// update/delete in THIS request drops the cached hash set. Cheap — add_action
		// only, the actual rebuild is lazy on the next echo record()/matches().
		Echo_Store::register_cache_hooks();
		$referrer_without_protocol = null;
		$posted_site               = null;
		if ( array_key_exists( 'HTTP_REFERER', $_SERVER ) ) {
			$referrer_without_protocol = preg_replace( '/^(https?:\/\/)/i', '', $_SERVER['HTTP_REFERER'] );
		}
		if ( array_key_exists( 'REQUEST_URI', $_SERVER ) && array_key_exists( 'HTTP_HOST', $_SERVER ) ) {
			$posted_site = $_SERVER['HTTP_HOST'] . preg_replace( '/^(https?:\/\/)/i', '', $_SERVER['REQUEST_URI'] );
		}
		//Check whether the IP is whitelisted
		$ip_whitelisted = false;
		$client_ip      = $this->get_client_ip();
		$lines          = preg_split( '/\r\n|\n|\r/', get_option( Option::POW_IP_WHITELIST ), -1, PREG_SPLIT_NO_EMPTY );
		if ( count( $lines ) > 0 ) {
			foreach ( $lines as $line ) {
				if ( trim( $line ) === $client_ip ) {
					$ip_whitelisted = true;
				}
			}
		}

		//Check whether the site is whitelisted
		$site_whitelisted = false;
		$lines            = preg_split( '/\r\n|\n|\r/', get_option( Option::POW_SITE_WHITELIST ), -1, PREG_SPLIT_NO_EMPTY );
		if ( count( $lines ) > 0 ) {
			foreach ( $lines as $line ) {
				if ( is_string( $posted_site ) && is_string( trim( $line ) ) && strpos( $posted_site, trim( $line ) ) === 0 ) {
					$site_whitelisted = true;
				}
			}
		}
		if ( is_string( $posted_site ) &&
			( strpos( $posted_site, '/wp-admin/admin-ajax.php?action=elementor_1_elementor_updater' )
				|| strpos( $posted_site, '/wp-cron.php' )
				|| strpos( $posted_site, '/?wordfence_syncAttackData=' )
			)
		) {
			$site_whitelisted = true;
		}

		//Check whether a rest route is used and whether it shall be processed
		$is_restroute = false;
		if ( ! get_option( Option::POW_APPLY_REST ) ) {
			if ( isset( $_SERVER['HTTP_HOST'] ) ) {
				$current_domain          = $_SERVER['HTTP_HOST'] . '/?rest_route=';
				$domain_without_protocol = preg_replace( '/^(https?:\/\/)/i', '', $current_domain );
				if ( is_string( $referrer_without_protocol ) && is_string( $domain_without_protocol ) && strpos( $referrer_without_protocol, $domain_without_protocol ) === 0 ) {
					$is_restroute = true;
				}
			}
		}

		$logged_out    = array_key_exists( 'loggedout', $this->whole_request_data ) ? $this->whole_request_data ['loggedout'] : false;
		$interim_login = array_key_exists( 'interim-login', $this->whole_request_data ) ? $this->whole_request_data ['interim-login'] : false;
		$ajax          = defined( 'DOING_AJAX' ) && DOING_AJAX;
		$action        = isset( $this->whole_request_data ['action'] ) ? sanitize_text_field( $this->whole_request_data ['action'] ) : '';

		$this->save_for_analysis();

		//If the client, the site, the rest-route, or the action is whitelisted, stop the further processing
		if ( ! $ip_whitelisted
			&& ! $site_whitelisted
			&& ! $is_restroute
			&& (
					( is_string( $referrer_without_protocol ) && false == strpos( $referrer_without_protocol, '/wp-admin/' ) ) // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual -- loose == is intentional: strpos()===0 (a "/wp-admin/" prefix match) must be treated the same as false here; strict === would change the whitelist classification.
					|| ! is_string( $referrer_without_protocol )
					|| $logged_out
					|| $interim_login
			)
		) {
			//Ajax-calls get a different treatment
			if ( $ajax ) {
				//Post-requests from the plugin
				if ( ! in_array( $action, array( 'get_stamp', 'check_stamp' ), true ) ) {
					if ( $this->check_explicit_actions() ) {
						// Only explicitly listed actions shall be allowed that are listed on the explicit actions list
						add_action( 'init', array( $this, 'run' ) );
						$this->check_submit( null, $this->request_data, 'ajax-call', $action, $ajax );
						return;
					}
				} else {
					add_action( 'init', array( $this, 'run' ) );
				}
			} elseif ( ! ( ! get_option( Option::POW_BLOCK_LOGIN ) && isset( $this->whole_request_data ['wp-submit'] ) ) ) {
				//Do not apply if login shall not be blocked and it is a login
				//Do not apply if the request is a wordfence_syncAttackData-Request from Wordfence
				if ( ! ( isset( $this->request_data['wordfence_syncAttackData'] ) && count( $this->request_data ) === 1 ) ) {
					add_action( 'init', array( $this, 'run' ) );
					$pattern_found = $this->check_existing_patterns();
					$action_found  = $this->check_explicit_actions();
					//WooCommerce
					if ( (
							isset( $this->request_data['update_cart'] ) && isset( $this->request_data['cart'] ) && isset( $this->request_data['woocommerce-cart-nonce'] )
						) || (
							isset( $this->whole_request_data ['wc-ajax'] ) && 'checkout' === $this->whole_request_data ['wc-ajax']
						)
						|| $pattern_found
						|| $action_found
					) {
						$this->check_submit( null, $this->request_data, 'specific call' );
						return;
					}
				}
			}
		}
	}

	private function capture_request_data() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Spam filter must inspect every third-party form POST; no nonce exists for foreign forms. Read-only capture only; the real gate is the PoW/token check downstream.
		$this->request_data = $_POST; // Standard POST data
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- see note above: read-only capture of the full request for inspection, not a state-changing action.
		$this->whole_request_data = $_REQUEST; // Standard REQUEST data

		// If the request is JSON, read data from php://input
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD']
			&& isset( $_SERVER['CONTENT_TYPE'] ) && strpos( $_SERVER['CONTENT_TYPE'], 'application/json' ) !== false ) {
			$json_data = json_decode( file_get_contents( 'php://input' ), true );
			if ( ! empty( $json_data ) ) {
				$this->request_data       = array_merge( $this->request_data, $json_data );
				$this->whole_request_data = array_merge( $this->whole_request_data, $json_data );
			}
		}
	}

	private function check_explicit_actions() {
		$action = isset( $this->whole_request_data ['action'] ) ? sanitize_text_field( $this->whole_request_data ['action'] ) : '';
		if ( $action ) {
			$lines = preg_split( '/\r\n|\n|\r/', get_option( Option::POW_EXPLICIT_ACTION ), -1, PREG_SPLIT_NO_EMPTY );
			if ( count( $lines ) > 0 ) {
				foreach ( $lines as $line ) {
					if ( trim( $line ) === $action //explicitly listed ajax-action
						|| isset( $this->whole_request_data [ $action ] ) //explicitly listed post-attribute
					) {
						return true;
					}
				}
			}
		}
		return false;
	}

	private function save_for_analysis() {
		$ajax      = defined( 'DOING_AJAX' ) && DOING_AJAX;
		$action    = isset( $this->whole_request_data ['action'] ) ? sanitize_text_field( $this->whole_request_data ['action'] ) : '';
		$client_ip = $this->get_client_ip();

		$excluded_patterns_for_analysis = array(
			array(
				'page'        => 'gdpr_pow_options',
				'action'      => 'update',
				'option_page' => 'gdpr_pow_header_section',
			),
		);

		$pattern_listed = false;
		foreach ( $excluded_patterns_for_analysis as $existing_pattern ) {
			if ( $existing_pattern ) {
				$pattern_listed = Option::compare_json_objects( $existing_pattern, $this->whole_request_data, true );
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
			$this->save_message( $this->whole_request_data, $action, $ajax, 4, $this->hash_values( $client_ip ) );
		}
	}

	/**
	 * Remove the plugin's own injected fields (PLUGIN_FIELDS) from a captured
	 * submission. Pure and static — unit-tested in tests/unit/StampStripPluginFieldsTest.php.
	 */
	public static function strip_plugin_fields( $fields ) {
		if ( ! is_array( $fields ) ) {
			return $fields;
		}
		foreach ( self::PLUGIN_FIELDS as $plugin_field ) {
			unset( $fields[ $plugin_field ] );
		}
		return $fields;
	}

	/**
	 * Field names whose values must never be gibberish-scored, beyond the
	 * name-heuristic built into Gibberish_Detector: the request's own
	 * hashPWFields password skip list (real passwords ARE random strings — e.g.
	 * a signup form posting two custom-named password fields would otherwise
	 * contribute two "gibberish" tokens and cross the message threshold) plus
	 * the admin-configured POW_SKIP_FIELDS entries ("site:field" per line, same
	 * format save_message() consumes). Collects every key and string leaf from
	 * the nested hashPWFields structure — a safe superset of the exact path
	 * matching save_message() performs, fine for an exemption list.
	 *
	 * @param mixed $fields The submission's field map (pre strip_plugin_fields);
	 *                      request-/hook-derived, so not guaranteed to be an array.
	 * @return string[]
	 */
	private function gibberish_exempt_field_names( $fields ) {
		$names = array();
		if ( is_array( $fields ) && isset( $fields['hashPWFields'] ) && is_string( $fields['hashPWFields'] ) ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- benign: hashPWFields is the plugin's own base64-encoded password-field skip list (client twin in recaptcha-gdpr-analysis.js), not obfuscated code.
			$decoded = json_decode( base64_decode( $fields['hashPWFields'] ), true );
			if ( is_array( $decoded ) ) {
				$stack = array( $decoded );
				while ( $stack ) {
					$node = array_pop( $stack );
					foreach ( $node as $key => $value ) {
						if ( is_string( $key ) && '' !== $key ) {
							$names[] = $key;
						}
						if ( is_array( $value ) ) {
							$stack[] = $value;
						} elseif ( is_string( $value ) && '' !== $value ) {
							$names[] = $value;
						}
					}
				}
			}
		}
		$lines = preg_split( '/\r\n|\n|\r/', (string) get_option( Option::POW_SKIP_FIELDS ), -1, PREG_SPLIT_NO_EMPTY );
		foreach ( $lines as $line ) {
			$args = explode( ':', $line );
			if ( 2 === count( $args ) ) {
				$names[] = trim( $args[1] );
			}
		}
		return $names;
	}

	private function check_existing_patterns() {
		$pattern_found = false;
		//Specific posts as proprietary ajax calls
		$existing_pattern = get_option( Option::POW_PARAMETER_PATTERN );
		if ( $existing_pattern ) {
			$existing_lines_pattern = preg_split( "/\r\n|\n|\r/", $existing_pattern );

			// Iterate through the array, convert each field to JSON, and update the array
			foreach ( $existing_lines_pattern as &$line ) {
				// Trim the line to remove any extra spaces or newline characters
				$line = trim( $line );
				// Decode the line from JSON to an array
				$line = json_decode( $line ); // Passing true makes it return an associative array

				if ( $this->check_pattern( $line, $this->whole_request_data ) ) {
					$pattern_found = true;
				}
			}
		}
		// Wildcard value patterns ({"*":"value"}) also make an otherwise-unmonitored
		// form monitored, so the wildcard classification in check_submit() can fire
		// on ANY form (the whole point of "across all forms"). Evaluated over the
		// user-content POST fields only (Echo_Values skips technical keys).
		if ( $this->matches_wildcard_patterns( self::strip_plugin_fields( $this->request_data ) ) ) {
			$pattern_found = true;
		}
		return $pattern_found;
	}

	/**
	 * Whether any user-content field of $fields equals an admin-configured wildcard
	 * value pattern ({"*":"value"}) in POW_PARAMETER_PATTERN (normalized trim +
	 * lowercase). The pattern parsing and the field walk are the pure Echo_Values
	 * class; this method is only the get_option() glue.
	 *
	 * @param mixed $fields Field map to test.
	 * @return bool
	 */
	private function matches_wildcard_patterns( $fields ) {
		$option = (string) get_option( Option::POW_PARAMETER_PATTERN );
		if ( '' === trim( $option ) ) {
			return false;
		}
		$lines           = preg_split( '/\r\n|\n|\r/', $option, -1, PREG_SPLIT_NO_EMPTY );
		$wildcard_values = Echo_Values::wildcard_values_from_lines( $lines );
		if ( empty( $wildcard_values ) ) {
			return false;
		}
		return Echo_Values::matches_wildcard_values( $fields, $wildcard_values, Echo_Store::site_domains() );
	}

	private function check_pattern( $a, $b ) {
		if ( ! $a || ! $b ) {
			return false;
		}
		if ( is_object( $b ) ) {
			$b = get_object_vars( $b );
		}
		if ( is_object( $a ) ) {
			$a = get_object_vars( $a );
		}
		foreach ( $a as $key => $value ) {
			// Wenn der Wert in $a ein weiteres assoziatives Array ist, rekursiv überprüfen
			if ( is_array( $value ) || is_object( $value ) ) {
				if ( ! isset( $b[ $key ] ) || ! $this->check_pattern( $value, $b[ $key ] ) ) {
					return false;
				}
			} elseif ( null !== $value ) {
					// Wenn der Wert in $a nicht null ist, überprüfe, ob der Schlüssel-Wert-Paar in $b existiert
				if ( ! isset( $b[ $key ] ) || $a[ $key ] !== $b[ $key ] ) {
					return false;
				}
				// Wenn der Wert in $a null ist, überprüfe, ob der Schlüssel in $b existiert
			} elseif ( ! isset( $b[ $key ] ) ) {
				return false;
			}
		}
		return true;
	}

	/** Register the plugin's own get_stamp/check_stamp admin-ajax handlers.
	 *
	 * Called unconditionally from the constructor (NOT from the referrer-gated run()):
	 * these are the plugin's token-issue/verify endpoints and must always be reachable,
	 * regardless of referrer, whitelist or admin context. They are stateless w.r.t. the
	 * spam decision, so always-on registration does not weaken the check.
	 */
	public function register_token_endpoints() {
		add_action( 'wp_ajax_nopriv_get_stamp', array( $this, 'get_stamp_call' ) );
		add_action( 'wp_ajax_nopriv_check_stamp', array( $this, 'check_stamp' ) );
		add_action( 'wp_ajax_get_stamp', array( $this, 'get_stamp_call' ) );
		add_action( 'wp_ajax_check_stamp', array( $this, 'check_stamp' ) );
	}

	/** When the plugin is run
	 */
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- signature kept for WP hook / manual-call compatibility (registered as an 'init' action callback).
	public function run( $form_builder = null ) {
		$ajax = defined( 'DOING_AJAX' ) && DOING_AJAX;
		if ( ! $ajax ) {
			add_action( 'wp_enqueue_scripts', array( $this, 'add_script_to_header' ) );
			if ( get_option( Option::POW_BLOCK_LOGIN ) ) {
				add_action( 'login_enqueue_scripts', array( $this, 'add_script_to_header' ) );
				add_action( 'wp_signon', array( $this, 'pre_process_login' ), 1, 1 );
				add_action( 'wp_authenticate_user', array( $this, 'pre_process_login' ), 1, 1 );
				add_action( 'check_passwords', array( $this, 'pre_process_login' ), 1, 1 );
				add_action( 'password_reset', array( $this, 'pre_process_login' ), 1, 1 );
			}
		}
	}

	/** Login/password-reset pre-processing (hooked at wp_signon, wp_authenticate_user,
	 * check_passwords, password_reset): run the spam check on the credentials POST.
	 * Logins deliberately skip the pattern-/action-gate — they are always monitored.
	 *
	 * Historical note (2026-07-16): the former pre_process_submission() this delegated
	 * to carried a non-login leg (analysis capture + pattern matching before
	 * check_submit) that was dead twice over — unreachable via an always-false
	 * precedence bug (`! $origin === 'login'`), and functionally superseded by the
	 * constructor triage, which handles classic POSTs itself. Removed, method folded
	 * down to its only real job.
	 */
	public function pre_process_login( $wp = null ) {
		// Empty request_data: WordPress fires loading-time POSTs (e.g. containing only
		// the time) that must not be treated as a submission.
		if ( ! is_admin() && $this->request_data ) {
			return $this->check_submit( $wp, $this->request_data );
		}
		return $wp;
	}


	/**
	 * Enqueue the client-side proof-of-work script in the page <head>.
	 *
	 * Loaded in the head (not the footer) so its fetch/XHR interception can wrap
	 * window.fetch before other page scripts run. Per-request and configuration
	 * values are handed to the script via wp_localize_script as the global `gdprPow`.
	 * The script itself lives in scripts/recaptcha-gdpr-pow.js.
	 */
	public function add_script_to_header() {
		$stamp = $this->get_stamp();

		wp_enqueue_script(
			'gdpr-recaptcha-pow',
			plugins_url( '/scripts/recaptcha-gdpr-pow.js', __DIR__ ),
			array(),
			RCM_Main::VERSION,
			false
		);

		wp_localize_script(
			'gdpr-recaptcha-pow',
			'gdprPow',
			array(
				'stamp'      => $stamp['stamp'],
				'clientIp'   => $stamp['client_ip'],
				'difficulty' => (string) $stamp['difficulty'],
				'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
				'timeout'    => get_option( Option::POW_TIME_WINDOW ),
			)
		);
	}

	/** For Filter hooks
	 *
	 */
	public function spam_check( $gdpr_fields ) {
		return $this->check_submit( null, $gdpr_fields, 'hook' );
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

	/** Check whether a valid stamp and nonce are given
	 *
	 */
	public function check_submit( $wp = null, $gdpr_fields = null, $form_builder = '', $action = null, $ajax = null ) {

		$hook_name         = current_filter();
		$this->plugin_spam = false;

		// Process the spam check
		if ( ! ( $this->check_request() ) ) {
			$this->print_debug_information( 'Classified as spam' );
			$this->plugin_spam = true;
			// Site-wide spam-rate metric feeding is_under_attack() (AP4) — only for
			// genuine PoW/token failures, never for the simulation mode below.
			$this->increment_spam_counter();
		}

		// Process the spam simulation
		if ( get_option( Option::POW_SIMULATE_SPAM ) && 'wp_authenticate_user' !== $hook_name && 'wp_signon' !== $hook_name ) {
			$this->print_debug_information( 'Spam simulated' );
			$this->plugin_spam = true;
		}

		// Value-based deterministic spam signals (BACKLOG "Wertbasierte Spam-Pattern
		// über alle Formulare"), evaluated BEFORE gibberish so they take precedence
		// as the more deliberate, value-based classification. Both run only on
		// an otherwise-clean submission and only over user-content fields (Echo_Values
		// skips technical keys — invariant 1).
		//
		// (1) Auto-echo lock: an incoming submission whose core values (sender email,
		//     payload domain, phone, long-text hash) match a value auto-recorded from
		//     a recent spam-folder message — catches the same sender/domain on ANY
		//     form / ANY IP within the TTL window (would have caught field datum #2).
		//     Cheap: one get_transient() + hash lookups.
		// strip_plugin_fields() first: gdpr_pow_token (92 chars → always a text hash)
		// and hashPWFields (constant per form → would self-match every submission)
		// are the plugin's OWN fields, not user content, and must never seed or match
		// an echo/wildcard value (they are not caught by Echo_Values' technical-key
		// rule, which only knows generic key patterns).
		$content_fields = self::strip_plugin_fields( $gdpr_fields );
		if ( $gdpr_fields && ! $this->plugin_spam && Echo_Store::matches( $content_fields ) ) {
			$this->print_debug_information( 'Echo value match' );
			$this->plugin_spam = true;
			// Additively feed the under-attack wave counter (same bucket as PoW/token
			// fails and gibberish), never in simulation mode. This does NOT change that
			// echo/wildcard act from the first attempt on their own (POW_BLOCK applies,
			// single message sorted immediately) — the feed only widens the wave-
			// detection signal so a determined echo/wildcard spammer also trips
			// is_under_attack(). Wildcard hits are the same deterministic value-based
			// class as echo, so both feed the counter.
			if ( ! get_option( Option::POW_SIMULATE_SPAM ) ) {
				$this->increment_spam_counter();
			}
		}

		// (2) Wildcard value pattern: a user-content field equals an admin-configured
		//     {"*":"value"} line in POW_PARAMETER_PATTERN.
		if ( $gdpr_fields && ! $this->plugin_spam && $this->matches_wildcard_patterns( $content_fields ) ) {
			$this->print_debug_information( 'Wildcard value match' );
			$this->plugin_spam = true;
			// Feed the wave counter too — same deterministic value class as the echo
			// hit above (see that comment). Additive only; not in simulation mode.
			if ( ! get_option( Option::POW_SIMULATE_SPAM ) ) {
				$this->increment_spam_counter();
			}
		}

		// Gibberish detection (BACKLOG "Gibberish-Erkennung: Binnen-Case-Wechsel-Regel"):
		// only evaluated when the submission passed every check above and would
		// otherwise be clean ($this->plugin_spam still false here) — a genuine
		// PoW/token failure or the simulation above already routed the message
		// through $this->plugin_spam. A hit is treated EXACTLY like any other spam
		// classification from here on (same rgm_type-2 save gated by POW_SAVE_SPAM/
		// POW_FLAG_SAVE, same POW_FLAG_SPAM field-flagging, same Fail2Ban log line,
		// same POW_BLOCK gate — reusing $this->plugin_spam instead of a parallel
		// one-off save call also avoids double-saving the message when
		// POW_SAVE_CLEAN is on). An earlier revision exempted gibberish-only hits
		// from POW_BLOCK ("sort, never block"); dropped by user decision
		// 2026-07-17: a spam classification must always interrupt delivery to the
		// original target — the spam folder is an analysis/rescue archive, not a
		// delivery path, and the saved copy (written before the block gate) keeps
		// false positives rescuable while the block's error message tells a
		// genuine sender how to reach the site instead.
		//
		// $quarantine_only_spam marks the under-attack quarantine below, which —
		// unlike every other classification — is neither counter-fed nor
		// echo-recorded nor fail2ban-logged (see the quarantine block below and the
		// guards on Echo_Store::record() and the fail2ban block).
		$quarantine_only_spam = false;
		if ( $gdpr_fields && ! $this->plugin_spam
			&& Gibberish_Detector::is_gibberish_message(
				self::strip_plugin_fields( $gdpr_fields ),
				$this->gibberish_exempt_field_names( $gdpr_fields )
			)
		) {
			$this->print_debug_information( 'Gibberish detected' );
			$this->plugin_spam = true;
			// Feed the same under-attack wave counter as a real PoW/token failure —
			// but only in the real (non-simulated) mode, matching the existing
			// increment_spam_counter() call above. (POW_SIMULATE_SPAM can be on while
			// $this->plugin_spam is still false here for the wp_authenticate_user/
			// wp_signon hooks the simulation branch above deliberately excludes, so
			// this check is not redundant with the "still false" guard above.)
			if ( ! get_option( Option::POW_SIMULATE_SPAM ) ) {
				$this->increment_spam_counter();
			}
		}

		// Under-attack quarantine (BACKLOG "Under-Attack-Eskalationsstufe"): opt-in
		// second stage of the under-attack response, evaluated LAST so it only ever
		// fires on a submission that passed every individual check above
		// ($this->plugin_spam still false). While a spam wave is in progress, such
		// grey-zone submissions are treated like any other spam classification — the
		// NORMAL spam path applies, including POW_BLOCK ("under-attack mode with
		// teeth": during the wave, grey-zone messages are held for review instead of
		// being delivered as clean; a sort-only copy would leave delivery untouched
		// and give the mode no teeth at all). Deterministic and lossless: nothing is
		// discarded, the message lands in the spam folder and the admin rehabilitates
		// genuine ones from there.
		//
		// The gate uses the quarantine's OWN opt-in (POW_UNDER_ATTACK_QUARANTINE) plus
		// the raw wave DETECTION (is_under_attack()). It deliberately does NOT also
		// require POW_UNDER_ATTACK_MODE: that option only gates the difficulty *boost*
		// in get_stamp(); the wave-detection primitive is independent, and the
		// quarantine's dedicated opt-in is already the admin's explicit choice — an
		// admin wanting quarantine without the boost (or vice versa) must be able to
		// have either.
		//
		// THREE hard exceptions vs. every other classification (critical, all via
		// $quarantine_only_spam):
		//  1. NO increment_spam_counter() — a grey-zone submission counted as spam
		//     during the wave would keep the wave alive by itself (every clean
		//     submission would re-trip is_under_attack() → self-reinforcing endless
		//     escalation). Simply never calling it here IS exception #1.
		//  2. NO Echo_Store::record() — grey-zone submissions are presumed innocent;
		//     echoing their core values would deterministically spam-classify a
		//     legitimate sender for the full 36h TTL, even AFTER the wave ends
		//     (cascading false positive). Enforced via the Echo_Store::record() guard
		//     below.
		//  3. NO fail2ban logging — a genuine visitor submitting during a wave must
		//     not have their IP fed to an out-of-band ban tool (see the fail2ban
		//     guard below).
		if ( $gdpr_fields && self::should_quarantine(
			(bool) get_option( Option::POW_UNDER_ATTACK_QUARANTINE ),
			self::is_under_attack(),
			$this->plugin_spam,
			(bool) get_option( Option::POW_SIMULATE_SPAM )
		) ) {
			$this->print_debug_information( 'Under-attack quarantine' );
			$this->plugin_spam    = true;
			$quarantine_only_spam = true;
		}

		// Auto-echo record (BACKLOG "Auto-Echo-Sperre mit TTL"): once a submission is
		// classified as spam for ANY reason (PoW/token failure, echo, wildcard,
		// gibberish) it will land in the spam folder — remember its core values
		// (hashed, TTL) so the same sender/domain/text is caught on any form / any IP
		// within the window. Never in simulation mode (everything is "spam" there,
		// which would poison the store with legitimate submissions). The under-attack
		// quarantine is EXCLUDED ($quarantine_only_spam, exception #2 above): its
		// grey-zone submissions are presumed innocent and must not seed echo values
		// that would spam-classify legitimate senders after the wave ends.
		if ( $gdpr_fields && $this->plugin_spam && ! $quarantine_only_spam && ! get_option( Option::POW_SIMULATE_SPAM ) ) {
			Echo_Store::record( self::strip_plugin_fields( $gdpr_fields ) );
		}

		// If message shall be saved before flagging
		if (
			( get_option( Option::POW_SAVE_SPAM ) && ! get_option( Option::POW_FLAG_SAVE ) && $this->plugin_spam )
			|| ( get_option( Option::POW_SAVE_CLEAN ) && ! $this->plugin_spam )
		) {
			$this->save_message( $gdpr_fields, $action, $ajax, null, $this->hash_values( $this->get_client_ip() ) );
			$this->print_debug_information( 'Message saved' );
		}

		if ( $gdpr_fields ) {
			// If message shall be flagged and message is spam
			if ( get_option( Option::POW_FLAG_SPAM ) && $this->plugin_spam ) {
				// Line by line for prefixes
				$lines = preg_split( '/\r\n|\n|\r/', get_option( Option::POW_FLAG_SUFFIXES ), -1, PREG_SPLIT_NO_EMPTY );
				if ( count( $lines ) > 0 ) {
					foreach ( $lines as $line ) {
						// Add the prefix to the respective posted technical field in order to flag this message as spam
						$args = explode( ':', $line );
						if ( 2 === count( $args ) ) {
							$field_link = &$this->access_object_or_array( $gdpr_fields, html_entity_decode( $args[0] ) );
							$post_link  = &$this->access_object_or_array( $this->request_data, html_entity_decode( $args[0] ) );
							if ( isset( $field_link ) ) {
								$prefix     = htmlspecialchars( $args[1], ENT_QUOTES, 'UTF-8' );
								$post_link  = $prefix . $post_link;
								$field_link = $prefix . $field_link;
							}
						}
					}
					$this->print_debug_information( 'Fields flagged' );
				}
				// Line by line for new fields
				$lines = preg_split( '/\r\n|\n|\r/', get_option( Option::POW_FLAG_TAGS ), -1, PREG_SPLIT_NO_EMPTY );
				if ( count( $lines ) > 0 ) {
					foreach ( $lines as $line ) {
						// Add the new field to the _POST array in order to flag this message as spam
						$args = explode( ':', $line );
						if ( 2 === count( $args ) ) {

							$field                        = htmlspecialchars( $args[0], ENT_QUOTES, 'UTF-8' );
							$value                        = htmlspecialchars( $args[1], ENT_QUOTES, 'UTF-8' );
							$_POST[ $field ]              = $value;
							$this->request_data[ $field ] = $value;
							$gdpr_fields[ $field ]        = $value;
						}
					}
					$this->print_debug_information( 'New flag fields added' );
				}
			}
		}

		// If message shall be saved after flagging
		if ( get_option( Option::POW_SAVE_SPAM )
			&& get_option( Option::POW_FLAG_SAVE )
			&& $this->plugin_spam
		) {
			$this->save_message( $gdpr_fields, $action, $ajax, null, $this->hash_values( $this->get_client_ip() ) );
			$this->print_debug_information( 'Message saved' );
		}

		// If the spam check is called by a filter
		if ( 'hook' === $form_builder ) {
			$return_value = array(
				'isSpam'    => $this->plugin_spam,
				'blockSpam' => get_option( Option::POW_BLOCK ),
				'fields'    => $gdpr_fields,
			);
			return $return_value;
		}

		// Write log for Fail2Ban — but never for a quarantine-only classification:
		// those submissions passed every individual check and are presumed innocent;
		// logging them would let fail2ban BAN the IPs of genuine visitors submitting
		// during a wave — a lasting, out-of-band lockout, unlike the per-message
		// quarantine hold (exception #3 in the quarantine block above).
		if ( $this->plugin_spam && ! $quarantine_only_spam ) {
			// Hook into failed login attempts in WordPress
			if ( isset( $this->whole_request_data ['wp-submit'] ) || ( isset( $this->whole_request_data ['log'] ) && isset( $this->whole_request_data ['pwd'] ) ) ) {
				$username = $this->whole_request_data ['log'] ?? 'unknown_user';
				$this->log_fail2ban_event( "Failed login attempt for user '$username' from IP " . $_SERVER['REMOTE_ADDR'], true );
			}

			// Logging a general spam-related event
			$this->log_fail2ban_event( 'Possible spam attempt from IP ' . $_SERVER['REMOTE_ADDR'] );
		}

		// If spam shall be blocked and message is spam. This applies to EVERY spam
		// classification including gibberish (see the user decision documented at
		// the gibberish check above) — blocked messages were already saved to the
		// spam folder before this gate, so false positives stay rescuable, and the
		// error message below tells a genuine sender how to reach the site.
		if ( get_option( Option::POW_BLOCK ) && $this->plugin_spam ) {
			$error_message = get_option( Option::POW_ERROR_MESSAGE );
			if ( ! $error_message ) {
				$error_message = __( 'Your message has been classified as spam! If you are a human, we are very sorry. Please give us notice via email.', 'gdpr-compliant-recaptcha-for-all-forms' );
			}
			// block spam
			if ( ( isset( $_SERVER['HTTP_ACCEPT'] ) && stripos( $_SERVER['HTTP_ACCEPT'], 'application/json' ) !== false ) || $ajax || isset( $_SERVER['HTTP_X_REQUESTED_WITH'] ) ) { //unknown editor but is ajax
				$response = array(
					'gdpr_error_message' => $error_message,
				);
				wp_send_json_error( $response );
				exit;
			} else {
				echo esc_html( $error_message );
				exit;
			}
		}

		// Let WordPress do further processing
		return $wp;
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
		$hostname      = $_SERVER['SERVER_NAME'] ?? 'unknown_host'; // Get the server hostname
		$priority_spam = '<42>'; // Priority for spam logs
		$priority_auth = '<34>'; // Priority for authentication logs

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

	/** Transforms an array into a string-representation */

	private function generate_paths( $my_id, $data, $current_path, $pre_forbidden_fields, $referrer_without_protocol, $forbidden_fields, $forbidden_key, $query, $first, $custom_titles, $title ) {
		$values    = array();
		$forbidden = false;

		foreach ( $data as $key => $value ) {
			$path = $current_path . ( $current_path ? '->' : '' ) . $key;
			if ( is_array( $value ) || is_object( $value ) ) {
				// Check for fields that shall be skipped via option
				if ( $forbidden_fields ) {
					if ( array_key_exists( $forbidden_key, $forbidden_fields ) ) {
						$forbidden_fields = $forbidden_fields[ $forbidden_key ];
						$forbidden_key    = $key;
					} else {
						$forbidden_fields = null;
						$forbidden_key    = null;
					}
				}
				// Recurse into nested arrays/objects
				$nested_values = $this->generate_paths( $my_id, $value, $path, $pre_forbidden_fields, $referrer_without_protocol, $forbidden_fields, $forbidden_key, $query, $first, $custom_titles, $title );
				// Merge the nested values with the current values array
				$values    = array_merge( $values, $nested_values[0] );
				$query     = $nested_values[1];
				$title     = $nested_values[2];
				$first     = $nested_values[3];
				$forbidden = $nested_values[4];
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
					if ( $forbidden_fields ) {
						$forbidden = true;
					} else {
						$forbidden = false;
					}
					// Add the path and the corresponding value to the values array alternately
					$values[] = $my_id;
					$values[] = $path;
					$values[] = $value;
					$values[] = true;
				}
			}
		}

		return array( $values, $query, $title, $first, $forbidden );
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

	/** Recursive search like array_walk_recursive, but with depth-control */
	private function recursive_search( $data, $parameter, $depth = 0, $max_depth = 3, &$found = false ) {
		if ( $depth > $max_depth ) {
			return;
		}

		foreach ( $data as $key => $value ) {
			if ( $key === $parameter ) {
				$found = true;
				return;
			}

			if ( is_array( $value ) || is_object( $value ) ) {
				$this->recursive_search( $value, $parameter, $depth + 1, $max_depth, $found );
			}
		}
	}

	/** Save a message
	 *
	 */
	public function save_message( $fields, $action, $ajax, $message_type, $ip ) {
		if (
			// Check whether the message stems from a login and shall be saved
			! ( ! get_option( Option::POW_SAVE_LOGIN ) && isset( $fields['hashPWFields'] ) && isset( $this->whole_request_data ['wp-submit'] ) )
			&& ( //Check for WooCommerce shopping carts and whether they shall be saved
				get_option( Option::POW_SAVE_CART )
				|| ! (
					isset( $fields['add-to-cart'] )
					|| (
						isset( $fields['update_cart'] )
						&& isset( $fields['woocommerce-cart-nonce'] )
					)
				)
			)
		) {
			$posted_site = null;
			if ( array_key_exists( 'REQUEST_URI', $_SERVER ) && array_key_exists( 'HTTP_HOST', $_SERVER ) ) {
				$posted_site = $_SERVER['HTTP_HOST'] . preg_replace( '/^(https?:\/\/)/i', '', $_SERVER['REQUEST_URI'] );
			}
			$forbidden_fields = array();
			if ( isset( $fields['hashPWFields'] ) ) {
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- benign: hashPWFields is the plugin's own base64-encoded password-field skip list (client twin in recaptcha-gdpr-analysis.js), not obfuscated code.
				$decoded_values = json_decode( base64_decode( $fields['hashPWFields'] ), true );
				foreach ( $decoded_values as $decoded_value ) {
					foreach ( $decoded_value as $forbidden_key => $forbidden_field ) {
						$forbidden_fields[ $forbidden_key ] = $forbidden_field;
					}
				}
			}
			// Only AFTER hashPWFields has been consumed for the password-field skip
			// list above: drop the plugin's own injected fields so they never become
			// persisted detail rows (and thus never candidates for a recognition
			// pattern built from a saved message). Must not run before this point —
			// stripping hashPWFields earlier would disable exactly that skip list
			// and leak password fields into the inbox.
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

			foreach ( $fields as $key => $value ) {
				if ( is_array( $value ) || is_object( $value ) ) {
					$nested_values = $this->generate_paths( $my_id, $value, $key, $pre_forbidden_fields, $referrer_without_protocol, $forbidden_fields, $key, $query, $first, $custom_titles, $title );
					$forbidden     = $nested_values[4];
					if ( $forbidden ) {
						continue;
					}
					$values = array_merge( $values, $nested_values[0] );
					$query  = $nested_values[1];
					$title  = $nested_values[2];
					$first  = $nested_values[3];
				} else {
					$skipped_field = false;
					if ( count( $pre_forbidden_fields ) ) {
						$skipped_field = $this->check_skipped_fields( $pre_forbidden_fields, $key, $referrer_without_protocol );
					}
					if ( ! $skipped_field ) {
						$forbidden = false;
						$this->recursive_search( $forbidden_fields, $key, 1, 1, $forbidden );
						if ( $forbidden ) {
							continue;
						}
						$values[] = $my_id;
						$values[] = $key;
						$values[] = $value;
						$values[] = true;
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
		}
	}

	/** Function to get a stamp that can be invoked via ajax
	 *
	 */
	public function get_stamp_call() {

		// stamp = hash of user ip . salt value
		$stamp = $this->get_stamp();

		// Make your array as json
		wp_send_json( $stamp );

		// Don't forget to stop execution afterward.
		wp_die();
	}

	/**
	 * Bump the site-wide, 5-minute-bucketed spam counter (AP4 under-attack mode).
	 * DSGVO-neutral by construction: the transient key carries only a coarse time
	 * bucket, never a client identity, IP, or anything else request-specific.
	 *
	 * Deliberately a plain get+set (not atomic): under a real concurrent flood a
	 * few increments can be lost to a race, but this only feeds a threshold
	 * decision (is_under_attack()), not a security boundary in its own right — an
	 * approximate count is good enough, and avoiding a DB-level atomic increment
	 * keeps this on the cheap transient API used everywhere else in the plugin.
	 */
	private function increment_spam_counter() {
		$bucket = ProofOfWork::time_bucket( time(), 5 );
		$key    = 'gdpr_pow_spam_ctr_' . $bucket;
		$count  = (int) get_transient( $key );
		set_transient( $key, $count + 1, 15 * MINUTE_IN_SECONDS );
	}

	/**
	 * Whether the site-wide spam rate currently justifies the under-attack
	 * difficulty boost: the current + immediately preceding 5-minute bucket's
	 * spam counters together reach UNDER_ATTACK_THRESHOLD. Reads only the
	 * bucketed counters written by increment_spam_counter() — no per-client data.
	 *
	 * Public static: does not use $this, and is also read by Settings_Menu for
	 * the status-strip display.
	 *
	 * @return bool
	 */
	public static function is_under_attack() {
		$bucket   = ProofOfWork::time_bucket( time(), 5 );
		$current  = (int) get_transient( 'gdpr_pow_spam_ctr_' . $bucket );
		$previous = (int) get_transient( 'gdpr_pow_spam_ctr_' . ( $bucket - 1 ) );
		return ( $current + $previous ) >= self::UNDER_ATTACK_THRESHOLD;
	}

	/**
	 * Whether an otherwise-clean submission should be quarantined (sorted into the
	 * spam folder for review) purely because a spam wave is in progress. Pure
	 * decision helper with explicit bool inputs (no WP calls, no $this) so the
	 * three-way gate is unit-testable in isolation — see StampQuarantineTest.
	 *
	 * The caller wires the WP-dependent inputs (option reads, is_under_attack()).
	 *
	 * @param bool $quarantine_enabled POW_UNDER_ATTACK_QUARANTINE opt-in is on.
	 * @param bool $under_attack       is_under_attack() — a wave is currently detected.
	 * @param bool $already_spam       The submission was already classified as spam by
	 *                                 an earlier check (then quarantine is a no-op).
	 * @param bool $simulation         POW_SIMULATE_SPAM is on (never quarantine then —
	 *                                 the simulation already marks everything spam).
	 * @return bool
	 */
	public static function should_quarantine( $quarantine_enabled, $under_attack, $already_spam, $simulation ) {
		return $quarantine_enabled && $under_attack && ! $already_spam && ! $simulation;
	}

	/** Function to generate a submission-binding token (AP3).
	 *
	 * The token is a self-contained, HMAC-bound, single-issue string (see
	 * StampToken) — no DB row is written here, so an unsolved token never costs
	 * server state. check_stamp() creates the actual DB row once a valid PoW for
	 * this token is POSTed back.
	 */
	public function get_stamp() {
		$ip              = $this->get_client_ip();
		$base_difficulty = (int) get_option( Option::POW_DIFFICULTY );
		// Explicit `true` fallback: existing installations never had this option
		// backfilled (it postdates their POW_INSTALLED-gated defaults writeback in
		// Settings_Menu::prepare_options()), so an absent option must still default
		// to "on" here rather than get_option()'s own false-if-missing behaviour.
		$under_attack_boost = get_option( Option::POW_UNDER_ATTACK_MODE, true ) && self::is_under_attack();
		$difficulty         = ProofOfWork::effective_difficulty( $base_difficulty, $under_attack_boost, self::UNDER_ATTACK_BONUS, self::DIFFICULTY_CAP );
		$token              = StampToken::create( $ip, get_option( Option::POW_SALT ), $difficulty, time(), bin2hex( random_bytes( 8 ) ) );
		$array_result       = array(
			'stamp'      => $token, // Field name kept as `stamp` for client compatibility; value is now a token.
			'client_ip'  => $ip, // Damit der Client die korrekte IP speichern kann
			'difficulty' => $difficulty,
		);
		return $array_result;
	}

	/** Attempt to determine the client's IP address
	 *
	 */
	private function get_client_ip() {
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : (string) getenv( 'REMOTE_ADDR' );

		$forwarded_headers = array();
		foreach ( array( 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED' ) as $header_name ) {
			$value = isset( $_SERVER[ $header_name ] ) ? $_SERVER[ $header_name ] : getenv( $header_name );
			if ( is_string( $value ) && '' !== $value ) {
				$forwarded_headers[ $header_name ] = $value;
			}
		}

		// Trusted-proxy concept (see ClientIp): Forwarded-For-style headers are client-
		// settable, so they are only honored when REMOTE_ADDR (the actual TCP peer) is
		// itself a configured trusted proxy — otherwise REMOTE_ADDR wins outright.
		$trusted_proxies = preg_split( '/\r\n|\n|\r/', (string) get_option( Option::POW_TRUSTED_PROXIES ), -1, PREG_SPLIT_NO_EMPTY );

		return ClientIp::resolve( $remote_addr, $forwarded_headers, $trusted_proxies );
	}

	/** Hash helper — delegates to the pure ProofOfWork primitive (single source of truth).
	 *
	 */
	private function hash_values( $x ) {
		return ProofOfWork::hash_value( $x );
	}

	/** Atomically consume one use of the solved-stamp row matching the current IP
	 * (AP2 rate-limit). LIMIT 1 so that, if an IP has solved multiple stamps
	 * (multiple rows), only one row is charged per submission.
	 *
	 * @param int $time_window Configured Option::POW_TIME_WINDOW, minutes.
	 * @param int $max_uses    Configured Option::POW_MAX_USES.
	 * @return int Affected rows (0 or 1).
	 */
	private function consume_ip_row( $time_window, $max_uses ) {
		global $wpdb;
		return (int) $wpdb->query(
			$wpdb->prepare(
				'
                    UPDATE ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs
                       SET rgs_uses = rgs_uses + 1
                     WHERE rgs_ip = %s
                       AND rgs_time >= NOW() - INTERVAL %d MINUTE
                       AND rgs_uses < %d
                     LIMIT 1',
				$this->hash_values( $this->get_client_ip() ),
				$time_window + 2,
				$max_uses
			)
		);
	}

	/** Atomically consume one use of the row keyed by this specific token (AP3
	 * submission-binding) — the token, not the IP, is the rate-limit key here.
	 *
	 * @param string $token       The verified token (also the row's rgs_stamp value).
	 * @param int    $time_window Configured Option::POW_TIME_WINDOW, minutes.
	 * @return int Affected rows (0 or 1).
	 */
	private function consume_token_row( $token, $time_window ) {
		global $wpdb;
		return (int) $wpdb->query(
			$wpdb->prepare(
				'
                    UPDATE ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs
                       SET rgs_uses = rgs_uses + 1
                     WHERE rgs_stamp = %s
                       AND rgs_time >= NOW() - INTERVAL %d MINUTE
                       AND rgs_uses < %d
                     LIMIT 1',
				$token,
				$time_window + 2,
				self::TOKEN_MAX_USES
			)
		);
	}

	/** Poll (bounded, 100ms interval) until $consume() reports a consumed row or the
	 * attempt budget is exhausted. Check-before-sleep, no sleep after the last
	 * attempt — worst case is (max_attempts - 1) * 100ms ≈ 2s instead of blocking
	 * the PHP worker for 5s under a spam flood.
	 *
	 * @param callable $consume      Zero-arg callable returning affected-rows (int).
	 * @param int      $max_attempts Attempt budget (default 20 ≈ 2s). A valid chain
	 *                               token widens this (ChainToken::poll_attempts_for_difficulty)
	 *                               to bridge an in-flight re-challenge round.
	 * @return int Affected rows from the winning attempt (0 if the budget ran out).
	 */
	private function poll_for_row( callable $consume, $max_attempts = 20 ) {
		$max_attempts = max( 1, (int) $max_attempts );
		$attempts     = 0;
		$valid        = 0;

		while ( true ) {
			$valid = $consume();

			if ( $valid ) {
				break;
			}

			++$attempts;
			if ( $attempts >= $max_attempts ) {
				break;
			}
			usleep( 100000 ); // 100ms poll interval.
		}
		return $valid;
	}

	/** Check whether the current form-POST is backed by a solved PoW (AP3
	 * submission-binding, with an IP-based fallback for the transition period).
	 *
	 * - A valid `gdpr_pow_token` (verified against the server-resolved IP) is rate-
	 *   limited PER TOKEN (poll + consume, TOKEN_MAX_USES); if the poll window runs
	 *   out without a usable token row, one IP-fallback consumption is attempted
	 *   (no further polling — the token attempt already spent the wait budget).
	 * - No (valid) token at all → today's IP-fallback path WITH polling, unchanged
	 *   from AP2 (covers cached pages, no-JS environments, exotic form builders —
	 *   deliberately no big-bang cutover, see AP3_TOKEN_DESIGN.md).
	 */
	public function check_request() {
		$time_window = (int) get_option( Option::POW_TIME_WINDOW, 10 );
		$max_uses    = max( 1, (int) get_option( Option::POW_MAX_USES, 10 ) );

		// is_string guard: a non-scalar gdpr_pow_token[] would raise an array-to-string
		// warning on the cast — treat it as "no token" (IP fallback) instead.
		$token = isset( $this->request_data['gdpr_pow_token'] ) && is_string( $this->request_data['gdpr_pow_token'] )
			? preg_replace( '/[^a-zA-Z0-9]/', '', $this->request_data['gdpr_pow_token'] )
			: '';

		// Chain-token path (112 chars): a submission carrying a VALID re-challenge chain
		// token gets an adaptive, difficulty-scaled poll window (up to 8s) to bridge an
		// in-flight re-challenge round. Reachable ONLY after a paid first solve (a chain
		// token is issued only in response to a verified fast solve), so the protocol-
		// blind mass never gets this longer hold — no free worker-blocking vector.
		if ( ChainToken::LENGTH === strlen( $token ) ) {
			$now_ms = (int) round( microtime( true ) * 1000 );
			if ( ChainToken::verify( $token, $this->get_client_ip(), get_option( Option::POW_SALT ), $now_ms, $time_window ) ) {
				$parsed   = ChainToken::parse( $token );
				$attempts = ChainToken::poll_attempts_for_difficulty( $parsed ? $parsed['difficulty'] : 0 );
				$valid    = $this->poll_for_row(
					function () use ( $token, $time_window ) {
						return $this->consume_token_row( $token, $time_window );
					},
					$attempts
				);
				if ( $valid ) {
					return $valid;
				}
				// Chain row never landed within the (extended) window — one IP-fallback
				// consumption, no further polling, mirroring the 92 token path below.
				return $this->consume_ip_row( $time_window, $max_uses );
			}
		}

		$token_valid = '' !== $token && StampToken::verify(
			$token,
			$this->get_client_ip(),
			get_option( Option::POW_SALT ),
			time(),
			$time_window
		);

		if ( $token_valid ) {
			$valid = $this->poll_for_row(
				function () use ( $token, $time_window ) {
					return $this->consume_token_row( $token, $time_window );
				}
			);

			if ( $valid ) {
				return $valid;
			}

			// Token didn't land a usable row within the poll window (e.g. check_stamp()
			// hasn't landed yet, or the row is already exhausted) — one IP-fallback
			// consumption, no further polling.
			return $this->consume_ip_row( $time_window, $max_uses );
		}

		return $this->poll_for_row(
			function () use ( $time_window, $max_uses ) {
				return $this->consume_ip_row( $time_window, $max_uses );
			}
		);
	}

	/** Check validity, expiration, and difficulty target for a stamp
	 *
	 */
	public function check_stamp() {
		$fields = $this->request_data;
		//The validation of the hashStamp and the nonce is what this whole function is about.
		//The stamp is used to determine whether a valid hash and a valid nonce is given.
		//If either or are crap, we know that the input was manipulated.
		// is_string guard: an array-valued hashStamp[] would make preg_replace return
		// an array and fatal on the strlen() below — treat any non-string as empty.
		$raw_stamp         = $fields['hashStamp'] ?? '';
		$stamp             = is_string( $raw_stamp ) ? preg_replace( '/[^a-zA-Z0-9]/', '', $raw_stamp ) : '';
		$nonce             = '';
		$client_difficulty = '';
		$client_ip         = '';

		// If the difficulty level is not of type int, it has been manipulated and thus remains empty.
		// This will cause the input to be classified as spam
		if ( ctype_digit( $fields['hashDifficulty'] ?? '' ) ) {
			$client_difficulty = filter_var( $fields['hashDifficulty'], FILTER_SANITIZE_NUMBER_INT );
		}

		// The same holds for the nonce
		if ( ctype_digit( $fields['hashNonce'] ?? '' ) ) {
			$nonce = filter_var( $fields['hashNonce'], FILTER_SANITIZE_NUMBER_INT );
		}

		// Validation of IP
		if ( ! empty( $fields['clientIP'] ) ) {
			$raw_client_ip = trim( $fields['clientIP'] );
			$ips           = explode( ',', $raw_client_ip );
			$all_valid     = true;
			foreach ( $ips as $ip_candidate ) {
				if ( ! filter_var( trim( $ip_candidate ), FILTER_VALIDATE_IP ) ) {
					$all_valid = false;
					break;
				}
			}
			if ( $all_valid && count( $ips ) > 0 ) {
				// Alle Teilstrings sind gültige IPs – den gesamten, unbearbeiteten String übernehmen
				$client_ip = $raw_client_ip;
			} else {
				// Mindestens ein Teilstring ist ungültig
				wp_die( 'Invalid IP adress transmitted.' );
			}
		} else {
			// Es wurde gar keine IP übermittelt – das ist ein Fehler
			wp_die( 'No IP adress transmitted.' );
		}

		$this->print_debug_information( "stamp: $stamp" );
		$this->print_debug_information( "difficulty: $client_difficulty" );
		$this->print_debug_information( "nonce: $nonce" );
		$this->print_debug_information( "client-IP: $client_ip" );

		// Length decides the format: 92 = AP3 base token, 112 = re-challenge chain
		// token (solve-time plausibility), 64 = pre-AP3 legacy bucket-stamp. All are
		// exclusively hex/decimal, so this replaces the old single-length gate.
		$stamp_length = strlen( $stamp );

		// Whether to answer a successful, PERSISTED solve with the new JSON
		// {accepted:true} body (92 plausible / 112 accepted) instead of the classic
		// empty wp_die(). Legacy (64) keeps the empty wp_die() — old cached JS clients
		// never read the body, so JSON success answers are safe new behaviour and the
		// legacy path is deliberately left untouched.
		$send_accepted = false;

		if ( StampToken::LENGTH === $stamp_length ) {
			// Token path (AP3): verified exclusively against the server-resolved IP —
			// NEVER the posted clientIP field, which a spoofing client fully controls.
			// The posted hashDifficulty is ignored here; the difficulty that matters is
			// the one embedded (and HMAC-bound) in the token itself.
			$parsed           = StampToken::parse( $stamp );
			$token_difficulty = $parsed ? (int) $parsed['difficulty'] : null;

			// The difficulty is HMAC-bound inside the token (StampToken::create()),
			// so a client cannot forge a lower value than what the server actually
			// issued — accepting anything >= the CURRENT base option (AP4: the base
			// or the under-attack boost may have changed between issuing and solving)
			// is safe and avoids rejecting a just-issued, correctly higher-difficulty
			// token. DIFFICULTY_CAP is the upper bound get_stamp() itself respects.
			if ( ! $parsed || $token_difficulty < (int) get_option( Option::POW_DIFFICULTY ) || $token_difficulty > self::DIFFICULTY_CAP ) {
				$this->print_debug_information( 'Token difficulty below current base, above cap, or unparseable token' );
				wp_die();
			}

			if ( ! StampToken::verify( $stamp, $this->get_client_ip(), get_option( Option::POW_SALT ), time(), get_option( Option::POW_TIME_WINDOW, 10 ) ) ) {
				$this->print_debug_information( 'Token is incorrect or expired' );
				wp_die();
			}

			if ( $this->check_proof_of_work( $token_difficulty, $stamp, $nonce ) ) {
				$this->print_debug_information( 'Difficulty target met.' );
			} else {
				$this->print_debug_information( 'Difficulty target was not met.' );
				wp_die();
			}

			// Solve-time plausibility gate (BACKLOG "Solve-Zeit-Plausibilität", now
			// HANDBUCH §4). issued_at is HMAC-bound (StampToken), so the elapsed span is
			// unforgeable and — since network latency only ADDS — a hard LOWER bound on
			// the real solve time. The base token has 1-second granularity (deliberately
			// coarse); at cap difficulty this quantises ~1/5 of legit solves to 0ms,
			// costing them one invisible re-challenge round (accepted per spec).
			$measured_ms = max( 0, time() - $parsed['issued_at'] ) * 1000;
			$threshold   = ProofOfWork::solve_time_threshold_ms( $token_difficulty );
			if ( $measured_ms < $threshold ) {
				// Too fast — do NOT insert. A single fast solve is legitimate luck
				// (memoryless exponential distribution), so never block: issue a
				// difficulty-scaled re-challenge chain token instead. KK=1 → this first
				// re-challenge does NOT feed the under-attack counter (see should_feed_counter).
				$this->print_debug_information( 'Solve too fast — issuing re-challenge.' );
				$d1       = min( $token_difficulty + 1, self::DIFFICULTY_CAP );
				$now_ms   = (int) round( microtime( true ) * 1000 );
				$required = $threshold + ProofOfWork::solve_time_threshold_ms( $d1 );
				$chain    = ChainToken::create(
					$this->get_client_ip(),
					get_option( Option::POW_SALT ),
					$d1,
					$now_ms,
					1,
					$measured_ms,
					$required,
					bin2hex( random_bytes( 8 ) )
				);
				wp_send_json(
					array(
						'rechallenge' => true,
						'stamp'       => $chain,
						'difficulty'  => $d1,
					)
				);
				// wp_send_json() sends the body and calls wp_die() — execution stops here.
			}

			// Plausible solve → persist the base token below and answer {accepted:true}.
			$send_accepted = true;
		} elseif ( ChainToken::LENGTH === $stamp_length ) {
			// Re-challenge chain path (solve-time plausibility). The sanitisation above
			// already keeps only [a-zA-Z0-9]; a chain token is pure hex, so it survives.
			$parsed = ChainToken::parse( $stamp );
			$dd     = $parsed ? (int) $parsed['difficulty'] : null;

			// Difficulty gate mirrors the 92 path: the DD is HMAC-bound inside the chain
			// token, so a client cannot lower it — accept anything from the current base
			// up to the cap (base/boost may have shifted between rounds).
			if ( ! $parsed || $dd < (int) get_option( Option::POW_DIFFICULTY ) || $dd > self::DIFFICULTY_CAP ) {
				$this->print_debug_information( 'Chain token difficulty below base, above cap, or unparseable.' );
				wp_die();
			}

			// Verify ALWAYS against the server-resolved IP, never the posted clientIP.
			// Both issuing and measuring use microtime milliseconds here.
			$now_ms = (int) round( microtime( true ) * 1000 );
			if ( ! ChainToken::verify( $stamp, $this->get_client_ip(), get_option( Option::POW_SALT ), $now_ms, get_option( Option::POW_TIME_WINDOW, 10 ) ) ) {
				$this->print_debug_information( 'Chain token is incorrect or expired.' );
				wp_die();
			}

			// PoW target with the chain token's own difficulty.
			if ( ! $this->check_proof_of_work( $dd, $stamp, $nonce ) ) {
				$this->print_debug_information( 'Chain difficulty target was not met.' );
				wp_die();
			}

			$measured_ms = max( 0, $now_ms - $parsed['issued_at_ms'] );

			if ( ChainToken::is_accepted( $parsed['measured_ms'], $measured_ms, $parsed['required_ms'] ) ) {
				// Cumulative measured time reached the required Erlang budget → accept:
				// persist the chain token as rgs_stamp below (same duplicate/replay
				// protection as the 92 path) and answer {accepted:true}.
				$this->print_debug_information( 'Chain accepted (cumulative time sufficient).' );
				$send_accepted = true;
			} else {
				// Still too fast in aggregate → next re-challenge round, NO insert.
				$d_next = ChainToken::next_difficulty( $dd, self::DIFFICULTY_CAP );
				$k_next = ChainToken::next_round( $parsed['round'] );
				$ss     = ChainToken::accumulate_ms( $parsed['measured_ms'], $measured_ms );
				$qq     = ChainToken::accumulate_ms( $parsed['required_ms'], ProofOfWork::solve_time_threshold_ms( $d_next ) );
				$chain  = ChainToken::create(
					$this->get_client_ip(),
					get_option( Option::POW_SALT ),
					$d_next,
					$now_ms,
					$k_next,
					$ss,
					$qq,
					bin2hex( random_bytes( 8 ) )
				);
				// Feed the site-wide under-attack counter ONLY from round 2 on (KK>=2 in
				// the freshly issued token) — a sharp verdict after >=2 rounds, never on
				// the legitimate first lucky solve. check_stamp has no simulation
				// semantics (that is a check_submit concern), so the KK>=2 gate suffices.
				if ( ChainToken::should_feed_counter( $k_next ) ) {
					$this->increment_spam_counter();
				}
				$this->print_debug_information( 'Chain continues — issuing next re-challenge.' );
				wp_send_json(
					array(
						'rechallenge' => true,
						'stamp'       => $chain,
						'difficulty'  => $d_next,
					)
				);
				// wp_send_json() sends the body and calls wp_die() — execution stops here.
			}
		} elseif ( 64 === $stamp_length ) {
			// Legacy path: pre-AP3 IP+salt+time-bucket stamp (AP1). Kept for a staged
			// rollout — a stale cache of the `action=get_stamp` GET response (CDN/object
			// cache) can still hand out an old-format stamp after this deploy. Removal
			// tracked in BACKLOG.md for a later release. Validation logic unchanged.
			$this->print_debug_information( "difficulty comparison: $client_difficulty vs " . get_option( Option::POW_DIFFICULTY ) );
			// phpcs:ignore Universal.Operators.StrictComparisons.LooseNotEqual -- loose != is intentional: $client_difficulty is a sanitized numeric string while the option may be stored as int or string; strict !== would spuriously reject a matching difficulty.
			if ( get_option( Option::POW_DIFFICULTY ) != $client_difficulty ) {
				wp_die();
			}

			if ( $this->validate_stamp( $stamp, $client_ip ) ) {
				$this->print_debug_information( 'Stamp is correct' );
			} else {
				$this->print_debug_information( 'Stamp is incorrect' );
				wp_die();
			}

			// check the actual PoW
			if ( $this->check_proof_of_work( get_option( Option::POW_DIFFICULTY ), $stamp, $nonce ) ) {
				$this->print_debug_information( 'Difficulty target met.' );
			} else {
				$this->print_debug_information( 'Difficulty target was not met.' );
				wp_die();
			}
		} else {
			$this->print_debug_information( "stamp size: $stamp_length expected: " . StampToken::LENGTH . ', ' . ChainToken::LENGTH . ' or 64' );
			wp_die();
		}

		global $wpdb;
		$hashed_ip = $this->hash_values( $this->get_client_ip() );
		// Delete all lines which are older than the predefined time limit + 2 minutes buffer time
		// ... or which are available for the current IP already
		$wpdb->query(
			$wpdb->prepare(
				'DELETE FROM ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs
                            WHERE rgs_time < NOW() - INTERVAL %d MINUTE',
				get_option( Option::POW_TIME_WINDOW ) + 2
			)
		);

		// Insert the information about the successful spam-check (stamp + hashed IP-adress).
		// The hashed IP-adress doesn't need salt, as a reverse-engineering like using
		// password-lists is impossible.
		//
		// INSERT IGNORE + the UNIQUE key on rgs_stamp are the duplicate protection: a
		// second solve of the same token must NOT create a second row (it would hand the
		// token a fresh TOKEN_MAX_USES budget — N concurrent check_stamp POSTs of one
		// solved token would otherwise multiply the allowance). A SELECT-then-INSERT
		// guard here would be racy under concurrency; the unique key is not. For the
		// legacy path, identical stamps (same IP + same time bucket) collapse into one
		// shared row the same way.
		$wpdb->query(
			$wpdb->prepare(
				'INSERT IGNORE INTO ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs (
                                rgs_ip,
                                rgs_stamp,
                                rgs_time
                             )
                             VALUES(%s, %s, NOW())
                            ',
				$hashed_ip,
				$stamp
			)
		);

		// Answer a persisted solve. 92-plausible / 112-accepted → {accepted:true}
		// (new behaviour, safely ignored by old cached JS clients that never read the
		// body); legacy (64) keeps the classic empty wp_die(). wp_send_json() exits.
		if ( $send_accepted ) {
			wp_send_json( array( 'accepted' => true ) );
		}
		// Don't forget to stop execution afterwards.
		wp_die();
	}

	/** Check whether the stamp was manipulated
	 *
	 */
	private function validate_stamp( $a_stamp, $client_ip ) {
		$ip     = $client_ip;
		$salt   = get_option( Option::POW_SALT );
		$window = get_option( Option::POW_TIME_WINDOW, 10 );

		// Accept both the current and the immediately preceding time bucket, so a
		// stamp solved right before a bucket rollover is still honored (the client
		// may take a moment to find a nonce and POST it back).
		$current_bucket  = ProofOfWork::time_bucket( time(), $window );
		$previous_bucket = $current_bucket - 1;

		$validated = hash_equals( ProofOfWork::stamp_value( $ip, $salt, $current_bucket ), (string) $a_stamp )
			|| hash_equals( ProofOfWork::stamp_value( $ip, $salt, $previous_bucket ), (string) $a_stamp );

		$this->print_debug_information( $validated ? 'Stamp is valid' : 'Stamp invalid or expired' );
		return $validated;
	}

	/** check that the hash of the stamp + nonce meets the difficulty target
	 *
	 */
	private function check_proof_of_work( $difficulty, $stamp, $nonce ) {
		$this->print_debug_information( "checking $difficulty bits of work" );
		return ProofOfWork::meets_difficulty( $difficulty, $stamp, $nonce );
	}

	/** Debug hook: intentionally a no-op in production.
	 *
	 * Swap the body for `error_log( $x )` (or an echo) when locally tracing PoW
	 * decisions; kept as a method so call sites throughout the class stay in place.
	 *
	 * @param string $x Debug message (unused in production).
	 */
	private function print_debug_information( $x ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- no-op debug hook; parameter kept so call sites can be traced without signature churn.
	}
}
