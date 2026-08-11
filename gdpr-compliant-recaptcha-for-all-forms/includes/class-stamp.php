<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene) — als einzige Klasse ueber drei Bereiche verteilt:
//   handbuch/pow.md        Token-Ausgabe, check_stamp, check_request, get_client_ip
//   handbuch/gate.md       Konstruktor-Gate, run(), Login-Pfad, Signatur-Matcher
//   handbuch/detection.md  check_submit(), save_message(), Fail2Ban
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

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
	 * The plugin's OWN injected request fields. Server-side twin of
	 * stripPluginFields() in scripts/recaptcha-gdpr-analysis.js — keep both lists in
	 * sync. Stripped in save_message() so they never become persisted detail rows:
	 * a recognition pattern built from a saved message that includes e.g.
	 * `gdpr_pow_token` would only match POSTs that CARRY the token, so a bot simply
	 * omitting the field would fall out of the spam check entirely. NB: hashPWFields
	 * doubles as save_message()'s credential-field marker, so the strip must only
	 * happen after that marker has been consumed (see save_message()).
	 */
	public const PLUGIN_FIELDS = array( 'gdpr_pow_token', 'hashPWFields' );

	/** String that holds the spam-information */
	private $plugin_spam;

	/**
	 * WHY the current submission was classified as spam — a Classification_Reason
	 * string, or null for a clean submission (there is deliberately no "clean" code).
	 * Pure observation: nothing reads it to decide what check_submit()/check_request()
	 * return or whether a submission is blocked; it is only persisted as the technical
	 * field `_gdpr_reason` in save_message(). First cause wins — the first check that
	 * flips $plugin_spam sets it, nothing downstream overwrites it.
	 */
	private $classification_reason;

	/**
	 * The gibberish SCORING string for a submission that came out clean — a
	 * Classification_Reason::scoring() value, or null. The exact counterpart of
	 * $classification_reason and mutually exclusive with it: one of the two is set,
	 * never both. It exists because the reason taxonomy structurally cannot express a
	 * non-block (absence of a reason means clean), which left "why was this NOT
	 * flagged?" unanswerable — the question every near-miss support case turns on.
	 *
	 * Just as observational as the reason: nothing reads it to decide anything. It is
	 * persisted as the technical field `_gdpr_scoring` in save_message(), and a clean
	 * message is only saved at all under the "Save clean messages"/analysis opt-ins —
	 * so this adds no storage whatsoever in normal operation.
	 */
	private $clean_scoring;

	/**
	 * Which PoW/token path failed in check_request() — one of the
	 * Classification_Reason::NO_POW_* constants. check_request() records this on every
	 * failing path it takes, without knowing whether its overall result ends up being
	 * false; check_submit() promotes it to $classification_reason only when
	 * check_request() actually returned false (the IP fallback may still succeed).
	 */
	private $pow_fail_reason;

	/**
	 * The token check_request() evaluated, sanitized exactly as it evaluated it ('' when
	 * none was posted). Kept solely so measure_pow_probe() can look up the same row the
	 * consume queries looked for — reading $request_data again there would risk
	 * measuring something subtly different from what was actually decided on.
	 *
	 * @var string
	 */
	private $pow_token = '';

	/**
	 * What the stamp table actually held when a submission was classified "no proof of
	 * work" (Classification_Reason::pow_probe()), or null when nothing was measured.
	 * Persisted as the technical field `_gdpr_pow_probe` in save_message(), on exactly
	 * the same terms as `_gdpr_reason`: additive, rgm_posted = false, absent on every
	 * other classification.
	 *
	 * Measured in check_submit() — i.e. only once check_request() has actually returned
	 * false — so the healthy path pays nothing for it.
	 *
	 * @var string|null
	 */
	private $pow_probe;

	/**
	 * The REST route this request targets, as extracted by check_rest_routes(), or
	 * null when the request is not a REST request at all. Set whether or not the
	 * route ends up matching POW_REST_ROUTES — it describes the request, not the
	 * verdict.
	 *
	 * Read via get_rest_route() by save_message() (REST_ROUTES_PLAN.md AP5), which
	 * persists it as the technical `_gdpr_route` detail row on both type-4 analysis
	 * rows and normally classified messages. check_rest_routes() is called from the
	 * constructor BEFORE save_for_analysis(), specifically so this property is already
	 * set when that first save_message() call happens.
	 *
	 * @var string|null
	 */
	private $rest_route = null;

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
		$posted_site = null;
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
		$ajax   = defined( 'DOING_AJAX' ) && DOING_AJAX;
		$action = isset( $this->whole_request_data ['action'] ) ? sanitize_text_field( $this->whole_request_data ['action'] ) : '';

		if ( $this->is_special_case_request( $action ) ) {
			$site_whitelisted = true;
		}

		// Computed HERE, BEFORE save_for_analysis() — not down in the non-ajax gate
		// below, where it used to live. save_for_analysis() persists a type-4 row from
		// THIS call, and REST_ROUTES_PLAN.md AP5 needs $this->rest_route (read via
		// get_rest_route() in save_message()) already set for that row. check_rest_routes()
		// is pure request inspection (only $_SERVER/$_GET/$_POST + the option, see its
		// docblock) — computing it here changes no other behavior, and the boolean is
		// reused below instead of calling the method a second time.
		$route_found = $this->check_rest_routes();

		$this->save_for_analysis();

		// If the client or the site is whitelisted, stop the further processing.
		//
		// NO REQUEST HEADER MAY EVER DECIDE THIS AGAIN. Until 5.3.0 this condition also
		// carried two referer-based exemptions — a `?rest_route=` prefix (gated by the
		// removed "Apply on REST-API" option) and "the referer contains /wp-admin/".
		// Both were skipping the ENTIRE spam check, including the login check, on a
		// single header the sender picks freely; the second one also worked from a
		// foreign host and as a query-string substring. They are gone. Legitimate
		// backend traffic does not need them: what is evaluated behind this gate is
		// only what matches a field pattern or a monitored ajax action, and backend
		// POSTs (post.php, options.php, the block editor's REST save, admin-ajax,
		// builder settings screens) match neither — measured with a real logged-in
		// session in tests/integration/cases/backend-posts.mjs.
		//
		// What still comes from the request, and why it is bounded: the two remaining
		// terms are keyed on the URL (`is_special_case_request()`, anchored + narrowed
		// by the request's own action/body shape) and on `POW_SITE_WHITELIST`, which is
		// matched against `HTTP_HOST . REQUEST_URI` — and `Host` IS client-settable, so
		// an admin-entered whitelist line can be claimed by a forged Host header
		// (pre-existing, see ISSUES.md). Both are ADMIN-configured or fixed integration
		// endpoints, not switches a visitor turns on; that is the line this gate holds.
		if ( ! $ip_whitelisted && ! $site_whitelisted ) {
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
					// $route_found: computed earlier, before save_for_analysis() — see there.
					//WooCommerce
					if ( (
							isset( $this->request_data['update_cart'] ) && isset( $this->request_data['cart'] ) && isset( $this->request_data['woocommerce-cart-nonce'] )
						) || (
							isset( $this->whole_request_data ['wc-ajax'] ) && 'checkout' === $this->whole_request_data ['wc-ajax']
						)
						|| $pattern_found
						|| $action_found
						|| $route_found
					) {
						$this->check_submit( null, $this->request_data, 'specific call' );
						return;
					}
				}
			}
		}
	}

	/**
	 * The three fixed special cases of the site whitelist: WordPress' own cron
	 * spawner, Elementor's updater ajax call, and Wordfence's attack-data sync.
	 *
	 * ANCHORED comparison against REQUEST_URI — exact path plus, where the entry needs
	 * it, a query-string PREFIX. Until 5.3.0 this was a truthy `strpos()` over
	 * `HTTP_HOST . REQUEST_URI`, i.e. the needle was accepted ANYWHERE in the URL: a
	 * plain `POST /?redirect=/wp-cron.php` — a query parameter any sender picks for
	 * itself, no header needed — skipped the entire spam check (ISSUES.md, measured
	 * 2026-08-06). Anchoring also makes the entries correct on a WordPress installed
	 * in a subdirectory: the paths are built from the install's own site/home path
	 * instead of assuming the document root.
	 *
	 * The URL alone is NOT enough, and getting that wrong is how this method leaked
	 * twice (both found in review, both measured):
	 *
	 *   - Elementor: `$_REQUEST['action']` merges GET and POST, and POST wins. A
	 *     request to `admin-ajax.php?action=elementor_1_elementor_updater` carrying
	 *     `action=wpforms_submit` in its BODY matched this entry on the query while the
	 *     ajax branch below dispatched on the body value — i.e. any monitored ajax
	 *     action could be switched off with one query parameter. The entry therefore
	 *     requires the EFFECTIVE action to be Elementor's as well. Note the direction:
	 *     query AND effective action, never "action from the body alone" — that would
	 *     be the self-naming exemption this guard exists to prevent.
	 *   - Wordfence: matching only `?wordfence_syncAttackData=` let any body ride along
	 *     unevaluated. The entry now demands the same body shape the non-ajax branch
	 *     below already demands of this integration (that single field and nothing
	 *     else), so the URL cannot carry a foreign payload past the check.
	 *
	 * @param string $action Effective action of this request (`$_REQUEST['action']`).
	 * @return bool
	 */
	private function is_special_case_request( $action = '' ) {
		if ( ! array_key_exists( 'REQUEST_URI', $_SERVER ) || ! is_string( $_SERVER['REQUEST_URI'] ) ) {
			return false;
		}
		$request_uri   = wp_unslash( $_SERVER['REQUEST_URI'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared, never output or stored; sanitizing would alter the path being compared.
		$request_path  = (string) wp_parse_url( $request_uri, PHP_URL_PATH );
		$request_query = (string) wp_parse_url( $request_uri, PHP_URL_QUERY );
		$site_path     = untrailingslashit( (string) wp_parse_url( (string) get_option( 'siteurl' ), PHP_URL_PATH ) );
		$home_path     = untrailingslashit( (string) wp_parse_url( (string) get_option( 'home' ), PHP_URL_PATH ) );

		// The cron spawner posts an EMPTY body (`spawn_cron()` sends `body => array()`,
		// and wp-cron.php itself dies on a non-empty $_POST), so "no fields" is not a
		// restriction here — it is the real shape of the call.
		$is_wordfence_shape = isset( $this->request_data['wordfence_syncAttackData'] )
			&& count( $this->request_data ) === 1;

		$special_cases = array(
			// WordPress' own cron spawner — wp-cron.php sits at the SITE path.
			array( $site_path . '/wp-cron.php', '', true ),
			// Elementor's updater: same endpoint as every other ajax call, told apart by
			// the action — which must match in the URL *and* effectively (see docblock).
			array(
				$site_path . '/wp-admin/admin-ajax.php',
				'action=elementor_1_elementor_updater',
				'elementor_1_elementor_updater' === $action,
			),
			// Wordfence's attack-data sync, posted to the site's front page — only with
			// the body shape the non-ajax branch already expects of it.
			array( $home_path . '/', 'wordfence_syncAttackData=', $is_wordfence_shape ),
		);

		foreach ( $special_cases as $special_case ) {
			list( $path, $query_prefix, $payload_ok ) = $special_case;
			if ( ! $payload_ok ) {
				continue;
			}
			if ( $request_path === $path
				&& ( '' === $query_prefix || strpos( $request_query, $query_prefix ) === 0 )
			) {
				return true;
			}
		}
		return false;
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
	 * format save_message() consumes) plus the LEARNED credential field names.
	 * The last one is not optional: without it a no-JS submission carrying a
	 * learned password field has no marker to exempt it, and its random password
	 * would tip the very message into the gibberish classification that the
	 * marker path is exempt from — the same form judged differently depending on
	 * whether the JS ran. Collects every key and string leaf from the nested
	 * hashPWFields structure — a safe superset of the exact path matching
	 * save_message() performs, fine for an exemption list.
	 *
	 * Static and public since the Abilities API surface exists: the classify-text
	 * ability has to score a supplied field map with EXACTLY this exemption list.
	 * A second, parallel implementation there would be worse than useless — a
	 * diagnostic tool that judges differently from the live path sends whoever
	 * trusts it in the wrong direction. This method holds no instance state, so
	 * sharing it costs nothing.
	 *
	 * @param mixed $fields The submission's field map (pre strip_plugin_fields);
	 *                      request-/hook-derived, so not guaranteed to be an array.
	 * @return string[]
	 */
	public static function gibberish_exempt_field_names( $fields ) {
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
		foreach ( Credential_Learning::learned_names() as $learned ) {
			$names[] = $learned;
		}

		/**
		 * Filters the field names exempted from gibberish/content scoring.
		 *
		 * The plugin's FIRST public filter, added 2026-08-10 for the wp.org support case
		 * that asked for exactly this (fs26): the admin-facing list (POW_SKIP_FIELDS) is
		 * site-scoped free text — the right tool for a site owner, the wrong one for a
		 * developer who needs the decision to follow form logic. This hook is that second
		 * half, and it is deliberately SERVER-SIDE, unlike the `hashPWFields` marker
		 * above, which arrives with the request and is therefore attacker-supplied
		 * (see ISSUES.md).
		 *
		 * Being the first filter makes this an API commitment, so it carries the
		 * plugin's established `gdpr_pow_` prefix (Option::PREFIX) rather than a new
		 * one. The return value is normalised by normalize_exempt_names(): a filter
		 * returning garbage degrades to the unfiltered list instead of throwing or —
		 * far worse for a security plugin — silently exempting everything.
		 *
		 * @since 5.4.0
		 *
		 * @param string[] $names  Field names exempted from gibberish scoring. Matched
		 *                         case-insensitively at any nesting level.
		 * @param mixed    $fields The submission's field map (pre strip_plugin_fields);
		 *                         request-derived, so not guaranteed to be an array.
		 */
		$filtered = apply_filters( 'gdpr_pow_gibberish_exempt_fields', $names, $fields );

		return self::normalize_exempt_names( $filtered, $names );
	}

	/**
	 * Normalise whatever a filter returned into a usable exempt-name list.
	 *
	 * Pure and separate from the hook site on purpose. A filter is third-party code
	 * that may return anything at all, and in a security plugin the failure direction
	 * matters: a malformed return must never widen the exemption list, because a wider
	 * list means LESS scoring. Hence non-array input falls back to the unfiltered
	 * names, and non-string entries are dropped rather than coerced — a stringified
	 * array or object would become a nonsense field name that silently matches nothing
	 * (harmless) or something (not harmless).
	 *
	 * Being a separate pure function also keeps it directly unit-testable without a
	 * WordPress runtime (tests/unit/StampExemptNamesTest.php).
	 *
	 * @param mixed    $filtered The filter's return value — untrusted, any type.
	 * @param string[] $fallback The unfiltered list, used when $filtered is unusable.
	 * @return string[] Non-empty string field names.
	 */
	public static function normalize_exempt_names( $filtered, $fallback ) {
		if ( ! is_array( $filtered ) ) {
			return $fallback;
		}
		$clean = array();
		foreach ( $filtered as $name ) {
			if ( is_string( $name ) && '' !== $name ) {
				$clean[] = $name;
			}
		}
		return $clean;
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
	 * Third signature class alongside patterns/actions (REST_ROUTES_PLAN.md AP3):
	 * is this POST targeting an admin-configured REST route? Only collects the
	 * WordPress-specific inputs (REQUEST_URI, the `rest_route` request var — $_POST
	 * before $_GET, see below —, the home path, and the REST prefix
	 * `rest_get_url_prefix()`, changeable via the `rest_url_prefix` filter) and gates
	 * on POST; the actual extraction and wildcard matching is pure and lives in
	 * RestRoute (class-rest-route.php), unit-tested there in isolation — including
	 * the three places where WordPress' own routing is case-INsensitive and this
	 * class has to follow it.
	 *
	 * SAME GATE AS EVERY OTHER SIGNATURE CLASS (handbuch/gate.md): this runs behind
	 * the constructor's whitelist gate, which does not distinguish frontend from
	 * admin traffic — so once a route is configured, a POST to it is evaluated
	 * whether it came from a visitor or a logged-in admin (e.g. the block editor's
	 * own save request, `/wp/v2/posts/<id>`). Never seed a bare core namespace
	 * like `wp/v2` into POW_REST_ROUTES (see Settings_Menu::get_default_rest_routes()
	 * and its doc-comment) — that would make the plugin block post saves in
	 * wp-admin. Regression net: tests/integration/cases/backend-posts.mjs.
	 *
	 * @return bool
	 */
	private function check_rest_routes() {
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
			return false;
		}
		if ( ! isset( $_SERVER['REQUEST_URI'] ) || ! is_string( $_SERVER['REQUEST_URI'] ) ) {
			return false;
		}
		$request_uri = wp_unslash( $_SERVER['REQUEST_URI'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared/extracted, never output or stored.

		// $_POST BEFORE $_GET — WordPress' own precedence, not a preference. `rest_route`
		// is a PUBLIC query var (`$wp->add_query_var( 'rest_route' )` in
		// rest_api_register_rewrites(), wp-includes/rest-api.php), and WP::parse_request()
		// resolves every public query var in this order (wp-includes/class-wp.php, the
		// `foreach ( $this->public_query_vars as $wpvar )` loop): extra_query_vars, then
		// wp_die() if $_GET and $_POST BOTH hold it and DIFFER, then $_POST, then $_GET.
		// So a plain `POST /` whose BODY carries `rest_route=/…` is dispatched to the REST
		// server exactly like `GET|POST /?rest_route=/…`. Reading only $_GET here left that
		// spelling as a complete bypass — the request reached the endpoint, we saw no route.
		// Regression net: the post-body sub-case in tests/integration/cases/rest-routes.mjs.
		$rest_route_param = '';
		// phpcs:disable WordPress.Security.NonceVerification -- read-only inspection of which route is being targeted, not a state change.
		if ( isset( $_POST['rest_route'] ) && is_string( $_POST['rest_route'] ) ) {
			$rest_route_param = wp_unslash( $_POST['rest_route'] );
		} elseif ( isset( $_GET['rest_route'] ) && is_string( $_GET['rest_route'] ) ) {
			$rest_route_param = wp_unslash( $_GET['rest_route'] );
		}
		// phpcs:enable WordPress.Security.NonceVerification

		$home_path = untrailingslashit( (string) wp_parse_url( (string) get_option( 'home' ), PHP_URL_PATH ) );

		$route = RestRoute::extract( $request_uri, $rest_route_param, $home_path, rest_get_url_prefix() );
		// Feeds the `_gdpr_route` detail row — see $rest_route's doc-comment.
		// Recorded on every REST request, matched or not.
		$this->rest_route = $route;
		if ( null === $route ) {
			return false;
		}
		return RestRoute::matches( $route, (string) get_option( Option::POW_REST_ROUTES ) );
	}

	/**
	 * The REST route of the current request, or null if it is not a REST request —
	 * see $rest_route. Read by save_message() for the `_gdpr_route` detail row
	 * (REST_ROUTES_PLAN.md AP5); a plain accessor rather than a public property so
	 * $rest_route itself stays private.
	 *
	 * @return string|null
	 */
	public function get_rest_route() {
		return $this->rest_route;
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
				add_action( 'wp_authenticate_user', array( $this, 'pre_process_login' ), 1, 1 );
				add_action( 'password_reset', array( $this, 'pre_process_login' ), 1, 1 );
			}
		}
	}

	/** Login/password-reset pre-processing (hooked at wp_authenticate_user and
	 * password_reset): run the spam check on the credentials POST.
	 * Logins deliberately skip the pattern-/action-gate — they are always monitored.
	 *
	 * It passes $origin = 'login' down to check_submit()/save_message(): that explicit
	 * marker — not a reconstruction from request fields — is what drives the
	 * POW_SAVE_LOGIN suppression and the fail2ban auth-log line. Reconstructing the
	 * login-ness from `wp-submit`/`hashPWFields` (as this used to) silently failed for
	 * no-JS and minimal POSTs.
	 *
	 * Deliberately NO further hooks (scope discipline). Two more login-related actions
	 * used to be registered in run() and were dropped as provably inert: `wp_signon`
	 * is not a WordPress core action at all (nothing ever fires it), and
	 * `check_passwords` only fires inside wp-admin, where the is_admin() guard below
	 * bails out. Do not re-add either. And a brute-force attempt
	 * against an unknown user name never reaches `wp_authenticate_user`, so it never
	 * persists anything either — there is no leak to close there. Hooking `authenticate`
	 * instead would be a detection feature of its own (cookie auth, filter ordering)
	 * with its own risk, not part of this path.
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
			return $this->check_submit( $wp, $this->request_data, '', null, null, 'login' );
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
	 *
	 * PRIVACY INVARIANT (pinned by LocalizePrivacyTest): nothing here is derived from
	 * the visitor's IP — the embedded token is the anonymous one, and no address is
	 * localized to the page. Page HTML is cacheable and shared, so a value that
	 * identifies one visitor must never be rendered into it.
	 */
	public function add_script_to_header() {
		$stamp = $this->get_anonymous_stamp();

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
				'difficulty' => (string) $stamp['difficulty'],
				'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
				// Same default as every server-side reader of this option, so a missing
				// option row cannot make the client's renew cadence disagree with the
				// window the server actually enforces. (renewIntervalMs() clamps an
				// empty value to the same 10 minutes, so this changes no behaviour — it
				// removes the second definition of that number.)
				'timeout'    => get_option( Option::POW_TIME_WINDOW, 10 ),
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
	 * $origin names the path this submission came in on; only pre_process_login()
	 * passes anything ('login'), every other caller keeps the '' default. It is
	 * handed straight through to save_message() and is deliberately NOT stored on
	 * the instance (explicit data flow — the same Stamp object serves several
	 * submissions per request in the hook paths).
	 *
	 * NB: the credential redaction pre-pass lives in save_message() ONLY and must
	 * never be applied to $gdpr_fields here. Echo lock,
	 * wildcard patterns and gibberish detection below all read these raw values, and
	 * feeding them '[redacted]' would change what counts as spam — a silent weakening
	 * of the filter. They are safe on raw values: the echo store only keeps sha256
	 * hashes (text hashes only from 40 chars up), wildcard matching stores nothing at
	 * all, and the gibberish detector needs the raw text and exempts password fields
	 * itself (is_exempt_field_name(): substring `pass`/`pwd`, plus
	 * gibberish_exempt_field_names()).
	 */
	public function check_submit( $wp = null, $gdpr_fields = null, $form_builder = '', $action = null, $ajax = null, $origin = '' ) {

		$hook_name                   = current_filter();
		$this->plugin_spam           = false;
		$this->classification_reason = null;
		$this->clean_scoring         = null;
		$this->pow_probe             = null;

		// Process the spam check
		if ( ! ( $this->check_request() ) ) {
			$this->print_debug_information( 'Classified as spam' );
			$this->plugin_spam = true;
			// Promote the NO_POW_* reason check_request() recorded for the path it took.
			// It only counts as the classification reason once check_request() actually
			// returned false — a failing path whose IP fallback still succeeded never
			// gets here. This is the first check in the function, so it always wins.
			$this->classification_reason = $this->pow_fail_reason;
			// …and record WHAT THE TABLE HELD while deciding that. The reason names the
			// path that failed; this names the evidence. Only here, i.e. only on an
			// actually-failed check, so the healthy path never runs these queries.
			$this->pow_probe = $this->measure_pow_probe( $this->pow_token );
			// Site-wide spam-rate metric feeding is_under_attack() (AP4) — only for
			// genuine PoW/token failures, never for the simulation mode below.
			$this->increment_spam_counter();
		}

		// Process the spam simulation
		if ( get_option( Option::POW_SIMULATE_SPAM ) && 'wp_authenticate_user' !== $hook_name ) {
			$this->print_debug_information( 'Spam simulated' );
			$this->plugin_spam = true;
			// Unlike every check below, this block has NO ! $this->plugin_spam guard —
			// deliberately, so simulation also catches requests check_request() passed.
			// The REASON must still follow first-cause-wins, hence the explicit null
			// check here: a submission that failed PoW AND runs in simulation mode keeps
			// its no_pow:* reason.
			if ( null === $this->classification_reason ) {
				$this->classification_reason = Classification_Reason::CODE_SIMULATION;
			}
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
			$this->plugin_spam           = true;
			$this->classification_reason = Classification_Reason::CODE_ECHO_LOCK;
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
			$this->plugin_spam           = true;
			$this->classification_reason = Classification_Reason::CODE_WILDCARD;
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
		//
		// analyze_message() rather than its is_gibberish_message() wrapper: the verdict
		// is identical (the wrapper just returns ['gibberish']), but the same single
		// scan also yields the scoring components for the reason string — calling both
		// would score every submission twice.
		$quarantine_only_spam = false;
		$analysis             = array(
			'gibberish' => false,
			'letters'   => 0,
			'alnum'     => 0,
			'solo'      => false,
			'strong'    => false,
			'scoreable' => 0,
		);
		if ( $gdpr_fields && ! $this->plugin_spam ) {
			$analysis = Gibberish_Detector::analyze_message(
				self::strip_plugin_fields( $gdpr_fields ),
				self::gibberish_exempt_field_names( $gdpr_fields )
			);
		}
		if ( $analysis['gibberish'] ) {
			$this->print_debug_information( 'Gibberish detected' );
			$this->plugin_spam           = true;
			$this->classification_reason = Classification_Reason::gibberish(
				$analysis['letters'],
				$analysis['alnum'],
				$analysis['solo'],
				$analysis['strong']
			);
			// Feed the same under-attack wave counter as a real PoW/token failure —
			// but only in the real (non-simulated) mode, matching the existing
			// increment_spam_counter() call above. (POW_SIMULATE_SPAM can be on while
			// $this->plugin_spam is still false here for the wp_authenticate_user hook
			// the simulation branch above deliberately excludes, so this check is not
			// redundant with the "still false" guard above.)
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
			$this->plugin_spam           = true;
			$quarantine_only_spam        = true;
			$this->classification_reason = Classification_Reason::CODE_QUARANTINE;
		}

		// WHY this submission was NOT flagged — the counterpart of the reason above, and
		// the one question the reason taxonomy cannot answer (absence of a reason means
		// clean, so a near-miss looks exactly like a message nothing ever looked at).
		// Recorded ONLY for a submission that survived every check, hence after the
		// quarantine block: anything that flipped $plugin_spam already carries a reason,
		// and the two are mutually exclusive by construction.
		//
		// Costs no storage in normal operation: save_message() only ever persists a
		// clean submission under POW_SAVE_CLEAN or as a type-4 analysis row, both
		// explicit admin opt-ins. The value is derived purely from the plugin's own
		// scoring counts — it contains no submitted content and no visitor data, so it
		// carries nothing the GDPR positioning would object to.
		if ( $gdpr_fields && ! $this->plugin_spam ) {
			$this->clean_scoring = Classification_Reason::scoring(
				$analysis['letters'],
				$analysis['alnum'],
				$analysis['solo'],
				$analysis['strong'],
				$analysis['scoreable']
			);
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
			$this->save_message( $gdpr_fields, $action, $ajax, null, $this->hash_values( $this->get_client_ip() ), $origin );
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
			$this->save_message( $gdpr_fields, $action, $ajax, null, $this->hash_values( $this->get_client_ip() ), $origin );
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
			// Hook into failed login attempts in WordPress. The $origin leg is additive:
			// it also catches minimal login POSTs that carry neither `wp-submit` nor the
			// classic log/pwd pair, which the two request-data probes alone would miss.
			if ( isset( $this->whole_request_data ['wp-submit'] ) || ( isset( $this->whole_request_data ['log'] ) && isset( $this->whole_request_data ['pwd'] ) ) || 'login' === $origin ) {
				// The submitted login name is unauthenticated attacker input. Without
				// strict sanitisation a value containing CR/LF would forge extra fail2ban
				// log lines (e.g. an "<34>… auth: Failed login … from IP 8.8.8.8" line),
				// letting an attacker get arbitrary IPs banned. sanitize_user(strict)
				// drops everything outside a safe whitelist; the length is capped too.
				$username = ( isset( $this->whole_request_data ['log'] ) && is_string( $this->whole_request_data ['log'] ) )
					? substr( sanitize_user( wp_unslash( $this->whole_request_data ['log'] ), true ), 0, 60 )
					: '';
				if ( '' === $username ) {
					$username = 'unknown_user';
				}
				$this->log_fail2ban_event( "Failed login attempt for user '$username' from IP " . $this->get_client_ip(), true );
			}

			// Logging a general spam-related event. Use the validated client IP (honours
			// the trusted-proxy list), never the raw REMOTE_ADDR.
			$this->log_fail2ban_event( 'Possible spam attempt from IP ' . $this->get_client_ip() );
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
	public function save_message( $fields, $action, $ajax, $message_type, $ip, $origin = '' ) {
		if (
			// Check whether the message stems from a login and shall be saved
			! ( ! get_option( Option::POW_SAVE_LOGIN ) && 'login' === $origin )
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
		}
	}

	/** Function to get a stamp that can be invoked via ajax
	 *
	 */
	public function get_stamp_call() {

		// A freshly issued, single-use token plus its difficulty and the diagnostic
		// fingerprint — see get_stamp(). (Until AP3 this was a hash of IP + salt + time
		// bucket, hence the endpoint name; nothing of that construction is left.)
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
		$salt       = get_option( Option::POW_SALT );
		$difficulty = $this->issue_difficulty();
		// The fingerprint — NOT the IP — is what enters the token (StampToken::create_v2
		// has no IP parameter by design). It is diagnostic only: nothing about this
		// token's later validity depends on the address it was issued to.
		$fp    = StampToken::fingerprint( $this->get_client_ip(), $salt );
		$token = StampToken::create_v2( $fp, $salt, $difficulty, time(), bin2hex( random_bytes( 8 ) ) );

		return array(
			'stamp'      => $token, // Field name kept as `stamp` for client compatibility; value is now a token.
			// The keyed fingerprint replaces the former plaintext `client_ip` field: this
			// response is cacheable by construction, and a plaintext IP in a cached body
			// is a privacy defect. It stays in the answer because it is what makes the
			// "load get_stamp twice" proxy-rotation diagnosis possible (HANDBUCH §12).
			'fp'         => $fp,
			'difficulty' => $difficulty,
		);
	}

	/** The difficulty to hand out with a freshly issued token.
	 *
	 * Explicit `true` fallback: existing installations never had POW_UNDER_ATTACK_MODE
	 * backfilled (it postdates their POW_INSTALLED-gated defaults writeback in
	 * Settings_Menu::prepare_options()), so an absent option must still default to "on"
	 * here rather than get_option()'s own false-if-missing behaviour.
	 *
	 * No ceiling on the issued difficulty on purpose: check_stamp() only accepts a token
	 * whose difficulty is >= the configured base, so a clipped issue difficulty would
	 * make every issued token fail the server's own entrance check.
	 *
	 * @return int
	 */
	private function issue_difficulty() {
		$base_difficulty    = (int) get_option( Option::POW_DIFFICULTY );
		$under_attack_boost = get_option( Option::POW_UNDER_ATTACK_MODE, true ) && self::is_under_attack();
		return ProofOfWork::effective_difficulty( $base_difficulty, $under_attack_boost, self::UNDER_ATTACK_BONUS );
	}

	/** Token for the RENDER path (embedded in the page source via wp_localize_script).
	 *
	 * Deliberately ANONYMOUS (FP_ANONYMOUS) and deliberately not routed through
	 * get_stamp(): this path resolves no client IP at all, so nothing derived from a
	 * visitor's address — not even a keyed hash — can end up in cached page HTML. The
	 * token is fully usable; only its diagnostic fingerprint field is empty, so a solve
	 * of an embedded token counts as "anonymous" and feeds neither fingerprint counter.
	 *
	 * @return array{stamp:string,difficulty:int}
	 */
	private function get_anonymous_stamp() {
		$difficulty = $this->issue_difficulty();

		return array(
			'stamp'      => StampToken::create_v2(
				StampToken::FP_ANONYMOUS,
				get_option( Option::POW_SALT ),
				$difficulty,
				time(),
				bin2hex( random_bytes( 8 ) )
			),
			'difficulty' => $difficulty,
		);
	}

	/** Attempt to determine the client's IP address
	 *
	 */
	private function get_client_ip() {
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : (string) getenv( 'REMOTE_ADDR' );

		// Exactly the headers ClientIp honors — read from the class instead of keeping a
		// second list here, which is how the two drifted apart before.
		$forwarded_headers = array();
		foreach ( ClientIp::HEADER_PRIORITY as $header_name ) {
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
	 * @param int      $max_attempts Attempt budget (default 20 ≈ 2s). Every caller uses
	 *                               that default since the adaptive, difficulty-scaled
	 *                               window went with the re-challenge chain.
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
	 * - A valid `gdpr_pow_token` is rate-limited PER TOKEN (poll + consume,
	 *   TOKEN_MAX_USES); if the poll window runs out without a usable token row, one
	 *   IP-fallback consumption is attempted (no further polling — the token attempt
	 *   already spent the wait budget).
	 * - No (valid) token at all → today's IP-fallback path WITH polling, unchanged
	 *   from AP2 (covers cached pages, no-JS environments, exotic form builders —
	 *   deliberately no big-bang cutover, see AP3_TOKEN_DESIGN.md).
	 *
	 * TOKEN VALIDITY IS IP-FREE (v2): a token that was issued to one address and
	 * redeemed from another is fully valid here, which is the entire point — caches,
	 * proxy pools and IPv4/IPv6 dual stack rotate honest visitors' addresses between
	 * the two requests. The IP still governs the FALLBACK budget and identity
	 * (consume_ip_row(), whitelist, fail2ban), never validity.
	 */
	public function check_request() {
		$time_window = (int) get_option( Option::POW_TIME_WINDOW, 10 );
		$max_uses    = max( 1, (int) get_option( Option::POW_MAX_USES, 10 ) );
		$salt        = get_option( Option::POW_SALT );

		// is_string guard: a non-scalar gdpr_pow_token[] would raise an array-to-string
		// warning on the cast — treat it as "no token" (IP fallback) instead.
		$token = isset( $this->request_data['gdpr_pow_token'] ) && is_string( $this->request_data['gdpr_pow_token'] )
			? preg_replace( '/[^a-zA-Z0-9]/', '', $this->request_data['gdpr_pow_token'] )
			: '';

		// Remembered for measure_pow_probe() (check_submit), so the measurement looks up
		// exactly the value this function decided on.
		$this->pow_token = $token;

		$token_length = strlen( $token );

		// TRANSITIONAL chain-token path (120 = v2, 112 = in-flight legacy), one release
		// long: rows keyed on a chain token still exist until their window expires, and a
		// client that was mid-chain across the update still posts one. Re-challenges are
		// no longer issued anywhere (see check_stamp()), so there is no in-flight round
		// left to bridge — this uses the SAME standard poll window as the base-token path
		// below. That also retires the adaptive, difficulty-scaled window (up to 8s per
		// worker), whose amortisability across addresses was a BACKLOG concern of its own.
		if ( ChainToken::LENGTH_V2 === $token_length || ChainToken::LENGTH === $token_length ) {
			$now_ms      = (int) round( microtime( true ) * 1000 );
			$chain_is_v2 = ChainToken::LENGTH_V2 === $token_length;
			$chain_valid = $chain_is_v2
				? ChainToken::verify_integrity( $token, $salt, $now_ms, $time_window )
				: ChainToken::verify( $token, $this->get_client_ip(), $salt, $now_ms, $time_window );

			if ( $chain_valid ) {
				$valid = $this->poll_for_row(
					function () use ( $token, $time_window ) {
						return $this->consume_token_row( $token, $time_window );
					}
				);
				if ( $valid ) {
					return $valid;
				}
				// Chain row never landed within the window — one IP-fallback
				// consumption, no further polling, mirroring the base token path below.
				// Record WHY this path failed before the fallback attempt: if the
				// fallback still succeeds, check_request() returns true and
				// check_submit() never reads the reason (observe only, no cleanup).
				$this->pow_fail_reason = Classification_Reason::NO_POW_CHAIN_NO_ROW;
				return $this->consume_ip_row( $time_window, $max_uses );
			}
		}

		// Base-token path: 100 = v2 (integrity only, no IP), 92 = in-flight legacy.
		$token_is_v2 = StampToken::LENGTH_V2 === $token_length;
		if ( $token_is_v2 ) {
			$token_valid = StampToken::verify_integrity( $token, $salt, time(), $time_window );
		} else {
			$token_valid = StampToken::LENGTH === $token_length
				&& StampToken::verify( $token, $this->get_client_ip(), $salt, time(), $time_window );
		}

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
			// consumption, no further polling. Reason recorded before the fallback for
			// the same reason as the chain path above.
			//
			// PURE LABELLING, NOT A DECISION: a fingerprint mismatch only picks the more
			// specific reason string (the cache/proxy signature), so the site owner can
			// tell "the handshake broke" from "this token came from somewhere else".
			// The fallback attempt below is identical either way.
			$mismatched = $token_is_v2
				&& StampToken::STATUS_MISMATCH === StampToken::fp_status( $token, $this->get_client_ip(), $salt );

			$this->pow_fail_reason = $mismatched
				? Classification_Reason::NO_POW_TOKEN_IP_CHANGED
				: Classification_Reason::NO_POW_TOKEN_NO_ROW;
			return $this->consume_ip_row( $time_window, $max_uses );
		}

		// No usable token at all: either none was posted, or one was posted and failed
		// verification (forged, expired, wrong length, or a chain token whose
		// verification returned false above).
		$this->pow_fail_reason = '' === $token
			? Classification_Reason::NO_POW_NO_TOKEN
			: Classification_Reason::NO_POW_INVALID_TOKEN;
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
		$raw_stamp = $fields['hashStamp'] ?? '';
		$stamp     = is_string( $raw_stamp ) ? preg_replace( '/[^a-zA-Z0-9]/', '', $raw_stamp ) : '';
		$nonce     = '';

		// The nonce. is_string() guard: a posted hashNonce[] array would make
		// ctype_digit() a fatal TypeError on PHP 8 (unauthenticated).
		if ( is_string( $fields['hashNonce'] ?? '' ) && ctype_digit( $fields['hashNonce'] ?? '' ) ) {
			$nonce = filter_var( $fields['hashNonce'], FILTER_SANITIZE_NUMBER_INT );
		}

		// The POSTed hashDifficulty and clientIP fields are read NOWHERE anymore: the
		// difficulty that counts is the HMAC-bound one inside the token, and a client-
		// supplied address was never trustworthy to begin with. Old cached JS keeps
		// posting both — they are simply ignored (no wp_die(), which is what makes that
		// compatible). See POW_IP_BINDING_PLAN.md §3/§5.

		$this->print_debug_information( "stamp: $stamp" );
		$this->print_debug_information( "nonce: $nonce" );

		// Length decides the format: 100 = base token (v2), 120 = re-challenge chain
		// token (v2), 92/112 = the same two formats issued by the previous release and
		// still in flight (accepted for one release, see BACKLOG). All are exclusively
		// hex/decimal, so this replaces the old single-length gate.
		$stamp_length = strlen( $stamp );

		if ( StampToken::LENGTH_V2 === $stamp_length || StampToken::LENGTH === $stamp_length ) {
			// Base-token path. v2 (100) is verified for INTEGRITY ONLY — no IP enters
			// StampToken::verify_integrity(), so a token issued behind a cache or to a
			// rotating address still validates. v1 (92) keeps its IP-bound verify() for
			// one release (in-flight tokens). The posted hashDifficulty/clientIP fields
			// are ignored on both: the difficulty that matters is the one embedded (and
			// HMAC-bound) in the token itself.
			$token_is_v2      = StampToken::LENGTH_V2 === $stamp_length;
			$parsed           = $token_is_v2 ? StampToken::parse_v2( $stamp ) : StampToken::parse( $stamp );
			$token_difficulty = $parsed ? (int) $parsed['difficulty'] : null;

			// The difficulty is HMAC-bound inside the token (StampToken::create_v2()),
			// so a client cannot forge a lower value than what the server actually
			// issued — accepting anything >= the CURRENT base option (AP4: the base
			// or the under-attack boost may have changed between issuing and solving)
			// is safe and avoids rejecting a just-issued, correctly higher-difficulty
			// token. There is deliberately NO upper bound: get_stamp() issues base +
			// boost without a ceiling, so any ceiling here would reject the server's
			// own freshly issued tokens.
			if ( ! $parsed || $token_difficulty < (int) get_option( Option::POW_DIFFICULTY ) ) {
				$this->print_debug_information( 'Token difficulty below current base, or unparseable token' );
				wp_die();
			}

			$token_intact = $token_is_v2
				? StampToken::verify_integrity( $stamp, get_option( Option::POW_SALT ), time(), get_option( Option::POW_TIME_WINDOW, 10 ) )
				: StampToken::verify( $stamp, $this->get_client_ip(), get_option( Option::POW_SALT ), time(), get_option( Option::POW_TIME_WINDOW, 10 ) );

			if ( ! $token_intact ) {
				$this->print_debug_information( 'Token is incorrect or expired' );
				wp_die();
			}

			if ( $this->check_proof_of_work( $token_difficulty, $stamp, $nonce ) ) {
				$this->print_debug_information( 'Difficulty target met.' );
			} else {
				$this->print_debug_information( 'Difficulty target was not met.' );
				wp_die();
			}

			// NO SOLVE-TIME GATE HERE ANY MORE — and none may come back. A verified solve
			// is persisted, full stop.
			//
			// The gate that used to sit here (0a0c403, shipped in 5.3.0) measured
			// `time() - issued_at` and answered "too fast" with a harder re-challenge
			// chain. It was removed on the owner's decision after a Fable review; the
			// reasoning, in short:
			//   - The server measures ISSUE-TO-ARRIVAL, not compute time. A native solver
			//     that cracks the puzzle in microseconds simply SLEEPS before answering.
			//     Waiting is free and parallelisable, so the gate only ever caught clients
			//     that were fast AND protocol-naive — and those already die in
			//     check_request(), never having parsed the re-challenge at all.
			//   - Solve time is exponentially distributed, so an HONEST client beats the
			//     mean-work threshold with probability 1 - exp(-H_real/H_MAX) ~ 10-22 %,
			//     independent of difficulty. The gate therefore had a built-in false
			//     positive rate that only network latency hid at low difficulties.
			//   - It cost real users delivery: the client adopts the not-yet-solved chain
			//     token as its submission token, so a submission sent during that round
			//     found no stamp row and was failed closed (HANDBUCH.md §12 cause 6, the
			//     5.3.1 Spectra follow-up report).
			// BACKLOG.md said all of this on 2026-07-16 ("Zeit-Gating … als harter Gate
			// VERWORFEN", breaking point (b) "Pre-Solve-and-Age") before the gate was built
			// the same afternoon. Read that entry before proposing timing again.
			// Pinned by StampWiringTest and tests/integration/cases/no-solve-time-gate.mjs.
		} elseif ( ChainToken::LENGTH_V2 === $stamp_length || ChainToken::LENGTH === $stamp_length ) {
			// TRANSITIONAL chain path — accept-only, one release long (same pattern as the
			// 92/112 legacy token formats). Chains are no longer issued anywhere, but a
			// client that was mid-chain when the site updated still holds a valid chain
			// token and must be able to redeem it instead of silently losing its paid
			// solve. Verify, check the PoW target, insert — never re-challenge, never
			// feed a counter. Removal together with the ChainToken class, see BACKLOG.
			//
			// The sanitisation above already keeps only [a-zA-Z0-9]; a chain token is pure
			// hex, so it survives.
			$chain_is_v2 = ChainToken::LENGTH_V2 === $stamp_length;
			$parsed      = $chain_is_v2 ? ChainToken::parse_v2( $stamp ) : ChainToken::parse( $stamp );
			$dd          = $parsed ? (int) $parsed['difficulty'] : null;

			// Difficulty gate mirrors the base-token path: the DD is HMAC-bound inside the
			// chain token, so a client cannot lower it — accept anything from the current
			// base upwards (an in-flight chain escalated a bit above the base it started
			// from, and the base/boost may have shifted since).
			if ( ! $parsed || $dd < (int) get_option( Option::POW_DIFFICULTY ) ) {
				$this->print_debug_information( 'Chain token difficulty below base, or unparseable.' );
				wp_die();
			}

			// v2 verifies integrity only (no IP — a chain spans several requests by
			// construction); v1 keeps its IP-bound verify() for in-flight chains.
			$now_ms      = (int) round( microtime( true ) * 1000 );
			$chain_valid = $chain_is_v2
				? ChainToken::verify_integrity( $stamp, get_option( Option::POW_SALT ), $now_ms, get_option( Option::POW_TIME_WINDOW, 10 ) )
				: ChainToken::verify( $stamp, $this->get_client_ip(), get_option( Option::POW_SALT ), $now_ms, get_option( Option::POW_TIME_WINDOW, 10 ) );

			if ( ! $chain_valid ) {
				$this->print_debug_information( 'Chain token is incorrect or expired.' );
				wp_die();
			}

			// PoW target with the chain token's own difficulty.
			if ( ! $this->check_proof_of_work( $dd, $stamp, $nonce ) ) {
				$this->print_debug_information( 'Chain difficulty target was not met.' );
				wp_die();
			}

			$this->print_debug_information( 'In-flight chain token redeemed (accept-only).' );
		} else {
			// The pre-AP3 64-char bucket stamp is gone (it was the last path that believed
			// a POSTed IP, and back then the only one without a solve-time gate — a gate
			// that no longer exists anywhere; a stamp in that
			// format could only come from a >1-year-old cache copy and would be expired
			// anyway).
			$this->print_debug_information(
				"stamp size: $stamp_length expected: " . StampToken::LENGTH_V2 . ', ' . ChainToken::LENGTH_V2
				. ' (or ' . StampToken::LENGTH . '/' . ChainToken::LENGTH . ' in flight)'
			);
			wp_die();
		}

		// DIAGNOSIS ONLY, and deliberately placed here: at this point the solve is
		// accepted and about to be persisted, so measuring where it came from can no
		// longer influence the verdict. No wp_die() may ever appear between this call
		// and the INSERT below (pinned by StampWiringTest).
		$this->record_fp_status( $stamp, $stamp_length );

		global $wpdb;
		$hashed_ip = $this->hash_values( $this->get_client_ip() );
		// Delete all lines which are older than the predefined time limit + 2 minutes buffer time
		//
		// THE DEFAULT IS LOAD-BEARING and was missing here while every other reader of
		// this option passes it (check_request(), both verify calls above). Without it, an
		// installation whose option row is absent deletes rows after 2 minutes while its
		// tokens stay valid for 12 — so a visitor who takes longer than two minutes to
		// fill in a form posts a perfectly valid token whose row the next visitor's
		// check_stamp has already swept away: no_pow:token_no_row with an empty IP
		// fallback, on a site where nothing is broken. That is the reported symptom
		// exactly (HANDBUCH.md §12), reachable without a single defect elsewhere.
		$wpdb->query(
			$wpdb->prepare(
				'DELETE FROM ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs
                            WHERE rgs_time < NOW() - INTERVAL %d MINUTE',
				(int) get_option( Option::POW_TIME_WINDOW, 10 ) + 2
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
		// guard here would be racy under concurrency; the unique key is not.
		//
		// rgs_ip stays the hashed, server-resolved address: pure bookkeeping for the
		// IP fallback in check_request() (no-JS clients, cached pages), NOT a condition
		// on this token's validity.
		$inserted = $wpdb->query(
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

		// {accepted:true} MUST MEAN "a row exists for this token" — the client treats that
		// answer as its licence to publish the token as the submission token, and
		// check_request() will look for exactly this row.
		//
		// The catch is IGNORE: it downgrades a REAL failure (missing table, half-applied
		// migration, read-only/full database) to a warning and returns 0 — the very same 0
		// a legitimate duplicate returns. So 0 is ambiguous and has to be resolved by
		// looking, and only then; the extra SELECT never runs on the healthy path (a
		// successful insert returns 1).
		//
		// Answering {accepted:true} anyway is what made a broken-storage site
		// undiagnosable: a green handshake, and every single submission afterwards
		// classified no_pow:token_no_row (HANDBUCH.md §12 cause 7).
		if ( 1 !== (int) $inserted ) {
			$row_exists = (int) $wpdb->get_var(
				$wpdb->prepare(
					'SELECT COUNT(*) FROM ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs WHERE rgs_stamp = %s',
					$stamp
				)
			);

			if ( $row_exists < 1 ) {
				$this->record_store_failure( (string) $wpdb->last_error );
				// NOT a rejection of the proof of work — the solve was valid, this server
				// just cannot keep it. Fail-closed is untouched (no row means the
				// submission still has to pass check_request()); the client simply must
				// not publish a token it has no row for, and gets told so instead of
				// being lied to.
				wp_send_json(
					array(
						'accepted' => false,
						'stored'   => false,
					)
				);
			}
		}

		// Every path that reaches this point is an accepted, persisted solve — the two
		// re-challenge branches and every rejection already left the function. Answer
		// {accepted:true}; wp_send_json() sends the body and stops execution. Old cached
		// JS clients never read the body, so this is safe for them too.
		//
		// (Until the legacy 64-char path was removed there was a $send_accepted flag here
		// because that one path answered with a bare wp_die() instead. With the flag now
		// constantly true, keeping it would be dead branching, not documentation.)
		wp_send_json( array( 'accepted' => true ) );
	}

	/** Count where an accepted solve came from — MEASUREMENT, NEVER A DECISION.
	 *
	 * Compares the token's fingerprint field against a fingerprint of the address
	 * solving it now. A mismatch means the token was issued to a different address
	 * (page/response cache shared between visitors, proxy pool, IPv4/IPv6 dual stack) —
	 * the very situation v2 exists to tolerate. Nothing here rejects, re-challenges or
	 * raises difficulty; the numbers only answer the site owner's structural question
	 * "is a cache/proxy sitting in front of my site?" (settings status strip, dashboard
	 * widget) and point at POW_TRUSTED_PROXIES.
	 *
	 * ANONYMOUS (render-path token, or a legacy 92/112 token that has no fingerprint at
	 * all) feeds neither counter — "not measured" must not look like "matched".
	 *
	 * Non-atomic get+update on purpose, the same accepted trade-off as the under-attack
	 * spam counter: a lost increment under concurrency changes a diagnostic ratio by a
	 * hair and never a security decision. autoload=no — these are read on two admin
	 * screens, not on every front-end request.
	 *
	 * The ratio is COLOURABLE by an attacker: replaying one solved token+nonce from
	 * rotating addresses bumps the mismatch counter each time (this runs before the
	 * INSERT IGNORE that collapses the duplicate). Harmless by construction — nothing
	 * reacts to the number — but a site owner reading an implausible ratio should know
	 * it is a measurement, not evidence.
	 *
	 * @param string $stamp        The accepted stamp/token.
	 * @param int    $stamp_length Its length (decides the format).
	 * @return void
	 */
	private function record_fp_status( $stamp, $stamp_length ) {
		$salt = get_option( Option::POW_SALT );

		if ( StampToken::LENGTH_V2 === $stamp_length ) {
			$status = StampToken::fp_status( $stamp, $this->get_client_ip(), $salt );
		} elseif ( ChainToken::LENGTH_V2 === $stamp_length ) {
			$status = ChainToken::fp_status( $stamp, $this->get_client_ip(), $salt );
		} else {
			// Legacy in-flight formats carry no fingerprint.
			return;
		}

		if ( StampToken::STATUS_MATCH === $status ) {
			update_option( Option::POW_FP_MATCHED_TOTAL, (int) get_option( Option::POW_FP_MATCHED_TOTAL, 0 ) + 1, false );
		} elseif ( StampToken::STATUS_MISMATCH === $status ) {
			update_option( Option::POW_FP_MISMATCHED_TOTAL, (int) get_option( Option::POW_FP_MISMATCHED_TOTAL, 0 ) + 1, false );
			update_option( Option::POW_FP_LAST_MISMATCH_AT, time(), false );
		}
	}

	/** Measure what `…_stamp_rgs` actually held while a submission was being classified
	 * "no proof of work" — the evidence the reason string cannot carry.
	 *
	 * MEASUREMENT, NEVER A DECISION: this runs AFTER check_request() has already
	 * returned false, its result is only ever written to a technical detail row, and no
	 * code path reads it back. It cannot change a verdict, in either direction.
	 *
	 * Deliberately queried WITHOUT the `rgs_time >= NOW() - INTERVAL …` filter the
	 * consume queries use: "there was a row, but it was outside the window" and "there
	 * was no row at all" are opposite findings, and a filtered query reports both as
	 * nothing — which is exactly the ambiguity that cost two support rounds.
	 *
	 * Cost: at most three SELECTs, only ever on the already-slow spam path (which has
	 * just spent up to 2 seconds polling), never on a clean submission.
	 *
	 * @param string $token The sanitized token check_request() evaluated ('' when none).
	 * @return string Classification_Reason::pow_probe() string.
	 */
	private function measure_pow_probe( $token ) {
		global $wpdb;

		$token_row = null;
		if ( '' !== $token ) {
			$token_row = $wpdb->get_row(
				$wpdb->prepare(
					'SELECT rgs_uses, TIMESTAMPDIFF( SECOND, rgs_time, NOW() ) AS age_s
					   FROM ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs
					  WHERE rgs_stamp = %s
					  LIMIT 1',
					$token
				)
			);
		}

		// The address side, measured on ONE row — the NEWEST, which is the one a healthy
		// handshake just created and therefore the one a reader wants to see.
		//
		// An earlier version aggregated MIN(age) and MIN(uses) over all rows of the
		// address and called that "the best case the fallback had". It is not: the
		// fallback needs freshness AND remaining budget ON THE SAME ROW, so a fresh
		// exhausted row next to an old unused one would have printed `age_s=5,uses=0` —
		// a state no single row was in, reading as "the fallback should have worked".
		// A measurement that can describe a row that does not exist is worse than none.
		$ip_count = (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs WHERE rgs_ip = %s',
				$this->hash_values( $this->get_client_ip() )
			)
		);

		$ip_row = null;
		if ( $ip_count > 0 ) {
			$ip_row = $wpdb->get_row(
				$wpdb->prepare(
					'SELECT rgs_uses, TIMESTAMPDIFF( SECOND, rgs_time, NOW() ) AS age_s
					   FROM ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs
					  WHERE rgs_ip = %s
					  ORDER BY rgs_time DESC, rgs_id DESC
					  LIMIT 1',
					$this->hash_values( $this->get_client_ip() )
				)
			);
		}

		$ip_rows = $ip_row ? $ip_count : 0;

		return Classification_Reason::pow_probe(
			$token_row ? 1 : 0,
			$token_row ? $token_row->age_s : null,
			$token_row ? $token_row->rgs_uses : null,
			$ip_rows,
			$ip_row ? $ip_row->age_s : null,
			$ip_row ? $ip_row->rgs_uses : null
		);
	}

	/** Record that an ACCEPTED solve could not be stored — the one failure mode the
	 * plugin used to answer {accepted:true} to.
	 *
	 * Not a security decision and not a rate limit: purely the signal the site owner
	 * needs. Without it, a site whose `…_stamp_rgs` table is missing or unwritable looks
	 * perfectly healthy from the outside (get_stamp fine, check_stamp "accepted") while
	 * classifying every single submission as spam — the shape that cost two support
	 * rounds to even locate (HANDBUCH.md §12 cause 7).
	 *
	 * The database error is stored verbatim but capped, because it is the only thing
	 * that names the actual cause ("Table '…_stamp_rgs' doesn't exist", "The MySQL server
	 * is running with the --read-only option"). It is rendered escaped on the settings
	 * screen and never used in a query. Non-atomic get+update on purpose, the same
	 * accepted trade-off as the fingerprint counters.
	 *
	 * @param string $db_error $wpdb->last_error at the time of the failure ('' if the
	 *                         driver reported none — a silently swallowed IGNORE).
	 * @return void
	 */
	private function record_store_failure( $db_error ) {
		update_option( Option::POW_STORE_FAILED_TOTAL, (int) get_option( Option::POW_STORE_FAILED_TOTAL, 0 ) + 1, false );
		update_option( Option::POW_STORE_LAST_FAILED_AT, time(), false );
		update_option( Option::POW_STORE_LAST_ERROR, substr( sanitize_text_field( $db_error ), 0, 200 ), false );
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
