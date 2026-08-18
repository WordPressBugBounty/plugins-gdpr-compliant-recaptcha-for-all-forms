<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene) — als einzige Klasse ueber drei Bereiche verteilt:
//   handbuch/pow.md        Token-Ausgabe, check_stamp, check_request, get_client_ip
//   handbuch/gate.md       Konstruktor-Gate, run(), Login-Pfad, Signatur-Matcher
//   handbuch/detection.md  check_submit() samt seiner sechs Klassifikationsstufen
// Die PERSISTENZ-Haelfte von detection.md (save_message(), save_for_analysis(),
// Fail2Ban) steht seit Welle 5b in trait-stamp-persistence.php — dieselbe Klasse,
// zweite Datei; die Begruendung des Schnitts steht in deren Kopf-Docblock.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Class Stamp: Each instance of that class is intended to hold the Stamp and all checks around it
 *
 */
class Stamp {

	// Die PERSISTENZ-Haelfte dieser Klasse steht seit Dateigroessen-Welle 5b
	// (PLAN-DATEIGROESSE.md) in trait-stamp-persistence.php: save_for_analysis(),
	// save_message() samt Feldbaum-Abflachung, die Analyse-Urteil-Upserts und
	// log_fail2ban_event(). Dort steht auch, warum ein Trait und keine zweite Klasse.
	// Ein Trait wird zur Kompilierzeit hineinkopiert — $this->save_message() & Co.
	// bleiben unveraendert Methoden von Stamp, mit denselben Eigenschaften.
	use Stamp_Persistence;

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

	/**
	 * The `rgm_id` of the type-4 analysis row save_for_analysis() wrote for THIS
	 * request, or null when analysis mode wrote nothing.
	 *
	 * Kept because save_for_analysis() runs in the CONSTRUCTOR, i.e. before any
	 * check_submit(), so at write time $classification_reason and $clean_scoring are
	 * still null and the row gets neither. Whoever opens the analysis mode is asking
	 * exactly the question those two answer ("why was this flagged — or why was it
	 * not?"), so the values are written onto the existing row afterwards instead.
	 *
	 * @var int|null
	 */
	private $analysis_row_id = null;

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
		// Check whether the IP is whitelisted.
		//
		// Compared through ClientIp::matches_list() — THE address-list comparison of
		// this plugin — not with `===` as it was until 5.3.4. The string compare meant
		// the notation decided: ClientIp::resolve() hands back the candidate verbatim,
		// exactly as the proxy wrote it, so an operator who noted their office IPv6
		// differently than their proxy sends it (or whose visitors arrive as
		// ::ffff:203.0.113.5) silently had no whitelist at all, without any feedback.
		// Subnets could not be entered either. Two consequences of the change, both
		// intended: notations that denote the same address now compare equal, and a
		// CIDR line works. A `/0` line does NOT (see ClientIp::ip_in_cidr) — otherwise
		// "whitelist everything" would be a one-liner.
		$ip_whitelisted = ClientIp::matches_list(
			$this->get_client_ip(),
			preg_split( '/\r\n|\n|\r/', (string) get_option( Option::POW_IP_WHITELIST ), -1, PREG_SPLIT_NO_EMPTY )
		);

		// Check whether the site is whitelisted.
		//
		// THE HOST COMES FROM THE SERVER, NEVER FROM THE REQUEST. Until 5.3.4 this
		// matched against HTTP_HOST . REQUEST_URI, and HTTP_HOST is set by the client —
		// so anyone who knew a configured line could claim the whitelist with a single
		// forged header and pass unevaluated (measured, ISSUES.md). It was the last
		// remnant of the header-decides-the-gate class that the referer terms belonged
		// to. Host AND port are taken from the `home` option (the port matters: an
		// install reachable on :8080 has entries written that way), plus `siteurl` as a
		// second admissible host for setups whose wp-admin lives on another domain.
		//
		// Semantics of existing entries are preserved as long as they name the site's
		// REAL host. Entries naming an alias (www. vs. bare, a mapped second domain)
		// stop matching — fail-safe (the whitelist only ever gets narrower, never
		// wider), but a real behaviour change, hence documented in handbuch/gate.md.
		$site_whitelisted = false;
		$lines            = preg_split( '/\r\n|\n|\r/', (string) get_option( Option::POW_SITE_WHITELIST ), -1, PREG_SPLIT_NO_EMPTY );
		if ( count( $lines ) > 0 && array_key_exists( 'REQUEST_URI', $_SERVER ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared, never output or stored; sanitizing would alter the path being compared.
			$request_uri = preg_replace( '/^(https?:\/\/)/i', '', (string) wp_unslash( $_SERVER['REQUEST_URI'] ) );
			foreach ( self::server_known_hosts() as $host ) {
				foreach ( $lines as $line ) {
					$line = trim( $line );
					if ( '' !== $line && strpos( $host . $request_uri, $line ) === 0 ) {
						$site_whitelisted = true;
					}
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
		// by the request's own action/body shape) and on `POW_SITE_WHITELIST`, whose
		// host half no longer comes from the request at all — since 5.3.4 the lines are
		// matched against `server_known_hosts() . REQUEST_URI`, i.e. the hosts derived
		// from the `home`/`siteurl` options (see the block above), so a forged `Host`
		// header can no longer claim an admin-entered whitelist line. Both are
		// ADMIN-configured or fixed integration endpoints, not switches a visitor turns
		// on; that is the line this gate holds.
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
	/**
	 * The host[:port] values this installation is actually reachable under, taken from
	 * its own options — never from the request.
	 *
	 * Two entries at most, deduplicated: `home` (where visitors are) and `siteurl`
	 * (where wp-admin is; on most installs identical, on some a different domain). The
	 * PORT is part of the value on purpose: `HTTP_HOST` carried it, so a POW_SITE_WHITELIST
	 * line for an install served on :8080 was written with it, and dropping it here
	 * would silently stop matching those lines.
	 *
	 * Reads the raw options rather than home_url()/site_url(): this runs at plugin
	 * include time, before third-party filters on those functions are registered, so
	 * the option value is both what they would return and the more predictable source.
	 * Multisite needs no special case — the options are resolved per site.
	 *
	 * @return string[] Lower-cased host[:port] values, possibly empty.
	 */
	private static function server_known_hosts() {
		$hosts = array();
		foreach ( array( 'home', 'siteurl' ) as $option_name ) {
			$url  = (string) get_option( $option_name );
			$host = (string) wp_parse_url( $url, PHP_URL_HOST );
			if ( '' === $host ) {
				continue;
			}
			$port    = wp_parse_url( $url, PHP_URL_PORT );
			$hosts[] = strtolower( $host ) . ( $port ? ':' . (int) $port : '' );
		}

		return array_values( array_unique( $hosts ) );
	}

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
						// EVERY name from here is ATTACKER-SUPPLIED. hashPWFields travels
						// with the request; until 5.3.4 each key and each string leaf of
						// the decoded structure became an exempt field name unchecked. A
						// bot that passes the PoW (headless browser running our own JS —
						// the class the 2026-07-16 field data documents) and has read the
						// publicly available source could therefore list its target's real
						// field names ("your-message", "your-email") as hashPWFields
						// entries and become invisible to gibberish scoring, whatever it
						// actually sent. See ISSUES.md.
						//
						// The marker's legitimate job is narrow: naming the password
						// fields of THIS form so their values are not scored as gibberish.
						// So a name is only honoured if it plausibly IS a credential field
						// name. A password field with an unusual name loses its exemption
						// until an admin confirms it — that is what Credential_Learning's
						// suggestion path is for, and its learned names are added below,
						// server-side and unfiltered.
						if ( is_string( $key ) && '' !== $key && Credential_Fields::is_password_key( $key ) ) {
							$names[] = $key;
						}
						if ( is_array( $value ) ) {
							$stack[] = $value;
						} elseif ( is_string( $value ) && '' !== $value && Credential_Fields::is_password_key( $value ) ) {
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
		 * @since 5.3.2
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

			// One line, one rule. Trimming, JSON-decoding and comparing are ALL
			// Pattern_Matcher's job — deliberately not done here, so the settings page's
			// save-time warning (Pattern_Matcher::overbroad_lines()) cannot drift away
			// from what this gate actually matches. See class-pattern-matcher.php.
			foreach ( $existing_lines_pattern as $line ) {
				if ( Pattern_Matcher::line_matches( $line, $this->whole_request_data ) ) {
					$pattern_found = true;
				}
			}
		}
		// A blocked value (POW_BLOCKED_VALUES) also makes an otherwise-unmonitored
		// form monitored, so the wildcard classification in check_submit() can fire
		// on ANY form (the whole point of "across all forms"). Evaluated over the
		// user-content POST fields only (Echo_Values skips technical keys).
		if ( $this->matches_blocked_values( self::strip_plugin_fields( $this->request_data ) ) ) {
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
	 * Whether any part of $fields matches the operator's blocklist (POW_BLOCKED_VALUES) —
	 * the instance-side name the two call sites in this class use. The evaluation itself is
	 * blocklist_matches() below, shared with the diagnosis path; the four match forms
	 * (exact field value, extracted email address, registrable domain of an embedded URL,
	 * "@sender-domain") live entirely in the pure Echo_Values class and are not restated
	 * anywhere.
	 *
	 * @param mixed $fields Field map to test.
	 * @return bool
	 */
	private function matches_blocked_values( $fields ) {
		return self::blocklist_matches( $fields );
	}

	/**
	 * THE blocklist evaluation — "does POW_BLOCKED_VALUES hit this submission?" — in one
	 * place, for the live classification AND for the agent-facing diagnosis
	 * (Abilities::wildcard_hit()). Its own docblock states the requirement: a diagnostic
	 * that judged differently from production would be worse than none. Sharing the
	 * function is how that stops being a matter of discipline.
	 *
	 * Two line shapes, one option, both read by Echo_Values::partition_blocklist_lines():
	 * - PLAIN VALUES (the short form, and the folded {"*":"value"} spelling) go through
	 *   Echo_Values::matches_wildcard_values() exactly as they always have.
	 * - RULES (a line written as a JSON object, e.g. {"_wpcf7":"123","your-email":
	 *   "@gmail.com"}) go through Pattern_Matcher::line_matches_blocked(), i.e. through the
	 *   plugin's ONE field traversal with the four blocked-value comparisons at its value
	 *   positions. Unreadable lines match nothing; the settings page names them at save
	 *   time.
	 *
	 * A hit still both makes the form monitored (check_existing_patterns()) and classifies
	 * the submission as spam under the unchanged reason code
	 * Classification_Reason::CODE_WILDCARD.
	 *
	 * @param mixed $fields Field map to test.
	 * @return bool
	 */
	public static function blocklist_matches( $fields ) {
		$option = (string) get_option( Option::POW_BLOCKED_VALUES );
		if ( '' === trim( $option ) ) {
			return false;
		}
		$lines     = preg_split( '/\r\n|\n|\r/', $option, -1, PREG_SPLIT_NO_EMPTY );
		$partition = Echo_Values::partition_blocklist_lines( is_array( $lines ) ? $lines : array() );

		$own_domains = Echo_Store::site_domains();
		if ( ! empty( $partition['values'] )
			&& Echo_Values::matches_wildcard_values( $fields, $partition['values'], $own_domains ) ) {
			return true;
		}
		foreach ( $partition['rules'] as $rule ) {
			if ( Pattern_Matcher::line_matches_blocked( $rule, $fields, $own_domains ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The operator's blocked values (the plain-text lines of POW_BLOCKED_VALUES),
	 * normalized. Pure get_option() glue around Echo_Values::values_from_plaintext_lines().
	 *
	 * NOT Echo_Values::wildcard_values_from_lines(): that one reads the LEGACY JSON form
	 * ({"*":"value"} inside POW_PARAMETER_PATTERN) and exists only for the one-time
	 * migration. Both return the same normalized value list, so nothing downstream had to
	 * change when the source moved.
	 *
	 * PLAIN VALUES ONLY, and that is a decision rather than a leftover. The login exemption
	 * (is_exempt_login_submission()) is the one caller, and it asks which ADDRESSES caused a
	 * block; a field-bound RULE has no place in that question, so a rule-caused block on the
	 * login screen is never exempted — fail CLOSED, like everything else on that path. The
	 * long spelling {"*":"value"} is folded into the values by
	 * Echo_Values::partition_blocklist_lines(), so it is exempted exactly like the short
	 * form it is a spelling of; only genuinely field- or form-bound rules fall outside, and
	 * those reach a login POST only if the operator bound them to login fields on purpose.
	 *
	 * @return string[] Normalized blocked values, empty when the option holds none.
	 */
	private function blocked_values() {
		$option = (string) get_option( Option::POW_BLOCKED_VALUES );
		if ( '' === trim( $option ) ) {
			return array();
		}
		$lines = preg_split( '/\r\n|\n|\r/', $option, -1, PREG_SPLIT_NO_EMPTY );
		return Echo_Values::values_from_plaintext_lines( $lines );
	}

	/**
	 * Whether this submission is exempt from the WILDCARD classification because it is a
	 * registered user signing in on the WordPress login screen.
	 *
	 * THE RULE, verbatim: on the login surface, the exemption applies exactly when the set
	 * B of addresses that an ADDRESS-BASED blocklist comparison hit (exact address equality
	 * against an entry without "@", or a sender-domain hit against an "@" entry —
	 * Echo_Values::blocked_emails()) is NOT EMPTY and EVERY address in it belongs to a
	 * registered user (Echo_Values::all_emails_exempt() against
	 * Echo_Store::user_email_hashes()). An empty B — the wildcard hit came from
	 * whole-value equality or an URL domain, not from an address — grants nothing: fail
	 * closed.
	 *
	 * WHY THE EXEMPTION EXISTS. A blocked value is allowed to name a whole sender domain
	 * ("@gmail.com"), and with POW_BLOCK_LOGIN on (the default) the login POST runs
	 * through the same classification as any form. Without this exemption, every
	 * registered user who signs in WITH THEIR EMAIL ADDRESS is classified as spam and
	 * locked out — in the worst case the operator, who then cannot reach the setting
	 * again to undo it. The auto-echo lock has had an exemption for exactly this since it
	 * shipped (Echo_Store::user_email_hashes() as the exclude set of build_echo_set());
	 * the blocklist did not.
	 *
	 * WHY IT IS CUT THIS NARROW — the expensive insight of this change, do not widen it:
	 *
	 * - NOT "registered addresses are exempt everywhere". On a site with open
	 *   registration that would be a full bypass: the spammer signs up as
	 *   spam@mailinator.com and from that moment every admin block on his address or
	 *   domain is inert on every content form. The echo lock tolerates the broad
	 *   exemption because it LEARNED its own values and the exemption protects it from
	 *   self-poisoning; the blocklist is an explicit ORDER by the operator and must
	 *   be obeyed on content forms.
	 * - The anchor is the login SCREEN, taken from the server-set SCRIPT_FILENAME, not
	 *   anything derived from the request body. Any "this looks like a login" signal read
	 *   out of the submission (field names, presence of a password field) would be
	 *   attacker-colorable — the spammer would simply name his fields log/pwd and open
	 *   precisely the bypass rejected above. Frontend login forms of membership plugins
	 *   are therefore knowingly OUTSIDE the exemption; that is a design limit, not an
	 *   oversight.
	 * - Reusing Overbroad_Pattern_Guard::screen_file() rather than re-deciding the
	 *   question here is deliberate: there is ONE implementation of "which screen is
	 *   this". The guard is loaded before this class (recaptcha-gdpr-compliant.php).
	 * - $origin === 'login' is an ADDITIVE second term, for the case where
	 *   pre_process_login() (wp_authenticate_user / password_reset) is actually reached.
	 *   It must never be the only anchor: when the constructor's own
	 *   check_existing_patterns() path classifies the login POST, check_submit() is
	 *   called WITHOUT an origin, so an $origin-only exemption would be dead code.
	 * - A registered ADDRESS is still required. A stranger trying to sign in with a
	 *   blocked address is classified as before; a new registration with a blocked domain
	 *   likewise stays blocked (that address is not registered yet). Username-only logins
	 *   carry no address and can never be hit by an address rule in the first place.
	 * - THE BLOCKED addresses must be registered — not merely SOME address in the
	 *   submission. This is the expensive lesson of 2026-08-13 and the whole reason the
	 *   rule is written over a SET. The first version asked "does this submission carry
	 *   any registered address?" (the former Echo_Values::contains_exempt_email(), over
	 *   ALL content fields). Measured against blocklist entry "@blocked.test" and the
	 *   registered chef@site.example: `log=stranger@blocked.test` was blocked correctly,
	 *   but the same POST plus `freeride=chef@site.example` came through — as did the same
	 *   address parked in `pwd` or in `redirect_to=/x?u=chef@site.example`. Anyone who
	 *   knows ONE registered address (usually the publicly findable admin address) could
	 *   thereby buy the exemption for ARBITRARY blocked identities. He gained no
	 *   authentication (the password is still required), but the exemption was bought, not
	 *   earned. Now the extra address is simply not in B, so it buys nothing; and the
	 *   ALL-quantor closes the remaining case where the attacker knows a registered
	 *   address AT the blocked domain (B then holds both, his own is not registered).
	 * - The fix is deliberately NOT "only look at the login fields (log/pwd)". A field-name
	 *   coupling would re-introduce exactly the attacker-colorable, request-derived signal
	 *   the SCREEN anchor above exists to avoid: field names are the attacker's to choose,
	 *   so he would move his blocked address out of `log` into a field the exemption does
	 *   not read and be exempt again. The set rule needs no request-derived signal at all —
	 *   which is why it was preferred over that (and over restricting the exemption to
	 *   submissions with exactly one address, which would break every login form that also
	 *   posts a redirect URL).
	 *
	 * KNOWN, ACCEPTED WIDTH (measured in the acceptance review of this very fix): the
	 * exemption lifts the WHOLE wildcard verdict for that submission, not just its address
	 * half. So a registered user at a blocked domain may, on wp-login.php only, also carry a
	 * value blocked by a LITERAL or URL-domain line without being classified. The price is a
	 * missing spam row for that one POST: the request still lands in WordPress' own login
	 * handling, still needs the password and a solved token, and nothing is stored or
	 * published. Narrowing this further would mean classifying a login per matched value
	 * instead of per submission — more machinery than the residue is worth.
	 *
	 * ORDER IS LOAD-BEARING: the cheap screen/origin test runs FIRST, then the pure,
	 * WordPress-free computation of B, and Echo_Store::user_email_hashes() (a get_users()
	 * query behind a transient) only behind BOTH — and the whole method only behind an
	 * actual blocklist hit, see the caller in check_submit(). Evaluating the user list on
	 * every unauthenticated POST would be a DoS vector on a large site.
	 *
	 * @param string $origin Submission path handed down to check_submit() ('login' or '').
	 * @param mixed  $fields User-content field map (plugin fields already stripped).
	 * @return bool
	 */
	private function is_exempt_login_submission( $origin, $fields ) {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- server-set path, only reduced to a file-name shape (screen_file()) and compared against one fixed file name.
		$script           = isset( $_SERVER['SCRIPT_FILENAME'] ) ? (string) $_SERVER['SCRIPT_FILENAME'] : '';
		$is_login_surface = 'wp-login.php' === Overbroad_Pattern_Guard::screen_file( $script ) || 'login' === $origin;
		if ( ! $is_login_surface ) {
			return false;
		}
		$blocked = Echo_Values::blocked_emails( $fields, $this->blocked_values(), Echo_Store::site_domains() );
		if ( empty( $blocked ) ) {
			// No address caused this block (whole-value or URL-domain hit), so no account
			// can vouch for it — fail closed. This early return is ALSO what keeps
			// user_email_hashes() (get_users()) off that path; all_emails_exempt() would
			// answer false for an empty set on its own, but only after the query had run.
			return false;
		}
		return Echo_Values::all_emails_exempt( $blocked, Echo_Store::user_email_hashes() );
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

		// The classification chain. Its ORDER IS THE SEMANTICS ("first cause wins"): each
		// stage below records a reason only if no earlier one did, so moving a stage would
		// change the recorded reason without changing the verdict — which no behavioural
		// test can see. Pinned in tests/unit/StampClassificationOrderTest.php.
		$this->classify_missing_proof_of_work();
		$this->classify_simulated_spam( $hook_name );

		// Value-based deterministic spam signals (BACKLOG "Wertbasierte Spam-Pattern
		// über alle Formulare"), evaluated BEFORE gibberish so they take precedence
		// as the more deliberate, value-based classification. Both run only on
		// an otherwise-clean submission and only over user-content fields (Echo_Values
		// skips technical keys — invariant 1).
		// strip_plugin_fields() first: gdpr_pow_token (92 chars → always a text hash)
		// and hashPWFields (constant per form → would self-match every submission)
		// are the plugin's OWN fields, not user content, and must never seed or match
		// an echo/wildcard value (they are not caught by Echo_Values' technical-key
		// rule, which only knows generic key patterns).
		$content_fields = self::strip_plugin_fields( $gdpr_fields );
		$this->classify_echo_lock( $gdpr_fields, $content_fields );
		$this->classify_blocked_value( $gdpr_fields, $content_fields, $origin );

		$analysis             = $this->classify_gibberish( $gdpr_fields );
		$quarantine_only_spam = $this->classify_under_attack_quarantine( $gdpr_fields );

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
		// classified as spam it will land in the spam folder — remember its core values
		// (hashed, TTL) so the same sender/domain/text is caught on any form / any IP
		// within the window. Never in simulation mode (everything is "spam" there,
		// which would poison the store with legitimate submissions).
		//
		// TWO CLASSES OF VERDICT ARE EXCLUDED, for one and the same reason: the echo
		// store holds CONTENT (sender email, payload domain, phone, long-text hash) for
		// 36h across every form and every address, so only a verdict that actually says
		// something about the content may fill it.
		//  a) The under-attack quarantine ($quarantine_only_spam, exception #2 above):
		//     its grey-zone submissions are presumed innocent and must not seed echo
		//     values that would spam-classify legitimate senders after the wave ends.
		//  b) The three infrastructure-shaped no_pow sub-cases
		//     (Classification_Reason::seeds_echo_values(), false for token_no_row /
		//     token_ip_changed / the historic chain_no_row): there a token that VERIFIED
		//     was presented and merely its solved-PoW row was missing — cache, proxy,
		//     storage failure, clock skew (HANDBUCH.md §12 causes 4/7/8). A `no_pow`
		//     verdict states that the handshake failed, nothing about the content, and
		//     "everything is flagged as spam" is the single most common support case
		//     there is: letting those seed turns each mass false alarm into a content
		//     blocklist that outlives its own fix by up to 36h (measured on 5.3.4 — the
		//     two-clocks bug's victims kept being blocked after the update, now as
		//     "Known spam value"). `no_pow:no_token` and `no_pow:invalid_token` DO keep
		//     seeding: protocol-blind mass spam is the echo lock's main food source.
		//     The two prices of that cut (a protocol-aware bot can provoke
		//     token_no_row for free; invalid_token is a false-alarm class too) are
		//     spelled out at seeds_echo_values() and deliberately accepted.
		if (
			$gdpr_fields
			&& $this->plugin_spam
			&& ! $quarantine_only_spam
			&& Classification_Reason::seeds_echo_values( $this->classification_reason )
			&& ! get_option( Option::POW_SIMULATE_SPAM )
		) {
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

		// Carry the verdict back onto the analysis row, if there is one.
		//
		// save_for_analysis() writes its type-4 row in the CONSTRUCTOR, i.e. before this
		// method has computed anything, so that row got `_gdpr_route` and nothing else.
		// The result was that the one screen built for the question "why was this
		// message judged the way it was" could not answer it: you needed "Save clean
		// messages" instead of the analysis mode. Not a regression — `_gdpr_reason` was
		// always missing there too — but it halved the value of the scoring field the
		// moment it was introduced.
		//
		// Written for BOTH fields, not just scoring. Consistency is the cheaper answer
		// here, and the diagnosis gains more from the pair than from either alone: a
		// reason says why it was flagged, a scoring line says why it was not.
		$this->update_analysis_verdict();

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

		// Write log for Fail2Ban — with two exclusions, both for the SAME reason: a
		// fail2ban line is a lasting, out-of-band lockout, and there are two situations
		// where the address it would carry is more likely to be a person than a bot.
		//
		// (1) A quarantine-only classification. Those submissions passed every individual
		//     check and are presumed innocent; logging them would let fail2ban ban the IPs
		//     of genuine visitors submitting during a wave (exception #3 in the quarantine
		//     block above).
		//
		// (2) A block that landed on a REAL wp-admin screen. An over-broad field pattern
		//     — `{"email":null}` is the measured example — turns an administrator's own
		//     profile save into a spam verdict, and without this term that verdict writes
		//     the ADMINISTRATOR'S address into spam.log. An external tool then locks the
		//     site's own administrator out, permanently and outside WordPress, over a
		//     setting they can no longer reach to correct.
		//
		//     WHAT THIS IS *NOT*: it is not "backend POSTs are not evaluated anyway, so
		//     nothing is lost". That reasoning is wrong and must not be written here. The
		//     evaluation hangs off the CONTENT of the POST, not off the URL — a shipped
		//     default pattern like `{"_wpcf7":null}` matches any POST carrying that field,
		//     including one aimed at /wp-admin/profile.php. So a bot CAN point its POST at
		//     a wp-admin URL and thereby exempt ITSELF from fail2ban logging. The attacker
		//     chooses the URL; that steerability is real and is the price paid here
		//     knowingly, not an oversight.
		//
		//     It is paid because the damage is asymmetric. Without the exclusion, the
		//     administrator is locked out for good and out of band. With it, the bot is
		//     still BLOCKED, still classified spam, still stored, and still counted
		//     towards the under-attack wave — it is merely not banned. Fail2Ban is the
		//     escalation stage here, not the protection; the protection is untouched.
		//     (This is the difference from the quarantine exception: there the submission
		//     itself is grey-zone and the verdict is a hold. Here the submission stays
		//     fully spam and nothing about its handling changes — only the log line goes.)
		//
		// BOTH calls below are covered, the auth.log one as well as the spam.log one: a
		// login-shaped POST aimed at a wp-admin screen is the same steering move as any
		// other, and wp-login.php itself does not define WP_ADMIN, so the real login
		// surface keeps its auth.log line (pinned in
		// tests/integration/cases/fail2ban-backend-exception.mjs, arm 3).
		//
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- server-set path, only compared against a fixed list of file names inside is_core_admin_screen_post(); never stored, never printed.
		$fail2ban_script    = isset( $_SERVER['SCRIPT_FILENAME'] ) ? (string) $_SERVER['SCRIPT_FILENAME'] : '';
		$backend_screen_hit = Overbroad_Pattern_Guard::is_core_admin_screen_post( is_admin(), wp_doing_ajax(), $fail2ban_script );
		if ( $this->plugin_spam && ! $quarantine_only_spam && ! $backend_screen_hit ) {
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
			// PURE OBSERVATION, and the ONE reference to the over-broad-pattern marker in
			// this file. It records "a wp-admin screen save was just discarded because a
			// configured field pattern matched it" so the administrator can be told
			// afterwards — the symptom otherwise points nowhere near its cause.
			//
			// Placed HERE, in the block branch itself, and NOT behind POW_SAVE_SPAM: the
			// health counter learnt that lesson the expensive way (HANDBUCH.md §12, end) —
			// a diagnostic hung off stored messages goes silent on exactly the sites whose
			// operator can see nothing else. The call decides for itself whether this
			// request was an admin screen at all, ignores its own storage result, and
			// NOTHING in check_submit()/check_request() ever reads what it writes
			// (source-level invariant, tests/unit/OverbroadPatternMarkerWiringTest.php).
			Overbroad_Pattern_Guard::record_backend_block(
				$this->whole_request_data,
				$this->hash_values( $this->get_client_ip() )
			);

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

	/**
	 * Stage 1 of the classification chain — promotes a failed check_request() to the
	 * spam verdict. Deliberately the FIRST stage, so its no_pow:* reason always wins.
	 *
	 * Mutates $this->plugin_spam, $this->classification_reason and $this->pow_probe, and
	 * feeds both counters (wave counter plus the storage-independent health counter).
	 *
	 * @phpstan-impure
	 * @return void
	 */
	private function classify_missing_proof_of_work() {
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
			// Health counter for the #1 support case ("everything is spam"), counted
			// HERE and not where check_request() sets pow_fail_reason: that method
			// records a reason on every failing path it takes, including ones whose IP
			// fallback then succeeds — those requests came through, and counting them
			// would inflate the number that is supposed to mean "submissions that found
			// no stamp row". This line is the promotion point, so it counts exactly the
			// submissions that were actually classified no_pow.
			//
			// WHY A SECOND COUNTER AT ALL. The existing one
			// (Option::count_no_pow_reasons_since_hours()) reads `_gdpr_reason` detail
			// rows, which only exist when save_message() ran — and for spam that is
			// gated by POW_SAVE_SPAM. On a site with spam storage off it therefore
			// reads 0 forever, and 0 reads like "healthy" precisely where the operator
			// can see nothing else either. This one is storage-independent.
			Option::increment_no_pow_health_counter();
		}
	}

	/**
	 * Stage 2 — the simulation switch (POW_SIMULATE_SPAM). The ONE stage without a
	 * `! $this->plugin_spam` guard, so it also catches requests check_request() passed.
	 *
	 * Mutates $this->plugin_spam unconditionally, and $this->classification_reason only
	 * while no earlier stage set one. Feeds no counter.
	 *
	 * @phpstan-impure
	 * @param string $hook_name Current filter, so the login hook stays excluded.
	 * @return void
	 */
	private function classify_simulated_spam( $hook_name ) {
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
	}

	/**
	 * Stage 3 — auto-echo lock: does this submission repeat a core value remembered from
	 * a recent spam message? First of the two value-based signals, behind both
	 * unconditional stages and ahead of the blocked-value check.
	 *
	 * Mutates $this->plugin_spam, $this->classification_reason and the wave counter.
	 *
	 * @phpstan-impure
	 * @param mixed $gdpr_fields    Submitted fields, raw.
	 * @param mixed $content_fields The same fields minus the plugin's own.
	 * @return void
	 */
	private function classify_echo_lock( $gdpr_fields, $content_fields ) {
		// (1) Auto-echo lock: an incoming submission whose core values (sender email,
		//     payload domain, phone, long-text hash) match a value auto-recorded from
		//     a recent spam-folder message — catches the same sender/domain on ANY
		//     form / ANY IP within the TTL window (would have caught field datum #2).
		//     Cheap: one get_transient() + hash lookups.
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
	}

	/**
	 * Stage 4 — blocked value: does a user-content field match one of the operator's
	 * POW_BLOCKED_VALUES lines? Second value-based signal, still ahead of gibberish.
	 *
	 * Mutates $this->plugin_spam, $this->classification_reason and the wave counter.
	 *
	 * @phpstan-impure
	 * @param mixed  $gdpr_fields    Submitted fields, raw.
	 * @param mixed  $content_fields The same fields minus the plugin's own.
	 * @param string $origin         Submission path, 'login' only from pre_process_login().
	 * @return void
	 */
	private function classify_blocked_value( $gdpr_fields, $content_fields, $origin ) {
		// (2) Blocked value: a user-content field matches one of the operator's
		//     POW_BLOCKED_VALUES lines. Reason code CODE_WILDCARD ('wildcard') is
		//     UNCHANGED — it is stored as `_gdpr_reason` in live databases and is a
		//     corpus label; only its source option and its UI label moved.
		//     The trailing exemption keeps a REGISTERED user signing in on wp-login.php
		//     out of this classification, so a sender-domain entry ("@gmail.com")
		//     cannot lock the operator out of his own site. It applies only when EVERY
		//     address that actually triggered the block belongs to a registered user —
		//     appending a known registered address to an otherwise blocked login used to
		//     buy the exemption, measured. That, why it is NOT "registered addresses are
		//     exempt everywhere", and why the anchor is the server-set login screen rather
		//     than anything read out of the request, is spelled out at
		//     is_exempt_login_submission().
		//     ORDER IS LOAD-BEARING, do not reorder these terms: the exemption stands
		//     BEHIND matches_blocked_values() so that &&'s short-circuit keeps
		//     Echo_Store::user_email_hashes() (a get_users() query) off every ordinary
		//     unauthenticated POST — running it there would be a fresh DoS vector.
		//     The echo branch (1) above deliberately carries NO such term: it is already
		//     safe through its own exclude set, and adding one there would obscure that.
		if ( $gdpr_fields && ! $this->plugin_spam && $this->matches_blocked_values( $content_fields ) && ! $this->is_exempt_login_submission( $origin, $content_fields ) ) {
			$this->print_debug_information( 'Blocked value match' );
			$this->plugin_spam           = true;
			$this->classification_reason = Classification_Reason::CODE_WILDCARD;
			// Feed the wave counter too — same deterministic value class as the echo
			// hit above (see that comment). Additive only; not in simulation mode.
			if ( ! get_option( Option::POW_SIMULATE_SPAM ) ) {
				$this->increment_spam_counter();
			}
		}
	}

	/**
	 * Stage 5 — gibberish detection, the content heuristic. Runs behind both value-based
	 * signals so their more deliberate verdict takes precedence.
	 *
	 * Mutates $this->plugin_spam, $this->classification_reason and the wave counter, and
	 * RETURNS the single scan result — the clean-scoring line is built from the very same
	 * components, and handing them back is what keeps it at one scan per submission.
	 *
	 * @phpstan-impure
	 * @param mixed $gdpr_fields Submitted fields, raw.
	 * @return array{gibberish: bool, letters: int, alnum: int, solo: bool, strong: bool,
	 *         scoreable: int} The one scan result, for the clean-scoring line.
	 */
	private function classify_gibberish( $gdpr_fields ) {
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
		$analysis = array(
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

		return $analysis;
	}

	/**
	 * Stage 6 — the under-attack quarantine, evaluated LAST so it only ever sees a
	 * submission that passed every individual check above.
	 *
	 * Mutates $this->plugin_spam and $this->classification_reason and — alone among the
	 * stages — feeds NO counter (exception #1). Returns whether it fired, so the caller's
	 * $quarantine_only_spam can carry exceptions #2/#3 to the guards that enforce them.
	 *
	 * @phpstan-impure
	 * @param mixed $gdpr_fields Submitted fields, raw.
	 * @return bool Whether the quarantine fired (caller's $quarantine_only_spam).
	 */
	private function classify_under_attack_quarantine( $gdpr_fields ) {
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
			$this->classification_reason = Classification_Reason::CODE_QUARANTINE;

			return true;
		}

		return false;
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
		return self::resolve_client_ip();
	}

	/**
	 * THE client-IP resolution of this plugin: read the request and the options, hand
	 * both to the pure ClientIp::resolve().
	 *
	 * Static and shared because there is more than one caller and there used to be more
	 * than one implementation. `Analysis::store_analysis_entry()` carried its own copy,
	 * whose comment claimed to mirror this method but read a WIDER header list than
	 * ClientIp::HEADER_PRIORITY (harmless only by accident — resolve() ignores the
	 * extra names). Two copies of an address decision is one too many: the moment an
	 * option like POW_TRUST_PRIVATE_PROXY changes what "the client's address" means,
	 * a second copy silently answers differently in the same request.
	 *
	 * @return string
	 */
	public static function resolve_client_ip() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- passed to ClientIp::resolve(), which validates every address it returns.
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : (string) getenv( 'REMOTE_ADDR' );

		// Exactly the headers ClientIp honors — read from the class instead of keeping a
		// second list here, which is how the two drifted apart before.
		$forwarded_headers = array();
		foreach ( ClientIp::HEADER_PRIORITY as $header_name ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- see above; the chain is parsed and validated in ClientIp.
			$value = isset( $_SERVER[ $header_name ] ) ? $_SERVER[ $header_name ] : getenv( $header_name );
			if ( is_string( $value ) && '' !== $value ) {
				$forwarded_headers[ $header_name ] = $value;
			}
		}

		// Trusted-proxy concept (see ClientIp): Forwarded-For-style headers are client-
		// settable, so they are only honored when REMOTE_ADDR (the actual TCP peer) is
		// itself a configured trusted proxy — otherwise REMOTE_ADDR wins outright.
		$trusted_proxies = preg_split( '/\r\n|\n|\r/', (string) get_option( Option::POW_TRUSTED_PROXIES ), -1, PREG_SPLIT_NO_EMPTY );

		// Opt-in, default OFF, and only effective while the list above is empty: treat a
		// private/loopback peer as a proxy. See ClientIp::is_private() for both halves of
		// the trade-off.
		$trust_private = (bool) get_option( Option::POW_TRUST_PRIVATE_PROXY, false );

		return ClientIp::resolve( $remote_addr, $forwarded_headers, $trusted_proxies, $trust_private );
	}

	/** Hash helper — delegates to the pure ProofOfWork primitive (single source of truth).
	 *
	 */
	private function hash_values( $x ) {
		return ProofOfWork::hash_value( $x );
	}

	/** Format a point in time for the `rgs_time` column — THE ONE CLOCK this table is
	 * read and written with.
	 *
	 * Every rgs_time comparison used to be `NOW() - INTERVAL n MINUTE`, i.e. the clock of
	 * whichever database session happened to run the query. Token validity, meanwhile,
	 * has always been decided in PHP (`time()` against the HMAC-bound `issued_at`). Two
	 * clocks deciding one lifetime is a defect waiting for a host to expose it, and one
	 * did: where the writing and the reading session disagreed by two hours, every solved
	 * row read as two hours old, no row was ever consumable, and every submission on the
	 * site was spam while the handshake and the self-test stayed green (HANDBUCH.md §12
	 * cause 8).
	 *
	 * So PHP states the time and the database only compares: no NOW(), no INTERVAL, no
	 * CURDATE() may return to any query touching this table. UTC rather than site-local
	 * time because nothing ever displays rgs_time — it is short-lived bookkeeping, and a
	 * site owner switching the WordPress timezone must not shift the frame of rows
	 * already written.
	 *
	 * @param int $offset_seconds Seconds relative to now (negative = in the past).
	 * @return string `Y-m-d H:i:s` in UTC, ready to bind as %s.
	 */
	private static function sql_utc( $offset_seconds = 0 ) {
		return gmdate( 'Y-m-d H:i:s', time() + (int) $offset_seconds );
	}

	/** Atomically consume one use of the solved-stamp row matching the current IP
	 * (AP2 rate-limit). LIMIT 1 so that, if an IP has solved multiple stamps
	 * (multiple rows), only one row is charged per submission.
	 *
	 * THE FRESHNESS BOUND IS LOAD-BEARING HERE — unlike in consume_token_row(), where it
	 * was redundant and has been dropped. This path has no token and therefore no expiry
	 * of its own: the row is found by address alone, and the sweep in check_stamp() only
	 * runs when somebody solves. Without the bound, one row on a quiet site would keep
	 * delivering token-less traffic from that address until POW_MAX_USES was spent,
	 * however many days later. "This address paid RECENTLY" is the entire semantics of
	 * the fallback, not decoration on it.
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
                       AND rgs_time >= %s
                       AND rgs_uses < %d
                     LIMIT 1',
				$this->hash_values( $this->get_client_ip() ),
				self::sql_utc( -( ( (int) $time_window + 2 ) * MINUTE_IN_SECONDS ) ),
				$max_uses
			)
		);
	}

	/** Atomically consume one use of the row keyed by this specific token (AP3
	 * submission-binding) — the token, not the IP, is the rate-limit key here.
	 *
	 * NO TIME PREDICATE, DELIBERATELY. A row is created (check_stamp) only after its
	 * token was issued, so the row can never be older than the token — and the token's
	 * age is already decided, one call earlier, by StampToken::verify_integrity(), which
	 * is the sole gate this method sits behind (pinned by StampWiringTest). A second
	 * freshness test could therefore never reject anything the first one let through: it
	 * could only fire when the two clocks disagreed, which is precisely how a site with a
	 * timezone-inconsistent database ended up classifying every submission as spam
	 * (HANDBUCH.md §12 cause 8). The most robust time check on this path is the one that
	 * is not there.
	 *
	 * What still bounds the row, with no clock involved: the token expiry above, the
	 * TOKEN_MAX_USES budget below, the sweep in check_stamp(), and the fact that the row
	 * is unreachable without presenting the matching valid token — the lookup is by
	 * rgs_stamp, and the UNIQUE index keeps a second solve from minting fresh budget.
	 *
	 * @param string $token The verified token (also the row's rgs_stamp value).
	 * @return int Affected rows (0 or 1).
	 */
	private function consume_token_row( $token ) {
		global $wpdb;
		return (int) $wpdb->query(
			$wpdb->prepare(
				'
                    UPDATE ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs
                       SET rgs_uses = rgs_uses + 1
                     WHERE rgs_stamp = %s
                       AND rgs_uses < %d
                     LIMIT 1',
				$token,
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

		// Base-token path — the ONLY token path. There is exactly one accepted format
		// (v2, 100 chars, integrity-only, no IP in the HMAC). Two former branches sat
		// here and are gone: the 92-char legacy format of the pre-v2 release, and the
		// 112/120-char chain tokens of the removed solve-time gate. Both were explicit
		// one-release transition paths; both transitions are over (5.3.3 shipped). See
		// handbuch/pow.md, "Kein Solve-Zeit-Gate — und warum keins zurückkommt".
		$token_valid = StampToken::LENGTH_V2 === $token_length
			&& StampToken::verify_integrity( $token, $salt, time(), $time_window );

		if ( $token_valid ) {
			// verify_integrity() above has already bounded this token's age; the row it
			// looks for cannot be older than the token itself, so consume_token_row()
			// asks about the budget only and never about the clock (see there).
			$valid = $this->poll_for_row(
				function () use ( $token ) {
					return $this->consume_token_row( $token );
				}
			);

			if ( $valid ) {
				return $valid;
			}

			// Token didn't land a usable row within the poll window (e.g. check_stamp()
			// hasn't landed yet, or the row is already exhausted) — one IP-fallback
			// consumption, no further polling. Record WHY this path failed BEFORE the
			// fallback attempt: if the fallback still succeeds, check_request() returns
			// true and check_submit() never reads the reason (observe only, no cleanup).
			//
			// PURE LABELLING, NOT A DECISION: a fingerprint mismatch only picks the more
			// specific reason string (the cache/proxy signature), so the site owner can
			// tell "the handshake broke" from "this token came from somewhere else".
			// The fallback attempt below is identical either way.
			$mismatched = StampToken::STATUS_MISMATCH === StampToken::fp_status( $token, $this->get_client_ip(), $salt );

			$this->pow_fail_reason = $mismatched
				? Classification_Reason::NO_POW_TOKEN_IP_CHANGED
				: Classification_Reason::NO_POW_TOKEN_NO_ROW;
			return $this->consume_ip_row( $time_window, $max_uses );
		}

		// No usable token at all: either none was posted, or one was posted and failed
		// verification (forged, expired, or of a length this build no longer accepts —
		// which now includes the retired 92/112/120-char formats).
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

		// ONE accepted length, and it must stay one. 100 = base token (v2). Three former
		// alternatives are gone: the pre-AP3 64-char bucket stamp, the 92-char pre-v2
		// token, and the 112/120-char chain tokens of the removed solve-time gate. Every
		// one of them was a transitional path with an announced end; every one of them
		// also weakened this gate while it lived (the 64er believed a POSTed IP, the
		// 92/112er bound validity to the server-resolved address). A new length here
		// needs the same kind of justification, not a convenience argument.
		$stamp_length = strlen( $stamp );

		if ( StampToken::LENGTH_V2 === $stamp_length ) {
			// Base-token path, verified for INTEGRITY ONLY — no IP enters
			// StampToken::verify_integrity(), so a token issued behind a cache or to a
			// rotating address still validates. The posted hashDifficulty/clientIP
			// fields are ignored: the difficulty that matters is the one embedded (and
			// HMAC-bound) in the token itself.
			$parsed           = StampToken::parse_v2( $stamp );
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

			$token_intact = StampToken::verify_integrity( $stamp, get_option( Option::POW_SALT ), time(), get_option( Option::POW_TIME_WINDOW, 10 ) );

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
		} else {
			$this->print_debug_information(
				"stamp size: $stamp_length expected: " . StampToken::LENGTH_V2
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
                            WHERE rgs_time < %s',
				self::sql_utc( -( ( (int) get_option( Option::POW_TIME_WINDOW, 10 ) + 2 ) * MINUTE_IN_SECONDS ) )
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
		// rgs_time is stated by PHP rather than left to the database (NOW()): this row is
		// later compared against thresholds PHP computes, and the token's own lifetime is
		// decided by PHP too. One clock writes it, the same clock reads it — see sql_utc().
		$inserted = $wpdb->query(
			$wpdb->prepare(
				'INSERT IGNORE INTO ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs (
                                rgs_ip,
                                rgs_stamp,
                                rgs_time
                             )
                             VALUES(%s, %s, %s)
                            ',
				$hashed_ip,
				$stamp,
				self::sql_utc()
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

		// Only one format reaches this point — check_stamp() ends the request on any
		// other length. The guard stays anyway: this method is the last thing that runs
		// before the INSERT, and a format that ever arrives here without a fingerprint
		// must count as "not measured" rather than silently as a match.
		if ( StampToken::LENGTH_V2 !== $stamp_length ) {
			return;
		}

		$status = StampToken::fp_status( $stamp, $this->get_client_ip(), $salt );

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
	 * Deliberately queried WITHOUT the freshness filter consume_ip_row() applies: "there
	 * was a row, but it was outside the window" and "there was no row at all" are
	 * opposite findings, and a filtered query reports both as nothing — which is exactly
	 * the ambiguity that cost two support rounds. The age is measured against a PHP-stated
	 * "now" (sql_utc()), the same clock that wrote rgs_time; measuring it against the
	 * database session's clock is what produced the impossible reading — a row older than
	 * the token it belongs to — that exposed §12 cause 8.
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
					'SELECT rgs_uses, TIMESTAMPDIFF( SECOND, rgs_time, %s ) AS age_s
					   FROM ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs
					  WHERE rgs_stamp = %s
					  LIMIT 1',
					self::sql_utc(),
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
					'SELECT rgs_uses, TIMESTAMPDIFF( SECOND, rgs_time, %s ) AS age_s
					   FROM ' . $wpdb->prefix . 'recaptcha_gdpr_stamp_rgs
					  WHERE rgs_ip = %s
					  ORDER BY rgs_time DESC, rgs_id DESC
					  LIMIT 1',
					self::sql_utc(),
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
