<?php
/**
 * The TRIAGE of Stamp: everything the constructor does to answer the one question
 * handbuch/gate.md is about — is THIS request evaluated at all?
 *
 * SCHNITTLINIE (PLAN-DATEIGROESSE.md). class-stamp.php was 2421 lines against a ledger
 * cap of 2460, i.e. 39 lines of headroom for a file that is still the busiest in the
 * plugin. The cut follows the seam its own head docblock has named all along — the
 * class spans three area files — and takes the piece that belongs to exactly one of
 * them: the whitelist/special-case/gate block of handbuch/gate.md.
 *
 * WHAT MOVED AND WHAT DID NOT. triage_request() holds the constructor body verbatim:
 * the IP whitelist (ClientIp::matches_list), the site whitelist (server_known_hosts() .
 * REQUEST_URI), $ajax/$action, the is_special_case_request() call and the gate `if`
 * itself with its ajax branch, the login exclusion, the Wordfence exclusion, the three
 * run() registrations and the two check_submit() calls. The constructor keeps what has
 * to happen for EVERY request regardless of the verdict — capture_request_data(),
 * register_token_endpoints(), Echo_Store::register_cache_hooks(), check_rest_routes()
 * and save_for_analysis().
 *
 * TWO ENTRY POINTS INTO THE TRIAGE, and only one of them is the normal one. For every
 * request that is not a wp-admin SCREEN POST — all frontend traffic, ajax, REST,
 * wp-login.php — the constructor calls triage_request() itself, synchronously, at the
 * point where the block always sat. For a screen POST it instead defers to
 * evaluate_admin_screen_post() on `init` priority 0, which asks the one question that
 * cannot be asked at include time (current_user_can(), pluggable.php is not loaded yet)
 * and then either skips the evaluation entirely or runs the very same triage_request().
 * There is exactly one triage body; the screen branch changes WHEN it runs and WHETHER
 * it runs, never WHAT it does.
 *
 * is_special_case_request() DELIBERATELY STAYED in class-stamp.php. It is the span end
 * marker of tests/unit/StampGateTest.php and tests/unit/StampRouteOrderingTest.php,
 * which cut the constructor out of class-stamp.php as "everything up to the literal
 * `private function is_special_case_request(`". Moving it here would leave both spans
 * anchored on a string that is no longer in that file — an unspoken condition, so it is
 * spoken out loud here and pinned in StampGateTest.
 *
 * A TRAIT, NOT A SECOND CLASS — same decision and same reason as
 * trait-stamp-persistence.php (Welle 5b): the triage reads and writes the SAME instance
 * state as the constructor and check_submit() ($request_data, $whole_request_data,
 * $route_found), and handing that state across a class boundary would create the one
 * place where the two halves can disagree. A trait is compiled into Stamp: every
 * property is the same one, visibility is unchanged, and PHPStan still attributes
 * findings to class-stamp.php.
 *
 * Consequence for the loader: a trait must be loaded BEFORE the class that uses it — see
 * the require_once order in plugin/recaptcha-gdpr-compliant.php and tests/bootstrap.php.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/gate.md, Abschnitt "Konstruktor, Triage, Hooks,
// Login". Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse
// (Traits bekommen keine eigene Indexzeile; sie sind Teil ihrer Klasse).

/**
 * Deciding whether a request is evaluated at all. Composed into Stamp.
 */
trait Stamp_Triage {

	/**
	 * The deferred half of the admin-screen decision, and the ONLY place in the whole
	 * spam path where a capability is consulted: on a real wp-admin screen POST, is the
	 * sender the operator of this site — or just someone POSTing at an admin URL?
	 *
	 * Registered by the constructor as `add_action( 'init', …, 0 )` when, and only when,
	 * Overbroad_Pattern_Guard::is_core_admin_screen_post() said yes. Public because that
	 * is what a hook callback has to be, not because anything else may call it.
	 *
	 * WHY A CAPABILITY AT ALL. Without one, an operator whose field pattern is too
	 * generic (`{"email":null}`, `{"name":null}`) has their OWN backend saves classified
	 * as spam and discarded — profile.php, the post editor, comment editing. The
	 * exempted population here is "people who administer this site", and that population
	 * is not a spam threat model. What makes the exemption defensible is that both of
	 * its inputs are server truth: the script the web server executed, and who WordPress
	 * says this session is. Neither is a header.
	 *
	 * WHY `edit_posts`, hard-wired, and nothing else:
	 *   - NOT is_user_logged_in(): on a site with open registration every self-registered
	 *     bot account would be exempt — precisely the new blindness this must avoid.
	 *   - NOT manage_options: too narrow. Editors and authors are exactly the people who
	 *     run into a self-inflicted `{"content":null}` in the post editor and the comment
	 *     screens; excluding them would leave the reported symptom in place for them.
	 *   - NO FILTER, no option, no constant. A filter here would be the one-line
	 *     disarmament of the whole gate, addable by any plugin and invisible in review.
	 *     tests/unit/StampScreenExemptionTest.php pins the literal for that reason.
	 *   - NAMED RESIDUAL CASE, accepted rather than hidden: a subscriber on profile.php
	 *     of a membership site still gets blocked by an over-broad pattern. Subscribers
	 *     are not the population this exemption is for.
	 *
	 * WHY `init` PRIORITY 0. Not plugins_loaded: membership and session plugins register
	 * their `determine_current_user` filters there, so asking earlier would answer
	 * "nobody" on exactly the sites that motivate the fix — fail-closed, hence safe, but
	 * useless. Not later either: real admin-screen handlers run from `admin_init`
	 * onwards, so `init` 0 still sits in front of everything that would process this
	 * POST. wp-settings.php has resolved the current user (via $GLOBALS['wp']->init())
	 * before do_action( 'init' ) runs, so the answer here is the real one.
	 *
	 * AND THE HALF THAT KEEPS THE PROTECTION: `init` fires BEFORE auth_redirect(), so an
	 * anonymous spam POST to /wp-admin/index.php does reach this method — and fails
	 * current_user_can(), and is therefore evaluated completely normally, on the same
	 * path and with the same verdict as before. That is the entire reason the capability
	 * check may not be skipped "for now": without it, "is an admin URL" would once more
	 * be something the sender chooses, which is the 5.3.0 referer bug in a new costume.
	 *
	 * EXEMPT MEANS NOT EVALUATED, not "evaluated but not blocked". Returning here skips
	 * run(), check_submit(), the spam row, the wave and health counters, the fail2ban
	 * line and — the one that reaches other people — Echo_Store::record(), which would
	 * otherwise seed echo locks out of an administrator's OWN text and let them hit real
	 * frontend visitors afterwards.
	 *
	 * @return void
	 */
	public function evaluate_admin_screen_post() {
		if ( current_user_can( 'edit_posts' ) ) {
			return;
		}

		$this->triage_request();
	}

	/**
	 * The request triage: whitelists, special cases and the gate `if` that decides
	 * whether this request is evaluated.
	 *
	 * Reached on exactly two paths, both of which end here unchanged: directly from the
	 * constructor, synchronously, as the last thing it does — that is every request that
	 * is not a wp-admin screen POST; or from evaluate_admin_screen_post() on `init` 0,
	 * for a screen POST whose sender turned out NOT to hold `edit_posts`. Same body,
	 * same verdict; only the moment differs.
	 *
	 * @return void
	 */
	private function triage_request() {
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
		//
		// THE THREE run() REGISTRATIONS BELOW KEEP THE DEFAULT PRIORITY 10, and that is
		// a requirement now, not a habit. Since the admin-screen deferral this method can
		// itself be running inside an `init` callback at priority 0 — and MEASURED in the
		// container (WP 7.0.4): a callback added at priority 10 from within a priority-0
		// callback still fires in the SAME do_action( 'init' ), while one added at the
		// SAME priority 0 does not, because that bucket has already been walked. So
		// "unifying" these to 0 would not tidy anything up; it would silently stop run()
		// from ever registering the script and the login hooks on every deferred request.
		if ( ! $ip_whitelisted && ! $site_whitelisted ) {
			//Ajax-calls get a different treatment
			if ( $ajax ) {
				//Post-requests from the plugin
				if ( ! in_array( $action, array( 'get_stamp', 'check_stamp' ), true ) ) {
					if ( $this->check_explicit_actions() ) {
						// Only explicitly listed actions shall be allowed that are listed on the explicit actions list
						// Priority: the DEFAULT 10, deliberately — see the note above the gate `if`.
						add_action( 'init', array( $this, 'run' ) );
						$this->check_submit( null, $this->request_data, 'ajax-call', $action, $ajax );
						return;
					}
				} else {
					// Priority: the DEFAULT 10, deliberately — see the note above the gate `if`.
					add_action( 'init', array( $this, 'run' ) );
				}
			} elseif ( ! ( ! get_option( Option::POW_BLOCK_LOGIN ) && isset( $this->whole_request_data ['wp-submit'] ) ) ) {
				//Do not apply if login shall not be blocked and it is a login
				//Do not apply if the request is a wordfence_syncAttackData-Request from Wordfence
				if ( ! ( isset( $this->request_data['wordfence_syncAttackData'] ) && count( $this->request_data ) === 1 ) ) {
					// Priority: the DEFAULT 10, deliberately — see the note above the gate `if`.
					add_action( 'init', array( $this, 'run' ) );
					$pattern_found = $this->check_existing_patterns();
					$action_found  = $this->check_explicit_actions();
					// $this->route_found: computed earlier in the constructor, before
					// save_for_analysis() — see there.
					//WooCommerce
					if ( (
							isset( $this->request_data['update_cart'] ) && isset( $this->request_data['cart'] ) && isset( $this->request_data['woocommerce-cart-nonce'] )
						) || (
							isset( $this->whole_request_data ['wc-ajax'] ) && 'checkout' === $this->whole_request_data ['wc-ajax']
						)
						|| $pattern_found
						|| $action_found
						|| $this->route_found
					) {
						$this->check_submit( null, $this->request_data, 'specific call' );
						return;
					}
				}
			}
		}
	}
}
