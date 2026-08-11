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

	/** String that represents the name of the plugin */
	private $plugin_name;

	/** Feld der Optionen */
	private $options;

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

	public static function get_default_ajax_actions() {
		include_once ABSPATH . 'wp-admin/includes/plugin.php';
		$actions           = array();
		$installed_plugins = get_plugins();
		$installed_themes  = wp_get_themes();

		// *** Thrive Architect Forms (custom submission method) ***
		if ( array_key_exists( 'thrive-architect/thrive-architect.php', $installed_plugins ) ) {
			$actions[] = 'tve_api_form_submit';
			self::display_admin_notice( __( 'Thrive Architect detected – added action: tve_api_form_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Forminator (uses WordPress AJAX) ***
		if ( is_plugin_active( 'forminator/forminator.php' ) || array_key_exists( 'forminator/forminator.php', $installed_plugins ) ) {
			$actions[] = 'forminator_submit_form_custom-forms';
			self::display_admin_notice( __( 'Forminator detected – added action: forminator_submit_form_custom-forms', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** WPForms (uses WordPress AJAX) ***
		if ( array_key_exists( 'wpforms/wpforms.php', $installed_plugins ) || array_key_exists( 'wpforms-lite/wpforms.php', $installed_plugins ) ) {
			$actions[] = 'wpforms_submit';
			self::display_admin_notice( __( 'WPForms detected – added action: wpforms_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Ninja Forms (uses WordPress AJAX) ***
		if ( array_key_exists( 'ninja-forms/ninja-forms.php', $installed_plugins ) ) {
			$actions[] = 'nf_ajax_submit';
			self::display_admin_notice( __( 'Ninja Forms detected – added action: nf_ajax_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Fluent Forms (uses WordPress AJAX) ***
		if ( array_key_exists( 'fluentform/fluentform.php', $installed_plugins ) ) {
			$actions[] = 'fluentform_submit';
			self::display_admin_notice( __( 'Fluent Forms detected – added action: fluentform_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Jetpack Forms (uses WordPress AJAX) ***
		if ( array_key_exists( 'jetpack/jetpack.php', $installed_plugins ) ) {
			$actions[] = 'jetpack_contact_form_submit';
			self::display_admin_notice( __( 'Jetpack Forms detected – added action: jetpack_contact_form_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Everest Forms (uses WordPress AJAX). The real registered action is the
		// dynamically built `wp_ajax_nopriv_everest_forms_ajax_form_submission` hook,
		// see includes/class-evf-ajax.php's $ajax_events['ajax_form_submission'] and
		// assets/js/frontend/ajax-submission.js — the `action` value the client sends
		// is the hook name minus the `wp_ajax(_nopriv)_` prefix. Verified against the
		// wp.org zip, Everest Forms 3.5.3. ISSUES.md "Drei Defekte…": the previous
		// `everest_forms_submit` value was never registered, so this never fired. ***
		if ( array_key_exists( 'everest-forms/everest-forms.php', $installed_plugins ) ) {
			$actions[] = 'everest_forms_ajax_form_submission';
			self::display_admin_notice( __( 'Everest Forms detected – added action: everest_forms_ajax_form_submission', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// WS Form and Otter Blocks do NOT submit via admin-ajax (verified against the
		// current wp.org zips, ws-form 1.12.0 and otter-blocks 3.2.1: neither registers
		// a `wp_ajax(_nopriv)_*` hook for form submission) — both are REST-only
		// builders. Detection moved to get_default_rest_routes() below
		// (ISSUES.md "Drei Defekte…"); the previous `ws_forms_submit`/
		// `otter_blocks_submit` action entries here were never registered by either
		// plugin and are removed rather than fixed.

		// *** Spectra / Ultimate Addons for Gutenberg (uses WordPress AJAX) ***
		// Verified against the wp.org zip, Spectra 2.20.1: blocks-config/forms/
		// class-uagb-forms.php registers BOTH `wp_ajax_uagb_process_forms` and
		// `wp_ajax_nopriv_uagb_process_forms`, so the action a visitor's browser sends
		// is `uagb_process_forms` (checked, not assumed — see ISSUES.md "Drei Defekte…"
		// for what a guessed action costs). Spectra posts it via
		// `fetch( ajaxUrl, { body: new URLSearchParams( … ) } )`, which is also why the
		// client-side token injection has to understand that body shape — see
		// scripts/recaptcha-gdpr-pow.js#injectTokenIntoBody() and HANDBUCH §12 cause 5.
		if ( array_key_exists( 'ultimate-addons-for-gutenberg/ultimate-addons-for-gutenberg.php', $installed_plugins ) ) {
			$actions[] = 'uagb_process_forms';
			self::display_admin_notice( __( 'Spectra detected – added action: uagb_process_forms', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Elementor Pro Forms (correct action) ***
		if ( array_key_exists( 'elementor-pro/elementor-pro.php', $installed_plugins ) ) {
			$actions[] = 'elementor_pro_forms_send_form';
			self::display_admin_notice( __( 'Elementor Pro Forms detected – added action: elementor_pro_forms_send_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		return implode( "\n", $actions );
	}

	public static function get_default_recognition_patterns() {
		include_once ABSPATH . 'wp-admin/includes/plugin.php';
		$patterns          = array();
		$installed_plugins = get_plugins();
		$installed_themes  = wp_get_themes();

		// *** Contact Form 7 ***
		if ( array_key_exists( 'contact-form-7/wp-contact-form-7.php', $installed_plugins ) ) {
			$patterns[] = '{"_wpcf7":null}';
			$patterns[] = '{"wpcf7_submit":null}';
			$patterns[] = '{"wpcf7_contact_form":null}';
			$patterns[] = '{"wpcf7_file_upload":null}';
			$patterns[] = '{"wpcf7_attachment":null}';
			$patterns[] = '{"wpcf7_post_submission":null}';
			$patterns[] = '{"wpcf7_save_post":null}';
			self::display_admin_notice( __( 'Contact Form 7 detected – added default recognition patterns', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** WooCommerce ***
		if ( array_key_exists( 'woocommerce/woocommerce.php', $installed_plugins ) ) {
			$patterns[] = '{"add-to-cart":null}';
			$patterns[] = '{"remove-from-cart":null}';
			$patterns[] = '{"update-cart":null}';
			$patterns[] = '{"woocommerce_checkout":null}';
			$patterns[] = '{"woocommerce_order":null}';
			$patterns[] = '{"woocommerce_payment_complete":null}';
			$patterns[] = '{"woocommerce_created_customer":null}';
			$patterns[] = '{"woocommerce_login":null}';
			$patterns[] = '{"woocommerce_review":null}';
			$patterns[] = '{"woocommerce_comment":null}';
			self::display_admin_notice( __( 'WooCommerce detected – added recognition patterns for cart, checkout, and user actions', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Gravity Forms (custom submission method) ***
		if ( array_key_exists( 'gravityforms/gravityforms.php', $installed_plugins ) ) {
			$patterns[] = '{"gform_submit":null}';
			$patterns[] = '{"gform_file_upload":null}';
			self::display_admin_notice( __( 'Gravity Forms detected – added recognition patterns for submissions and file uploads', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Divi Contact Form Module (custom submission method) ***
		if ( array_key_exists( 'Divi', $installed_themes ) ) {
			$patterns[] = '{"et_pb_contactform_submit_0":null}';
			self::display_admin_notice( __( 'Divi detected – added recognition pattern: {"et_pb_contactform_submit_0":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Thrive Leads & Thrive Architect (custom submission method) ***
		if ( array_key_exists( 'thrive-leads/thrive-leads.php', $installed_plugins ) ) {
			$patterns[] = '{"thrive_leads_submit":null}';
			self::display_admin_notice( __( 'Thrive Leads detected – added recognition pattern: {"thrive_leads_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Thrive Apprentice (Online course signups) ***
		if ( array_key_exists( 'thrive-apprentice/thrive-apprentice.php', $installed_plugins ) ) {
			$patterns[] = '{"thrive_apprentice_signup":null}';
			self::display_admin_notice( __( 'Thrive Apprentice detected – added recognition pattern: {"thrive_apprentice_signup":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Thrive Quiz Builder (Quiz forms) ***
		if ( array_key_exists( 'thrive-quiz-builder/thrive-quiz-builder.php', $installed_plugins ) ) {
			$patterns[] = '{"thrive_quiz_submission":null}';
			self::display_admin_notice( __( 'Thrive Quiz Builder detected – added recognition pattern: {"thrive_quiz_submission":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Thrive Comments (replaces WordPress comments) ***
		if ( array_key_exists( 'thrive-comments/thrive-comments.php', $installed_plugins ) ) {
			$patterns[] = '{"comment_content":null,"comment_post_ID":null,"tva_term":null}';
			self::display_admin_notice( __( 'Thrive Comments detected – added recognition pattern: {"thrive_comments_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Formidable Forms (custom submission method) ***
		if ( array_key_exists( 'formidable/formidable.php', $installed_plugins ) ) {
			$patterns[] = '{"formidable_submit":null}';
			self::display_admin_notice( __( 'Formidable Forms detected – added recognition pattern: {"formidable_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** WP User Frontend Forms (custom submission method) ***
		if ( array_key_exists( 'wp-user-frontend/wp-user-frontend.php', $installed_plugins ) ) {
			$patterns[] = '{"wpuf_submit":null}';
			self::display_admin_notice( __( 'WP User Frontend Forms detected – added recognition pattern: {"wpuf_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Jotform (custom submission method) ***
		if ( array_key_exists( 'jotform/jotform.php', $installed_plugins ) ) {
			$patterns[] = '{"jotform_submit":null}';
			self::display_admin_notice( __( 'Jotform detected – added recognition pattern: {"jotform_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Typeform (custom submission method) ***
		if ( array_key_exists( 'typeform/typeform.php', $installed_plugins ) ) {
			$patterns[] = '{"typeform_submit":null}';
			self::display_admin_notice( __( 'Typeform detected – added recognition pattern: {"typeform_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Zoho Forms (custom submission method) ***
		if ( array_key_exists( 'zoho-forms/zoho-forms.php', $installed_plugins ) ) {
			$patterns[] = '{"zoho_forms_submit":null}';
			self::display_admin_notice( __( 'Zoho Forms detected – added recognition pattern: {"zoho_forms_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** JetFormBuilder (TESTSUITE_PLAN.md AP4). Neither admin-ajax nor REST:
		// Jet_Form_Builder\Request\Form_Request_Router::listen() (includes/request/
		// request-router.php) intercepts a plain POST to the CURRENT page URL
		// (Http_Tools::get_form_action_url(), includes/classes/http/http-tools.php —
		// home_url( $wp->request ) with a QUERY STRING appended, never to
		// admin-ajax.php) and, for its OWN "ajax" submit mode, defines DOING_AJAX
		// itself right there inside listen() (request-router.php:48) — reached via
		// Plugin::init_components() -> Form_Handler::call_form() on the
		// 'after_setup_theme' hook, priority 0 (functions.php:11-15) — long AFTER
		// Stamp::__construct() has already run (RCM_Main::get_instance() is called
		// at plugin-file-include time). Only the SEPARATE do_action( 'wp_ajax(_nopriv)_...' )
		// dispatch (setup_ajax_request()) is deferred to 'parse_request'; DOING_AJAX
		// itself is already set well before that. Either way the timing conclusion
		// holds: every JetFormBuilder submission, both its "reload" (default) and
		// "ajax" submit-type settings, reaches this plugin's non-ajax Pattern branch,
		// never the admin-ajax Action branch.
		// The query-string marker's key AND value are RANDOMIZED per installation
		// (Admin\Tabs_Handlers\Options_Handler::set_jfb_request_args() /
		// jfb_generate_str(), includes/admin/tabs-handlers/options-handler.php —
		// live-measured example: `?qR6M61=M1ny66OS80H9&method=reload`, not the
		// literal `jet_form_builder_submit=submit` default the property declaration
		// suggests), which is what makes it useless as a signature — it WOULD be
		// visible to check_existing_patterns() if it were fixed: that method matches
		// against Stamp::$whole_request_data, which is $_REQUEST (GET+POST+COOKIE),
		// not just $_POST (class-stamp.php:307, used at :456). The actual signature
		// is the hidden `_jet_engine_booking_form_id` field
		// (Jet_Form_Builder\Blocks\Render\Form_Hidden_Fields::render(), includes/
		// blocks/render/form-hidden-fields.php:28, `jet_fb_handler()->form_key`) —
		// chosen specifically because, unlike hook_key/hook_val above, form_key is
		// never reassigned anywhere after its declaration (includes/form-handler.php:51)
		// and is therefore identical on every installation. Every JetFormBuilder form
		// renders it as a real <input type="hidden"> unconditionally — verified
		// against the pinned 3.6.5 zip and a live tokenless submission
		// (tests/integration/cases/jetformbuilder.mjs).
		if ( array_key_exists( 'jetformbuilder/jet-form-builder.php', $installed_plugins ) ) {
			$patterns[] = '{"_jet_engine_booking_form_id":null}';
			self::display_admin_notice( __( 'JetFormBuilder detected – added recognition pattern: {"_jet_engine_booking_form_id":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		return implode( "\n", $patterns );
	}

	/**
	 * Default REST routes (REST_ROUTES_PLAN.md AP3/AP4) — the third signature class,
	 * for builders that submit over the WordPress REST API and carry neither an
	 * ajax `action` nor one of the field patterns above. Plugin-detection-conditioned
	 * like the two getters above (AP4), so `Scope_Sync` (third ledger
	 * `POW_SEEDED_ROUTES`) only offers a route once the matching builder is actually
	 * active — never a route for a builder that isn't installed.
	 *
	 * Routes verified against the current wp.org zips (not guessed, ISSUES.md
	 * "Drei Defekte…"):
	 * - WS Form 1.12.0: namespace `ws-form/v1` (ws-form.php:71,
	 *   `WS_FORM_RESTFUL_NAMESPACE`), anonymous POST submit endpoint `/submit/`
	 *   (api/class-ws-form-api.php:332, `permission_callback => true`) — matched via
	 *   the namespace-suffix wildcard, not the exact endpoint, so future WS Form REST
	 *   endpoints stay covered too. Main plugin file is `ws-form/ws-form.php` (the
	 *   previous ajax-action entry used the wrong slug `ws-forms/ws-forms.php` and
	 *   never fired).
	 * - Otter Blocks 3.2.1: namespace built from `$namespace . $version` = `otter/v1`
	 *   (inc/server/class-form-server.php:49,57), route `/form/frontend`
	 *   (class-form-server.php:174-177, `WP_REST_Server::CREATABLE`). The previous
	 *   ajax-action entry `otter_blocks_submit` was never registered anywhere.
	 * - Contact Form 7 also submits via REST but is already covered by its `_wpcf7`
	 *   pattern above; the route is added here too, belt-and-suspenders (no separate
	 *   detection notice — the pattern getter already announces CF7).
	 *
	 * NEVER add a bare namespace like `wp/v2` here: this option is read behind the
	 * same triage gate as every other signature class (handbuch/gate.md), which also
	 * sees the block editor's own REST save (`/wp/v2/posts/<id>`) — seeding that
	 * namespace would make the plugin block post saves in wp-admin.
	 *
	 * @return string
	 */
	public static function get_default_rest_routes() {
		include_once ABSPATH . 'wp-admin/includes/plugin.php';
		$routes            = array();
		$installed_plugins = get_plugins();

		// *** Contact Form 7 (belt-and-suspenders on top of the `_wpcf7` pattern) ***
		if ( array_key_exists( 'contact-form-7/wp-contact-form-7.php', $installed_plugins ) ) {
			$routes[] = 'contact-form-7/v1/contact-forms/*/feedback';
		}

		// *** WS Form (submits over its own REST namespace, no admin-ajax path) ***
		if ( array_key_exists( 'ws-form/ws-form.php', $installed_plugins ) ) {
			$routes[] = 'ws-form/v1/*';
			self::display_admin_notice( __( 'WS Form detected – added REST route: ws-form/v1/*', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Otter Blocks (Gutenberg form block submits over REST, no admin-ajax path) ***
		if ( array_key_exists( 'otter-blocks/otter-blocks.php', $installed_plugins ) ) {
			$routes[] = 'otter/v1/form/frontend';
			self::display_admin_notice( __( 'Otter Blocks detected – added REST route: otter/v1/form/frontend', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** SureForms (TESTSUITE_PLAN.md AP4). Submits over its own REST namespace,
		// no admin-ajax SUBMIT path (verified against the pinned 2.12.3 zip's
		// inc/form-submit.php: SRFM\Inc\Form_Submit registers
		// `register_rest_route( 'sureforms/v1', '/submit-form', … )` on
		// `rest_api_init`; the front-end submit script calls
		// `wp.apiFetch( { path: 'sureforms/v1/submit-form', method: 'POST', … } )`,
		// assets/js/minified/form-submit.min.js). SureForms DOES register other
		// `wp_ajax(_nopriv)_*` hooks — `validation_ajax_action` in the SAME
		// Form_Submit::__construct() (inc/form-submit.php:57-58) and
		// `srfm_create_payment_intent`/`srfm_create_subscription_intent` in
		// Front_End::__construct() (inc/payments/front-end.php:44-47) — but none of
		// them is the actual form SUBMISSION, which always goes through the REST
		// route above; the payment-intent endpoints are known, deliberately
		// uncovered frontend write paths (no signature seeded for them here).
		// Seeded as the EXACT endpoint, not a
		// `sureforms/v1/*` namespace wildcard: that namespace also carries several
		// `manage_options`-gated ADMIN endpoints a logged-in admin's own browser calls
		// while editing a form (inc/create-new-form.php, inc/generate-form-markup.php,
		// inc/payments/stripe/*, inc/global-settings/*) — a wildcard would put those
		// behind this plugin's spam gate too and could block the SureForms admin UI
		// itself (the class of self-lockout `RestRoute::reject_self_lockout_lines()`
		// guards against for WordPress' OWN core namespaces, but that guard does not
		// and cannot know about a third-party plugin's admin routes).
		if ( array_key_exists( 'sureforms/sureforms.php', $installed_plugins ) ) {
			$routes[] = 'sureforms/v1/submit-form';
			self::display_admin_notice( __( 'SureForms detected – added REST route: sureforms/v1/submit-form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		return implode( "\n", $routes );
	}

	public function prepare_options() {
		$pow_save_spam_label = sprintf(
			/* translators: %s: URL to the spam inbox page */
			__(
				"You can review your saved spam messages <a href='%s'>here</a>.",
				'gdpr-compliant-recaptcha-for-all-forms'
			),
			admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_SPAM
		);

		$text_block = __(
			'Once enabled, submissions that the spam check classifies as spam are rejected outright instead of being passed on to your form or mailer.<br><br>Turn this off if you would rather let every submission through and rely only on flagging (see <b>Flag spam messages</b> 🚩) or manual review in the spam inbox.',
			'gdpr-compliant-recaptcha-for-all-forms'
		);

		$text_flag = __(
			'<strong>How it works:</strong> Instead of blocking spam messages, this option lets them through but marks them, so you can still receive every submission by mail while sorting spam into a separate folder client-side.
<br>
<br><strong>Use this if:</strong> your messages are routed to your email address and you want to receive all of them, but with spam ones flagged so your mail program can move them to a spam folder automatically.
<br>
<br>To flag spam in a specific field or a newly created field instead of blocking it:
<br><ul>
        <li>disable <b>Block spam</b> ⛔</li>
        <li>and either maintain <b>Fieldname:prefix to flag spam _*</b>, to signal spam via an existing technical field</li>
        <li>or maintain <b>New "POST" field to flag spam +</b>, to signal spam via a brand-new technical field</li>
    </ul>',
			'gdpr-compliant-recaptcha-for-all-forms'
		);

		$text_flag_suffixes = sprintf(
			/* translators: 1: opening anchor tag linking to the message inbox, 2: closing anchor tag */
			__(
				"<strong>How it works:</strong> The flagging works by adding a prefix (e.g. <code>[spam]</code>) to the value of a chosen field (e.g. a subject field) from a specific form.
<br>In your email client you can use this prefix to create a rule that moves flagged mails into a spam folder.
<br>
<br><strong>Example:</strong>
<br><ul>
        <li>the subject <code>New contact request</code>,</li>
        <li>submitted with the field <code>subject</code> of the contact form,</li>
        <li>is changed to <code>[spam]New contact request</code></li>
        <li>if the submission is classified as spam.</li>
    </ul>
<br><strong>Finding the field name:</strong> Enter the combination of field name and prefix into this textbox. The field name has to be the specific technical field name of the message you want to flag. If you don't know it, you can find it this way:
    <br><ol>
        <li>Tick the box for 'Save clean messages'.</li>
        <li>Post a message from the respective form.</li>
        <li>Open the %1\$sMessage inbox%2\$s and the just-received message.</li>
        <li>Look for the field you want to use for flagging and take the name of the respective attribute, without quotes.</li>
        <li>If the field name is nested, it may look a bit confusing (example: <code>wpforms->fields->0->first</code>). This happens when your form builder uses a nested field structure — the field name reflects that structure. Copy the whole field name without the trailing colon.</li>
    </ol>
<br><strong>Format:</strong> <code>fieldname:prefix</code>
<br>
<br><strong>Examples:</strong>
<br><code>prename:spam</code>
<br><code>wpforms->fields->0->first:[spam]</code>
<br>
<br><strong>Multiple fields:</strong> To add different flags to different technical fields, enter a new line for each combination of field name and prefix. This helps when different sources of submissions use different technical field names.",
				'gdpr-compliant-recaptcha-for-all-forms'
			),
			'<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES . '">',
			'</a>'
		);

		$this->options = array(
			Option::POW_DIRECT_ANALYSIS_MODE    => new Option(
				__( 'Direct analysis mode', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				sprintf(
					__(
						'<strong>How it works:</strong><br>
                    Once activated...<br>
                    <ol>
                        <li>Navigate to the pages containing your forms.</li>
                        <li>Submit the forms you want to add to the spam check.</li>
                        <li>Enhance the spam check directly from your pages.</li>
                        <li>Follow the additional instructions shown on the forms.</li>
                        <li>Finally, remember to deactivate the mode.</li>
                    </ol>',
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🕵️',
				__( 'Adds an inline helper to your live forms so you can teach the spam check about them without leaving the page.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_ANALYSIS_MODE           => new Option(
				__( 'Analysis mode', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				sprintf(
					/* translators: 1: URL to the Analytic Box (inline mention), 2: URL to the Analytic Box (step-by-step link) */
					__(
						"<strong>Why you might need this:</strong> If you cannot see specific submissions in the messages or spam inbox, enable analysis mode. Many types of POST submissions belong to technical background processes and are ignored by the spam check, which by default only runs on WordPress's standard submission routine — but many form builders and other plugins use proprietary submission methods.
                    <br>
                    <br><strong>How it works:</strong> In this mode, every type of POST submission is saved into the <a href='%1\$s'>Analytic Box</a>, a further inbox of this plugin used to widen the scope of the spam check.
                    <br><br>
                    <ol>
                        <li>Submit the specific form type you want the spam check to cover.</li>
                        <li>Visit the <a href='%2\$s'>Analytic Box</a> and look for the message related to your submission (usually one of the latest).</li>
                        <li>For a Non-Ajax-Request message, choose the field/value combination that identifies it. If a future message matches all chosen attributes and values, the spam check will cover it too — pick as few pattern elements as possible. Example: to recognize Contact Form 7, <code>_wpcf7</code> is enough, since virtually all its submissions include that key.</li>
                        <li>Click the button at the bottom of the message to register the pattern or action.</li>
                        <li>A single form submission can sometimes trigger multiple separate requests, each producing its own message in the Analytic Box — register all of them if applicable.</li>
                        <li>Disable <b>Analysis mode</b> 🔍 to stop recording.</li>
                    </ol>",
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS,
					admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔍',
				__( 'Records every incoming POST submission so you can add unrecognized form types to the spam check.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_EXPLICIT_ACTION         => new Option(
				__( 'Apply on actions', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				self::get_default_ajax_actions(),
				sprintf(
					/* translators: 1: opening anchor tag linking to the message inbox, 2: closing anchor tag, 3: URL to the Analytic Box */
					__(
						"Add one action per line that you want the spam protection to cover while the plugin is in <b>Explicit mode</b> 🎯.
                        <br>You can find and copy the action from unwanted messages in the plugin's %1\$sspam or message inbox%2\$s, or use <b>Analysis mode</b> 🔍 to record all types of submissions: open the <a href='%3\$s'>Analytic Box</a>, search for the related message and register its action from the button at the bottom of that message.
                        <br>
                        <br><strong>Example:</strong>
                        <br>
                        <br><code>forminator_submit_form_custom-forms</code>
                        <br><code>wpforms_submit</code>",
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					'<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES . '">',
					'</a>',
					admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⚙️✔️',
				__( 'Names the specific AJAX/form actions that the spam check should apply to when running in Explicit mode.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_PARAMETER_PATTERN       => new Option(
				__( 'Apply on pattern', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				self::get_default_recognition_patterns(),
				sprintf(
					/* translators: 1: opening anchor tag linking to the Analytic Box, 2: closing anchor tag */
					__(
						'<strong>Why you might need this:</strong> If your form submissions are not filtered by the spam check, the most likely reason is that this submission type is not yet recognized by it.
                    <br>
                    <br><strong>How it works:</strong> You can insert and view parameter patterns here directly, but the easiest way is to enable <b>Analysis mode</b> 🔍, submit the form you want covered, and search the %1$sAnalytic Box%2$s for the related message.
                    Open it, choose the fields and values that identify your pattern, and add the pattern via the button at the bottom of the message.
                    <br>Added patterns are listed here line by line, in JSON format, and can be edited directly.',
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					'<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS . '">',
					'</a>'
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔍✔️',
				__( 'Defines field/value patterns that identify a submission type so the spam check applies to it.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_REST_ROUTES             => new Option(
				__( 'Apply on REST routes', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				self::get_default_rest_routes(),
				__(
					'<strong>Why you might need this:</strong> Some form builders submit over the WordPress REST API instead of a classic POST or AJAX call, and carry neither an <b>Apply on actions</b> ⚙️✔️ value nor an <b>Apply on pattern</b> 🔍✔️ match — this list is what covers them.
                    <br>
                    <br><strong>How it works:</strong> Add one REST route per line. A leading slash is optional. Two wildcard forms are supported:
                    <br><ul>
                        <li><code>*</code> as one segment matches exactly that segment, e.g. a form ID: <code>contact-form-7/v1/contact-forms/*/feedback</code></li>
                        <li><code>*</code> as the LAST segment matches the whole namespace below it, e.g. <code>ws-form/v1/*</code></li>
                    </ul>
                    <br><strong>Never add a bare core namespace like <code>wp/v2</code></strong> — that would also match the block editor\'s own save requests and block your own post saves.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🧭✔️',
				__( 'Names the REST API routes that the spam check should apply to, for builders that submit over REST.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_BLOCK_LOGIN             => new Option(
				__( 'Apply for WordPress-Login', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__(
					'This option improves site security a lot.
                    <br>
                    <br><strong>Test first:</strong> enable <em>Simulate spam messages</em> before switching this on for a live site — it lets you verify nothing legitimate gets locked out.
                    <br>
                    <br><strong>But beware:</strong> for any plugin that secures the WP login, only use this if you know how to switch it off without logging in (e.g. by deleting the plugin files from your plugin directory). If anything goes wrong, the plugin will block your login too.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Most relevant', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔒',
				__( 'Applies the proof-of-work check to the WordPress login form in addition to your other forms.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_BLOCK                   => new Option(
				__( 'Block spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				$text_block . '<br><br><strong>Test first:</strong> ' . __( 'enable <em>Simulate spam messages</em> before switching this on for a live site — it lets you verify nothing legitimate gets blocked.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⛔', // Blocking
				__( 'Blocks submissions classified as spam instead of letting them through.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FLAG_SPAM               => new Option(
				__( 'Flag spam messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				$text_flag,
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🚩',
				__( 'Lets spam through but marks it so your mail client can filter it into a spam folder.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FLAG_SUFFIXES           => new Option(
				__( 'Fieldname:prefix to flag spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				$text_flag_suffixes,
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'_*',
				__( 'Adds a text prefix such as [spam] to a chosen field when a message is flagged as spam.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FLAG_TAGS               => new Option(
				__( 'New "POST" field to flag spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					"<strong>Use this if:</strong> you want to flag spam via a brand-new POST field instead of a prefix. This field can then be used during further processing (e.g. a mailer, database routines, a mail client, ...).
                <br>
                <br><strong>Beware:</strong> this option overrides existing post fields with the same name, which may affect further processing. If you want to be sure not to override an existing field, check the technical field names of your messages first, as described for the prefixes above.
                <br>
                <br><strong>How it works:</strong> For each combination of <code>field:value</code>, add a new line. If different follow-up processes require different fields to flag spam, add multiple lines.
                <br>
                <br><strong>Example:</strong> <code>spam_filter:spam</code>
                <br>
                <br>Applying this rule, a flagged spam message with the attributes ...
                <br>
                <br><code>{'name': 'Matthias Nordwig', 'email':'matthias.nordwig@programmiere.de', 'message':'Hi there'}</code>
                <br>
                <br>... would turn into ...
                <br>
                <br><code>{'name': 'Matthias Nordwig', 'email':'matthias.nordwig@programmiere.de', 'message':'Hi there', 'spam_filter':'spam'}</code>",
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'+',
				__( 'Adds a brand-new field with a fixed value to messages that are flagged as spam.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_ERROR_MESSAGE           => new Option(
				__( 'Error message', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::STRING,
				__( 'Your message has been classified as spam! If you are a human, we are very sorry. Please give us notice via email.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__(
					"
                    Usually visitors will never see this message, but if anything goes wrong, this is your chance to give them some meaningful advice.
                    <br>
                    <br>For some form builders or other relevant plugins, the error message won't pop up, since each plugin uses its own display format.
                ",
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'❌',
				__( 'Sets the message shown to visitors on the frontend when their submission is blocked as spam.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SIMULATE_SPAM           => new Option(
				__( 'Simulate spam messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__(
					'If checked, every incoming submission is treated as spam, so you can verify that blocking and flagging work as intended before relying on them for real traffic. It is not applied to the WordPress login.<br><br><strong>Beware:</strong> do not forget to uncheck this option once your testing is done.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'📈',
				__( 'Treats every incoming submission as spam so you can safely test blocking and flagging before going live.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FAIL_2_BAN_PATH         => new Option(
				__( 'Path to save spam approaches to syslog', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					'<strong>The purpose:</strong> <br>Fail2Ban is a security tool designed to <strong>protect servers</strong> by monitoring log files and automatically blocking IP addresses involved in <strong>repeated unauthorized access attempts or suspicious activity</strong>.
                            <br>While commonly used for <strong>SSH, email servers, and web applications</strong>, this integration focuses on securing WordPress forms from login abuse and spam.<br>

                            <br><strong>Specify the directory path where log files should be stored:</strong>
                            <ul>
                            <li>If the field is <strong>left empty or contains an invalid path</strong>, logging remains <strong>disabled</strong>.</li>
                            <li>A <strong>valid directory path</strong> enables logging, generating two separate log files:
                                <ul>
                                <li><strong>Login attempts log:</strong> <code>auth.log</code> — records failed login attempts.</li>
                                <li><strong>Spam detection log:</strong> <code>spam.log</code> — logs suspicious form submissions.</li>
                                </ul>
                            </li>
                            </ul>

                            <br>Ensure the specified path is <strong>writable</strong> by the server and does not include a filename, as logs are managed automatically within the chosen directory.
                            <br>If <code>auth.log</code> or <code>spam.log</code> already exist in the specified directory, they are reused instead of creating new files.<br>',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Spam Processing', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛡',
				__( 'Writes failed logins and spam attempts to log files that tools like Fail2Ban can monitor.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SAVE_CLEAN              => new Option(
				__( 'Save clean messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				sprintf(
					/* translators: %s: URL to the message inbox page */
					__( "You can review your saved clean messages <a href='%s'>here</a>.", 'gdpr-compliant-recaptcha-for-all-forms' ),
					admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES
				),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'💾',
				__( 'Stores non-spam submissions in the message inbox so you can review them later.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SAVE_SPAM               => new Option(
				__( 'Save spam messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				$pow_save_spam_label,
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'💾',
				__( 'Stores submissions classified as spam in the spam inbox so you can review them later.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SAVE_LOGIN              => new Option(
				__( 'Save Logins', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( "Disable this option if you don't want submissions from the WordPress login and password-reset forms to be recorded. Analysis Mode is the one exception — while it is on, it keeps capturing them for inspection.<br><br>Password values are never stored either way; they are replaced with [redacted].", 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔒💾',
				__( 'Records login and password-reset submissions in the message inbox.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_FLAG_SAVE               => new Option(
				__( 'Save spam messages with flag', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( 'Controls whether spam messages are saved with their flag intact or with the flag stripped.<br><br>For testing whether flagging works as desired, it can be useful to save messages with their flags.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🚩💾',
				__( 'Keeps the spam flag on messages that are saved, instead of stripping it before saving.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SAVE_IP                 => new Option(
				__( 'Save spam messages with IP', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__( "<strong>Warning:</strong> saving visitors' IP addresses does not comply with the European data privacy act <b>GDPR</b>.", 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛡️💾',
				__( "Stores the submitter's IP address with saved spam messages (not GDPR-compliant).", 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SKIP_FIELDS             => new Option(
				__( 'Skip fields from saving and spam analysis', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				sprintf(
					/* translators: 1: opening anchor tag linking to the message inbox, 2: closing anchor tag */
					__(
						"<strong>Use this if:</strong> you want to exclude specific fields on specific sites from being saved with messages. This is recommended for password fields, in particular.
                    <br>
                    <br><strong>How it works:</strong> Enter each combination of <code>site:field-name</code> on its own line. The field name has to be the specific technical field name, and the site name the specific technical name of the site containing it.
                    <br>If you don't know the exact technical field names and site names, you can find them this way:
                        <br><ol>
                            <li>Tick the box for 'Save clean messages'.</li>
                            <li>Save the options.</li>
                            <li>Post a message from the respective site.</li>
                            <li>Open the %1\$sMessage inbox%2\$s and the just-received message.</li>
                            <li>Look for the field you wish to skip from saving and take the name of the respective attribute, without quotes.</li>
                            <li>Look for the attribute 'from_site' to get the technical name of the site — just copy the unique part of the URL (i.e. the specific site name without the domain or any parameters).</li>
                        </ol>
                    <br><strong>Format:</strong> <code>site:field-name</code>
                    <br>
                    <br><strong>Example:</strong>
                    <br><u>Given site:</u> <code>www.your-domain.net/specific_site/?action=123</code>
                    <br><u>Given field name:</u> <code>pwd</code>
                    <br>
                    <br><u>Line to add:</u> <code>/specific_site/:pwd</code>
                    <br>
                    <br><strong>Also exempts from spam analysis:</strong> fields on this list are additionally excluded from content analysis, in particular gibberish detection. This is the right place for fields with technical values (captcha tokens, license/serial numbers, API keys) that get misclassified as 'Gibberish content'.
                    <br><strong>Important difference:</strong> for saving, an entry only applies to the given site (<code>site:field-name</code>). For spam analysis, the site part is ignored — the field name is exempted <strong>across all sites</strong>.
                    <br>Fields whose name contains <code>pass</code>, <code>pwd</code>, <code>token</code>, <code>code</code>, <code>coupon</code>, or <code>captcha</code> are already exempted automatically and don't need to be listed here.
                    <br>Developers can grant the same exemption in PHP via the <code>gdpr_pow_gibberish_exempt_fields</code> filter (signature: <code>apply_filters( 'gdpr_pow_gibberish_exempt_fields', array \$names, array|mixed \$fields )</code>, must return an array of field-name strings).
                    ",
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					'<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES . '">',
					'</a>'
				),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🚫▭',
				__( 'Excludes specific fields, such as passwords, from being saved with messages and from spam/gibberish analysis.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_CREDENTIAL_FIELDS       => new Option(
				__( 'Credential fields', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					"<strong>What this is:</strong> the list of field names this plugin treats as passwords. Their values are never stored — the field still appears in a saved message, but its value reads <code>[redacted]</code>.
                    <br>
                    <br><strong>You normally do not edit this here.</strong> Common password field names are recognised automatically. When a form on your site posts a password field with an unusual name, the plugin offers to add it — as a notice at the top of your admin pages, or as a <em>Treat as credential field</em> button next to the value in a saved message. This box is the place to review, correct and remove those entries.
                    <br>
                    <br><strong>Format:</strong> one field name per line, exactly as it appears in a saved message (the part after the last <code>-&gt;</code> for nested fields). Matching is case-insensitive and applies to whole names only — an entry <code>pass</code> never matches <code>passenger</code>. Entries are NOT tied to a site: a password field name counts everywhere.
                    <br>
                    <br><strong>Adding a name here also cleans up:</strong> messages you already received are redacted retroactively, in small steps, over the following page loads.
                    <br>
                    <br><strong>Careful with:</strong> <code>email</code>, <code>name</code>, <code>subject</code> and <code>message</code>. Redacting those hides the very values you need to judge and block spam, so the plugin never suggests them.
                    <br>
                    <br><strong>Not the same as 'Skip fields from saving':</strong> that one drops a field completely and is tied to a site. This one keeps the field visible and only removes its value.",
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔑🚫',
				__( 'Field names whose values are stored as "[redacted]" — normally filled by confirming the plugin\'s own suggestions.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_MESSAGE_HEADS           => new Option(
				__( 'Subject fields', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				sprintf(
					/* translators: %s: URL to the message inbox page */
					__(
						"<strong>Use this if:</strong> you want meaningful titles on the saved messages page instead of generic ones, by customizing the subject fields per form.
                <br>
                <br><strong>How it works:</strong> Add a new line for each part of the subject. The field name has to be the specific technical field name of the message. If you don't know it, you can find it this way:
                <br>
                <br><ol>
                    <li>Tick the box for 'Save clean messages'.</li>
                    <li>Post a message from the respective form.</li>
                    <li>Open the <a href='%s'>\"Messages\" inbox</a> and open the message that was just saved.</li>
                    <li>Look for the field you want to use, and take the name of the respective attribute without quotes.</li>
                </ol>
                <br><strong>Example for a subject composed of two parts:</strong>
                <br>
                <br><code>subject</code>
                <br><code>wpforms->fields->1</code>",
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_MESSAGES
				),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔤',
				__( 'Builds a readable subject line for saved messages from one or more submitted fields.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SAVE_CART               => new Option(
				__( 'Save WooCommerce shopping carts', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( 'If you get too many messages from shopping carts, you can disable this option.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛒',
				__( 'Saves WooCommerce shopping cart activity as messages in the inbox.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_CRON_DELETE_INBOX       => new Option(
				__( 'Automatic Message Deletion Interval', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				0,
				__( 'Note: to disable automatic deletion, set the number to 0 or leave the field empty.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🗑️✉️',
				__( 'Automatically deletes messages from the inbox after a set number of days.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_CRON_DELETE_SPAM        => new Option(
				__( 'Automatic Spam Deletion Interval', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				0,
				__( 'Note: to disable automatic deletion, set the number to 0 or leave the field empty.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🗑️📩',
				__( 'Automatically deletes messages from the spam inbox after a set number of days.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_CRON_DELETE_TRASH       => new Option(
				__( 'Automatic Trash Deletion Interval', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				0,
				__( 'Note: to disable automatic deletion, set the number to 0 or leave the field empty.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Saving Messages', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🗑️📨',
				__( 'Automatically deletes messages from the trash after a set number of days.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_IP_WHITELIST            => new Option(
				__( 'IP-Whitelist', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__( 'Add one IP per line, without any separator.<br><br><strong>Example:</strong><br>192.0.0.1<br>241.x.x.xxx<br>...', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🌐',
				__( 'Exempts the listed IP addresses from the spam check entirely.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SITE_WHITELIST          => new Option(
				__( 'Site-Whitelist', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					'Add one site per line, without the protocol (i.e. without "https://" or "http://").
                        <br>
                        <br><strong>Example:</strong>
                        <br>
                        <br><code>dev.whistle-blower.net/?rest_route=/jetpack/v4/verify_registration/</code>
                        <br>...',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'📄',
				__( 'Exempts the listed URLs (without protocol) from the spam check entirely.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_TRUSTED_PROXIES         => new Option(
				__( 'Trusted proxies', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					'One IP or CIDR range per line. Forwarded-For headers are only honored when the request comes from one of these proxies. Leave empty if your site is not behind a reverse proxy.
                        <br>
                        <br><strong>Example:</strong>
                        <br>
                        <br><code>203.0.113.10</code>
                        <br><code>10.0.0.0/8</code>
                        <br>...',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛰️',
				__( "Lists proxy IPs allowed to supply the visitor's real IP via forwarding headers.", 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_HIDE_ACTION             => new Option(
				__( 'Hide actions', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				__(
					'Add one action per line that you do not want shown in the Analytic Box of <b>Analysis mode</b> 🔍.
                        <br>
                        <br><strong>Example:</strong>
                        <br>
                        <br><code>heartbeat</code>',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⚙️🚫',
				__( 'Hides the listed action names from the Analytic Box while Analysis mode is recording.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_HIDE_PATTERN            => new Option(
				__( 'Hide Patterns', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::TEXT,
				'',
				sprintf(
					/* translators: 1: opening anchor tag linking to the Analytic Box, 2: closing anchor tag */
					__(
						'Manage, line by line, the patterns that you do not want shown in the Analytic Box of <b>Analysis mode</b> 🔍.
                        <br>The easiest way to add a pattern is directly from the %1$sAnalytic Box%2$s.',
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					'<a href="' . admin_url( 'admin.php', 'https' ) . Option::PAGE_QUERY_ANALYSIS . '">',
					'</a>'
				),
				__( 'Scope', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔍🚫',
				__( 'Hides submissions matching the listed patterns from the Analytic Box.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_MENU_POSITION           => new Option(
				__( 'Messages Inbox Position', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				0,
				__(
					"<strong>How it works:</strong> The default '0' places the menu in the first position. The number also has to account for WordPress's own submenu entries, so a value like '40' may in fact result in a real position of 8 — you may need to experiment with the figure to get your preferred position.
                    <br>To hide the messages inbox entirely, set this option to '-1'.",
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'WordPress Administration', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'📌', //Number symbol
				__( 'Sets where the message inbox appears in the WordPress admin menu.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_DASHBOARD               => new Option(
				__( 'Message counters on the Wordpress Dashboard', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( 'Includes counts for messages, spam and trash (today and in total), so you can see activity at a glance without opening the inboxes.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'WordPress Administration', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'📊', //Dashboard symbol
				__( 'Shows message counters as a widget on the WordPress dashboard.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_SALT                    => new Option(
				__( 'Salt', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::STRING,
				hash( 'sha256', gmdate( 'Y-m-d H:i:s.u' ) ),
				__( "Set this to a random string to give some unknown salt to the puzzle. It increases security, as it can't be guessed client-side.<br><br>By default, this salt is generated as a hash from the point in time of your installation.", 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔑',
				__( "Adds a secret random string to the proof-of-work puzzle so it can't be pre-computed client-side.", 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_TIME_WINDOW             => new Option(
				__( 'Time Window', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				10,
				__( 'The number of minutes a hash-puzzle stays valid before it has to be computed and solved anew.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⌛',
				__( 'Sets how many minutes a generated hash-puzzle stays valid before it must be solved again.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_DIFFICULTY              => new Option(
				__( 'Difficulty', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				14,
				sprintf(
					/* translators: %d: under-attack difficulty bonus in bits (Stamp::UNDER_ATTACK_BONUS) */
					__(
						"If you don't know about the concept of proof-of-work, don't change this.
                        <br>
                        <br><strong>Approximate number of hash guesses required per difficulty target:</strong>
                        <ul>
                            <li>Difficulty 1-4: 10</li>
                            <li>Difficulty 5-8: 100</li>
                            <li>Difficulty 9-12: 1,000</li>
                            <li>Difficulty 13-16: 10,000</li>
                            <li>Difficulty 17-20: 100,000</li>
                            <li>Difficulty 21-24: 1,000,000</li>
                            <li>Difficulty 25-28: 10,000,000</li>
                            <li>Difficulty 29-32: 100,000,000</li>
                        </ul>
                        Modern browsers solve the puzzle via crypto.subtle, which is roughly 10x faster than the plain-JavaScript fallback used by older browsers.
                        <br>
                        <br><strong>Recommended base: 15–16.</strong> Under-attack mode temporarily adds %d bits on top of your base difficulty, so the value you set here is what every visitor pays in normal operation — the table above shows what each step costs them.
                        <br>
                        <br>Every visitor solves exactly one puzzle at the difficulty you set here. Earlier versions could hand out a second, harder puzzle when a solve looked implausibly fast; that was removed, because how long a solve takes says nothing reliable about who solved it.",
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					Stamp::UNDER_ATTACK_BONUS
				),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🧩',
				__( "Controls how much computing power a visitor's browser must spend solving the proof-of-work puzzle. Recommended base: 15–16, to leave headroom for the under-attack boost.", 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_MAX_USES                => new Option(
				__( 'Max submissions per solved challenge', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::INT,
				10,
				__( 'Bots that replay one solution are cut off after this many submissions; raise it if legitimate visitors submit many forms in quick succession.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔁',
				__( 'Caps how many form submissions a single solved proof-of-work may be used for within the validity window.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_UNDER_ATTACK_MODE       => new Option(
				__( 'Under-attack mode', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__( 'Based purely on a coarse, site-wide counter — no per-visitor data is collected or stored.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🚨',
				__( 'Temporarily raises the puzzle difficulty for all visitors when site-wide spam suddenly spikes (+3 bits, roughly 8x the computing time, whenever 15+ blocked/flagged submissions occur within about 10 minutes).', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_UNDER_ATTACK_QUARANTINE => new Option(
				__( 'Under-attack quarantine', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__(
					'<strong>What it does:</strong> While a spam wave is detected (the same site-wide counter that drives under-attack mode), submissions that pass every individual check are treated like spam: they land in the spam folder for review, and your regular spam handling applies — with "Block spam" enabled they are held back instead of being delivered.
					<br>
					<br><strong>Nothing is lost:</strong> quarantined messages are never discarded — they wait in the spam folder, and you rehabilitate genuine ones from there, exactly as with any other spam. Quarantined submissions never feed the wave counter itself, so the quarantine cannot keep the wave alive on its own.
					<br>
					<br><strong>Use this if:</strong> during an attack you would rather review grey-zone messages by hand than risk a spam submission slipping through. Be aware that with "Block spam" enabled, genuine visitors submitting during a wave will also see the spam error until the wave subsides. It only ever acts while a wave is in progress.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🛡️',
				__( 'During a detected spam wave, treat otherwise-clean submissions as spam and hold them in the spam folder for review. Off by default; nothing is ever lost.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_ECHO_LOCK_ENABLED       => new Option(
				__( 'Repeat-sender echo lock', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				true,
				__(
					'<strong>What it does:</strong> Whenever a submission is classified as spam, the echo lock briefly remembers its core values (sender email, linked domain, phone number, and the hash of a long message body) as one-way hashes with a short lifetime. A later submission carrying the same value — on <em>any</em> form and from <em>any</em> IP — is then caught as well, so a returning spammer is stopped even after switching forms or rotating addresses.
					<br>
					<br><strong>Just a bonus layer:</strong> this only <em>adds</em> to the proof-of-work check; it never replaces it. Values are stored as hashes only (never in plain text) and expire on their own after about a day and a half.
					<br>
					<br><strong>Turn it off if</strong> (rarely) you would rather not carry values over between submissions at all — for example while diagnosing a false positive. Addresses of your registered users are already excluded automatically, so this is seldom necessary. You can also release all currently held values at any time under <em>Diagnostics</em> on this page.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'Algorithm', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🔁',
				__( 'Briefly remembers the core values of spam submissions (as hashes) so the same sender/domain is caught again on any form. A bonus layer over the proof-of-work; on by default.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_ABILITIES_WRITE         => new Option(
				__( 'Let agents extend what is monitored', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__(
					'<strong>What it does:</strong> With this on, an AI agent acting as a logged-in administrator can add form actions, field patterns and REST routes to the monitored scope — the same three lists you edit under <em>Recognition</em>. This is what makes it possible for an agent to notice an unprotected form and connect it up for you.
					<br>
					<br><strong>What it cannot do:</strong> entries are only ever added, never removed, and the agent cannot touch anything you added yourself. Entries that would make the plugin evaluate WordPress\' own admin traffic are refused outright, as are patterns built only from generic field names, and patterns that block senders rather than monitor forms.
					<br>
					<br><strong>What you take on:</strong> a badly chosen entry makes the plugin evaluate requests it should not, which shows up as genuine submissions being treated as spam. Every change is recorded, and you can review and undo all of it under <em>Recognition</em>. Off by default.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'AI & Agents', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'🤖',
				__( 'Let an AI agent add form actions, field patterns and REST routes to the monitored scope. Only ever adds, never removes. Off by default.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
			Option::POW_ABILITIES_UNSAFE        => new Option(
				__( 'Let agents read submissions and change protection', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Option::BOOL,
				false,
				__(
					'<strong>Leave this off unless you know why you need it.</strong> It is the one setting here that can undo the protection rather than adjust it.
					<br>
					<br><strong>What it does:</strong> it opens two things to an AI agent acting as a logged-in administrator — reading stored submissions, and changing protection settings (including switching blocking off).
					<br>
					<br><strong>Why that is different from the setting above:</strong> an agent usually runs on an external AI service. This plugin still contacts nobody on its own, but with this on, content your visitors typed into your forms can be read by whatever agent you connect, and it stops being this plugin alone that decides where that content goes. What your agent does with it is yours to answer for, including under data-protection law.
					<br>
					<br>While this is on, a warning stays visible in your admin area. Off by default.',
					'gdpr-compliant-recaptcha-for-all-forms'
				),
				__( 'AI & Agents', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'⚠️',
				__( 'Let an AI agent read stored submissions and change protection settings. Submitted content can leave your site through the agent. Off by default.', 'gdpr-compliant-recaptcha-for-all-forms' )
			),
		);

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

	/** Ordered list of distinct option groups (tab/panel order), derived from
	 * $this->options insertion order.
	 *
	 * @return string[]
	 */
	private function get_groups() {
		$groups = array();
		foreach ( $this->options as $option ) {
			$group = $option->get_group();
			if ( ! in_array( $group, $groups, true ) ) {
				$groups[] = $group;
			}
		}
		return $groups;
	}

	/** Badge map for option rows (design-layer only, not part of the options-matrix).
	 *
	 * @return array<string, array{class: string, text: string}>
	 */
	private function get_badge_map() {
		$warn = array(
			'class' => 'gdpr-badge gdpr-badge-warn',
			'text'  => __( 'Can lock out visitors', 'gdpr-compliant-recaptcha-for-all-forms' ),
		);
		return array(
			Option::POW_BLOCK            => $warn,
			Option::POW_BLOCK_LOGIN      => $warn,
			Option::POW_ABILITIES_WRITE  => array(
				'class' => 'gdpr-badge gdpr-badge-warn',
				'text'  => __( 'Agent can change monitoring', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
			Option::POW_ABILITIES_UNSAFE => array(
				'class' => 'gdpr-badge gdpr-badge-warn',
				'text'  => __( 'Submissions can leave your site', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
			// Static recommendation: there is no difficulty ceiling any more, so there
			// is nothing left to warn about here (the boost is never clipped).
			Option::POW_DIFFICULTY       => array(
				'class' => 'gdpr-badge gdpr-badge-recommend',
				'text'  => __( 'Recommended: 15–16', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
		);
	}

	/** Allowlist shared by the header message and the per-option help popovers.
	 *
	 * @return array<string, array<string, array<int, string>>>
	 */
	private function get_allowed_html() {
		return array(
			'br'     => array(),
			'ol'     => array(),
			'ul'     => array(),
			'li'     => array(),
			'strong' => array(),
			'b'      => array(),
			'u'      => array(),
			'em'     => array(),
			'code'   => array(),
			'span'   => array( 'class' => array() ),
			'a'      => array(
				'href'  => array(),
				'title' => array(),
			),
		);
	}

	/** Renders the review/FAQ header line, escaped via wp_kses with a tight allowlist. */
	private function render_header_message() {
		$review_link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( 'https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/reviews/#new-post' ),
			esc_html__( 'Help us and rate it', 'gdpr-compliant-recaptcha-for-all-forms' )
		);
		$faq_link    = sprintf(
			'<a href="%s">%s</a>',
			esc_url( 'https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/' ),
			esc_html__( 'Get help in the support forum', 'gdpr-compliant-recaptcha-for-all-forms' )
		);

		$message1 = sprintf(
			/* translators: 1: checkmark icon, 2,3: line breaks */
			__( '%1$s The plugin is now active on all of your forms and logins.%2$s%3$s', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'<span class="large-checkmark">&#10003;</span>',
			'<br>',
			'<br>'
		);
		$message2 = sprintf(
			/* translators: 1: smiley icon, 2: review link, 3,4: line breaks, 5: thinking-smiley icon, 6: FAQ link */
			__( '%1$s Happy with the plugin? %2$s %3$s%4$s %5$s Problems, questions, hints, improvements? %6$s', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'<span class="large-smiley">&#128578;</span>',
			$review_link,
			'<br>',
			'<br>',
			'<span class="large-smiley">&#129300;</span>',
			$faq_link
		);

		echo wp_kses( $message1 . $message2, $this->get_allowed_html() );
	}

	/** Status strip: protection/simulation state, effective difficulty, under-attack
	 * flag, weekly spam count (see SETTINGS_MODERNIZE_PLAN.md "Status-Leiste").
	 */
	private function render_status_strip() {
		$simulate        = get_option( Option::POW_SIMULATE_SPAM );
		$base_difficulty = (int) get_option( Option::POW_DIFFICULTY );
		// Same gate as Stamp::get_stamp(): the boost only applies while the
		// under-attack option is enabled (explicit `true` fallback, see there).
		$under_attack   = get_option( Option::POW_UNDER_ATTACK_MODE, true ) && Stamp::is_under_attack();
		$effective      = ProofOfWork::effective_difficulty( $base_difficulty, $under_attack, Stamp::UNDER_ATTACK_BONUS );
		$spam_this_week = Option::count_messages_since_days( 2, 7 );

		$items = array();

		if ( $simulate ) {
			$items[] = array(
				'class' => 'gdpr-status-amber',
				'text'  => __( 'Simulation mode active', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		} else {
			$items[] = array(
				'class' => 'gdpr-status-green',
				'text'  => __( 'Protection active', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		if ( $under_attack ) {
			$items[] = array(
				'class' => '',
				'text'  => sprintf(
					/* translators: 1: base difficulty, 2: applied under-attack bonus */
					__( 'Difficulty %1$d +%2$d (under attack)', 'gdpr-compliant-recaptcha-for-all-forms' ),
					$base_difficulty,
					$effective - $base_difficulty
				),
			);
			$items[] = array(
				'class' => 'gdpr-status-amber',
				'text'  => __( 'Under attack', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		} else {
			$items[] = array(
				'class' => '',
				/* translators: %d: configured difficulty */
				'text'  => sprintf( __( 'Difficulty %d', 'gdpr-compliant-recaptcha-for-all-forms' ), $base_difficulty ),
			);
		}

		// Quarantine is gated on the raw wave detection (Stamp::is_under_attack()),
		// independent of POW_UNDER_ATTACK_MODE (which only gates the difficulty boost
		// above) — so it can be actively sorting even when $under_attack is false here.
		// Surface a subtle hint only while it is actually acting (option on + wave +
		// not simulating, mirroring the check_submit() gate).
		if ( ! $simulate && get_option( Option::POW_UNDER_ATTACK_QUARANTINE ) && Stamp::is_under_attack() ) {
			$items[] = array(
				'class' => '',
				'text'  => __( 'Quarantine active', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		$items[] = array(
			'class' => '',
			/* translators: %d: number of spam messages blocked in the last 7 days */
			'text'  => sprintf( __( '%d spam blocked this week', 'gdpr-compliant-recaptcha-for-all-forms' ), $spam_this_week ),
		);

		// Health counter: submissions whose classification reason was "no usable stamp
		// row" (no_pow:*) in the last 24h — the fingerprint of a broken client-PoW
		// pipeline (HANDBUCH §12). Amber above the threshold; the decision itself is the
		// pure Option::health_counter_status().
		$no_pow_count  = Option::count_no_pow_reasons_since_hours( Option::HEALTH_NO_POW_WINDOW_HOURS );
		$no_pow_status = Option::health_counter_status( $no_pow_count, Option::HEALTH_NO_POW_WARN_THRESHOLD );
		$items[]       = array(
			'class' => $no_pow_status['class'],
			'text'  => sprintf(
				/* translators: %d: number of submissions in the last 24 hours that had no usable proof-of-work stamp */
				_n( '%d submission without a stamp row (24h)', '%d submissions without a stamp row (24h)', $no_pow_count, 'gdpr-compliant-recaptcha-for-all-forms' ),
				$no_pow_count
			),
		);

		// Storage alarm: the server accepted a proof of work and could NOT write its row
		// (Stamp::record_store_failure()). This is the only state in which everything else
		// on this page looks healthy while literally every submission is classified spam —
		// so it gets its own red item plus the database error underneath the strip.
		$store_failures = (int) get_option( Option::POW_STORE_FAILED_TOTAL, 0 );
		$store_status   = Option::store_failure_status(
			$store_failures,
			(int) get_option( Option::POW_STORE_LAST_FAILED_AT, 0 ),
			time()
		);
		if ( $store_status['show'] ) {
			$items[] = array(
				'class' => $store_status['class'],
				'text'  => __( 'Solved puzzles cannot be stored', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		?>
		<div class="gdpr-status-strip">
			<?php foreach ( $items as $item ) : ?>
				<span class="gdpr-status-item <?php echo esc_attr( $item['class'] ); ?>"><?php echo esc_html( $item['text'] ); ?></span>
			<?php endforeach; ?>
		</div>
		<?php if ( $store_status['show'] ) : ?>
			<p class="gdpr-store-failure-hint">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %d: how often a solved puzzle could not be written to the database */
						_n(
							'%d solved puzzle could not be written to the database. While this lasts, every submission is treated as spam — the check that protects your forms looks for exactly that stored puzzle.',
							'%d solved puzzles could not be written to the database. While this lasts, every submission is treated as spam — the check that protects your forms looks for exactly that stored puzzle.',
							$store_failures,
							'gdpr-compliant-recaptcha-for-all-forms'
						),
						$store_failures
					)
				);
				?>
				<?php $store_error = (string) get_option( Option::POW_STORE_LAST_ERROR, '' ); ?>
				<?php if ( '' !== $store_error ) : ?>
					<br><code><?php echo esc_html( $store_error ); ?></code>
				<?php endif; ?>
				<br><?php esc_html_e( 'Usually the plugin\'s own table is missing or the database is read-only. Deactivating and reactivating the plugin re-creates the table; if it comes back, your host has to look at the database user\'s write permissions. Once you have fixed it, run the self-test under Diagnostics — a green result clears this message.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
			</p>
		<?php endif; ?>
		<?php $this->render_proxy_hint(); ?>
		<?php
	}

	/** Hint when THIS admin request arrived carrying forwarding headers while the
	 * trusted-proxy list is empty — i.e. the site very likely sits behind a proxy the
	 * plugin has not been told about, so every visitor is seen under the proxy's
	 * address (whitelist, fail2ban and per-IP limits then work on the wrong address).
	 *
	 * Read-only observation of the CURRENT request: only the presence of a header is
	 * evaluated, never its (client-settable) value, and nothing is stored. Only
	 * X-Forwarded-For is ever honored for resolution — the other names are listed
	 * because their presence is still evidence of a proxy hop.
	 *
	 * @return void
	 */
	private function render_proxy_hint() {
		if ( '' !== trim( (string) get_option( Option::POW_TRUSTED_PROXIES ) ) ) {
			return;
		}

		$present = array();
		foreach ( ClientIp::DIAGNOSTIC_HEADERS as $header_name ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- presence check only; the value is never read, stored or printed.
			if ( ! empty( $_SERVER[ $header_name ] ) ) {
				$present[] = str_replace( '_', '-', substr( $header_name, 5 ) );
			}
		}

		if ( empty( $present ) ) {
			return;
		}
		?>
		<p class="gdpr-echo-reset-hint">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %s: comma-separated list of forwarding header names seen on the current request */
					__( 'This request reached WordPress through a proxy (%s), but no trusted proxies are configured. Visitors are therefore all seen under the proxy\'s address, which affects the IP whitelist, fail2ban logging and per-IP limits. Enter the proxy address under "Trusted proxies" below. Only X-Forwarded-For is evaluated, and only from an address listed there.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					implode( ', ', $present )
				)
			);
			?>
		</p>
		<?php
	}

	/** Renders one option row: label, optional badge, optional short description,
	 * control, help toggle + popover.
	 *
	 * @param string $key
	 * @param Option $option
	 */
	private function render_option_row( $key, Option $option ) {
		$badge_map = $this->get_badge_map();
		$short     = $option->get_short();
		?>
		<div class="gdpr-option-row">
			<div class="gdpr-option-main">
				<label class="gdpr-option-label" for="<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $option->get_name() ); ?></label>
				<?php if ( isset( $badge_map[ $key ] ) ) : ?>
					<span class="<?php echo esc_attr( $badge_map[ $key ]['class'] ); ?>"><?php echo esc_html( $badge_map[ $key ]['text'] ); ?></span>
				<?php endif; ?>
				<?php if ( '' !== $short ) : ?>
					<p class="gdpr-option-short"><?php echo esc_html( $short ); ?></p>
				<?php endif; ?>
			</div>
			<div class="gdpr-option-control">
				<?php $this->render_control( $key, $option ); ?>
				<button type="button" class="gdpr-help-toggle" aria-expanded="false" aria-controls="help_<?php echo esc_attr( $key ); ?>">?</button>
				<div class="gdpr-help-popover" id="help_<?php echo esc_attr( $key ); ?>" hidden>
					<?php echo wp_kses( $option->get_hint(), $this->get_allowed_html() ); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/** Renders the input control for one option, by type.
	 *
	 * @param string $key
	 * @param Option $option
	 */
	private function render_control( $key, Option $option ) {
		$type = $option->get_type();
		$val  = $option->get_value();

		if ( Option::BOOL === $type ) {
			?>
			<label class="gdpr-toggle">
				<input type="checkbox" name="<?php echo esc_attr( $key ); ?>" id="<?php echo esc_attr( $key ); ?>" <?php checked( (bool) $val ); ?> />
				<span class="gdpr-toggle-slider"></span>
			</label>
			<?php
		} elseif ( Option::INT === $type ) {
			?>
			<input type="number" name="<?php echo esc_attr( $key ); ?>" class="regular-text" id="<?php echo esc_attr( $key ); ?>" value="<?php echo esc_attr( $val ); ?>" />
			<?php
		} elseif ( Option::STRING === $type ) {
			?>
			<input type="text" name="<?php echo esc_attr( $key ); ?>" class="regular-text" id="<?php echo esc_attr( $key ); ?>" value="<?php echo esc_attr( $val ); ?>" />
			<?php
		} elseif ( Option::TEXT === $type ) {
			?>
			<textarea name="<?php echo esc_attr( $key ); ?>" class="regular-text" id="<?php echo esc_attr( $key ); ?>"><?php echo esc_textarea( $val ); ?></textarea>
			<?php
		} elseif ( Option::ROLE_DROPDOWN === $type ) {
			// ROLE_DROPDOWN branch kept functional though unused by the current
			// options-matrix (see SETTINGS_MODERNIZE_PLAN.md).
			$selected_roles = (array) $val;
			$all_roles      = get_editable_roles();
			?>
			<select name="<?php echo esc_attr( $key ); ?>[]" id="<?php echo esc_attr( $key ); ?>" multiple="multiple">
				<?php foreach ( $all_roles as $role_key => $role ) : ?>
					<option value="<?php echo esc_attr( $role_key ); ?>" <?php selected( in_array( $role_key, $selected_roles, true ) ); ?>>
						<?php echo esc_html( $role['name'] ); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<?php
		}
	}

	/** Updating the values for the options
	 *
	 */
	public function update_settings() {
		$post_action = strval( filter_input( INPUT_POST, self::RCM_ACTION, FILTER_SANITIZE_SPECIAL_CHARS ) );
		// If update and current user is allowed to manage options
		if ( self::UPDATE === $post_action && current_user_can( 'manage_options' ) ) {
			$hash  = null;
			$nonce = isset( $_POST['gdpr_settings_nonce_field'] ) ? sanitize_text_field( wp_unslash( $_POST['gdpr_settings_nonce_field'] ) ) : '';
			if ( '' === $nonce || ! wp_verify_nonce( $nonce, 'gdpr_settings_nonce' ) ) {
				wp_die( esc_html__( 'Security check failed. This request was blocked by an active CSRF protection mechanism. It may have been triggered by another webpage you recently visited or an unrelated browser tab. To resolve this issue, close untrusted sites, check browser extensions, and refresh your WordPress session by logging in again.', 'gdpr-compliant-recaptcha-for-all-forms' ) );
			}

			foreach ( $this->options as $key => $option ) {
				$type = $option->get_type();
				// Check if the input is an array or a single value
				$is_array = Option::ROLE_DROPDOWN === $type;

				if ( $is_array ) {
					// For arrays, filter as strings
					$post_value = filter_input( INPUT_POST, $key, FILTER_DEFAULT, FILTER_REQUIRE_ARRAY );
					$post_value ? array_map( 'sanitize_text_field', $post_value ) : array();
				} elseif ( Option::TEXT === $type || Option::STRING === $type ) {
					$post_value = isset( $_POST[ $key ] ) ? wp_kses_post( wp_unslash( $_POST[ $key ] ) ) : null;
				} else {
					// For single values, apply the specified filter
					$post_value = filter_input( INPUT_POST, $key, $this->get_option_filter( $type ) );
				}

				// The fail2ban log path is a filesystem location the plugin writes to. On
				// multisite a plain site admin (manage_options) must not be able to aim it
				// at an arbitrary path — restrict that to super admins — and reject path
				// traversal on any install. An invalid value is left unchanged (the old
				// path stays), never silently redirected.
				if ( Option::POW_FAIL_2_BAN_PATH === $key && ! empty( $post_value )
					&& ( ( is_multisite() && ! is_super_admin() ) || 0 !== validate_file( (string) $post_value ) ) ) {
					continue;
				}

				// A REST-route line that covers one of WordPress' OWN namespaces is a
				// one-way door, not a typo the admin can walk back: POW_BLOCK is on by
				// default, so the block editor's own save (`/wp/v2/posts/<id>`) would be
				// discarded as spam — and wp-admin never receives the PoW script, so there
				// is no challenge to solve either. Only the database or FTP would get them
				// out. Such lines are dropped BEFORE storing and then NAMED to the admin
				// (never swallowed silently); everything else in the textarea is saved
				// normally. The decision itself is pure and unit-tested:
				// RestRoute::reject_self_lockout_lines() / tests/unit/RestRouteTest.php.
				if ( Option::POW_REST_ROUTES === $key && is_string( $post_value ) ) {
					list( $post_value, $rejected_routes ) = RestRoute::reject_self_lockout_lines( $post_value );
					if ( ! empty( $rejected_routes ) ) {
						add_settings_error(
							Option::PREFIX . 'options',
							'gdpr-rest-routes-rejected',
							sprintf(
								/* translators: %s: the rejected route lines, comma separated */
								__( 'These REST route lines were not saved: %s. They would also cover WordPress\' own core routes, which would block your post saves and lock you out of wp-admin. All other lines were saved.', 'gdpr-compliant-recaptcha-for-all-forms' ),
								implode( ', ', $rejected_routes )
							),
							'error'
						);
					}
				}

				if ( Option::BOOL === $type && ( null === $post_value || false === $post_value ) ) {
					// Checkbox unchecked: persist an explicit '0' instead of
					// delete_option(). Bestand: delete_option() + the options-matrix
					// default-fallback in prepare_options() made an unchecked
					// default-true option show as "on" again after saving, while the
					// runtime already read it as "off" via get_option() (no fallback
					// there) — a visible/actual state mismatch.
					update_option( $key, '0' );
				} elseif ( null !== $post_value && ( $is_array || false !== $post_value ) ) {
					update_option( $key, $post_value );

					if ( $is_array ) {
						$hash .= implode( '', $post_value );
					} elseif ( '_key' === substr( $key, -strlen( '_key' ) ) ) {
						$hash .= $post_value;
					}
				} else {
					delete_option( $key );
				}
			}
			// Add success message
			add_settings_error(
				Option::PREFIX . 'options',
				'my-plugin-success',
				__( 'Success! Your settings have been saved.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'updated'
			);
		}
	}

	/** Filter special chars if not int
	 *
	 */
	private function get_option_filter( $type ) {
		$filter = '';
		if ( Option::INT === $type ) {
			$filter = FILTER_SANITIZE_NUMBER_INT;
		} elseif ( Option::BOOL === $type ) {
			$filter = FILTER_VALIDATE_BOOLEAN;
		} else {
			$filter = FILTER_SANITIZE_FULL_SPECIAL_CHARS;
		}
		return $filter;
	}

	/**
	 * Drawing the options page for the plugin: status strip, pill tabs and one
	 * card per group, all rendered directly (no WP-Settings-API indirection).
	 */
	public function options_page() {
		$groups  = $this->get_groups();
		$tab_ids = array();
		foreach ( $groups as $group ) {
			$tab_ids[] = 'gdpr-tab-' . sanitize_title( $group );
		}
		// The one panel that is NOT derived from an option group: three ACTIONS with a
		// live state and no stored value (self-test, and the two diagnostic resets).
		// They used to hang above the tabs as loose forms, which is exactly what made
		// the head of this page look like a junk drawer. get_groups() stays purely
		// option-derived; only this method knows about the extra tab — and $tab_ids must
		// carry it too, or a save from this tab bounces the admin back to the first one.
		$tab_ids[] = self::TAB_DIAGNOSTICS;

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- read-only: only re-selects the active pill tab for display (sanitize_key()'d, no state change); the actual save path in update_settings() already verifies gdpr_settings_nonce before writing anything.
		$requested_tab = isset( $_POST['gdpr-settings-selection'] ) ? sanitize_key( wp_unslash( $_POST['gdpr-settings-selection'] ) ) : '';
		// $tab_ids is never empty since the Diagnostics tab is appended unconditionally,
		// so the first entry always exists — no isset() dance needed any more.
		$active_tab = in_array( $requested_tab, $tab_ids, true ) ? $requested_tab : $tab_ids[0];
		?>
		<div class="wrap gdpr-settings-wrap">
			<h1><?php echo esc_html( $this->plugin_name . ' - ' . __( 'Settings', 'gdpr-compliant-recaptcha-for-all-forms' ) ); ?></h1>
			<?php $this->render_header_message(); ?>
			<?php $this->render_status_strip(); ?>
			<nav class="gdpr-pill-tabs">
				<?php foreach ( $groups as $group ) : ?>
					<?php
					$tab_id    = 'gdpr-tab-' . sanitize_title( $group );
					$is_active = ( $tab_id === $active_tab );
					?>
					<button type="button" class="gdpr-pill-tab<?php echo $is_active ? ' is-active' : ''; ?>" data-tab-target="<?php echo esc_attr( $tab_id ); ?>"><?php echo esc_html( $group ); ?></button>
				<?php endforeach; ?>
				<button type="button" class="gdpr-pill-tab<?php echo self::TAB_DIAGNOSTICS === $active_tab ? ' is-active' : ''; ?>" data-tab-target="<?php echo esc_attr( self::TAB_DIAGNOSTICS ); ?>"><?php esc_html_e( 'Diagnostics', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></button>
			</nav>
			<form class="gdpr-settings-form" method="post" action="<?php echo esc_attr( Option::PAGE_QUERY ); ?>">
				<?php wp_nonce_field( 'gdpr_settings_nonce', 'gdpr_settings_nonce_field' ); // CSRF-protection add ?>
				<input type="hidden" name="<?php echo esc_attr( self::RCM_ACTION ); ?>" value="<?php echo esc_attr( self::UPDATE ); ?>">
				<input type="hidden" id="gdpr-settings-selection" name="gdpr-settings-selection" value="<?php echo esc_attr( $active_tab ); ?>">
				<?php foreach ( $groups as $group ) : ?>
					<?php
					$tab_id    = 'gdpr-tab-' . sanitize_title( $group );
					$is_active = ( $tab_id === $active_tab );
					?>
					<section class="gdpr-tab-panel" id="<?php echo esc_attr( $tab_id ); ?>"<?php echo $is_active ? '' : ' hidden'; ?>>
						<div class="gdpr-card">
							<?php
							foreach ( $this->options as $key => $option ) {
								if ( $option->get_group() === $group ) {
									$this->render_option_row( $key, $option );
								}
							}
							?>
						</div>
					</section>
				<?php endforeach; ?>
				<?php $this->render_diagnostics_panel( self::TAB_DIAGNOSTICS === $active_tab ); ?>
				<div id="submit-container">
					<?php submit_button(); ?>
				</div>
			</form>
		</div>
		<?php
	}

	/** The Diagnostics panel: actions, not settings.
	 *
	 * Same grammar as render_option_row() — label + one-line description on the left,
	 * control on the right, the long explanation behind the same `?` popover — because
	 * those long sentences standing in the open above the tabs were the actual eyesore.
	 * Two things an option row does not have: a live VALUE the action operates on (shown
	 * next to the button, so "what will this do" is answered before the click), and a
	 * full-width RESULT area under the row, since a self-test verdict is several
	 * sentences and must not be squeezed into the control column.
	 *
	 * Every button here is type="button" on purpose: the panel sits inside the settings
	 * form, so a forgotten type would turn a diagnostic click into a settings save.
	 *
	 * @param bool $is_active Whether this panel is the visible one.
	 * @return void
	 */
	private function render_diagnostics_panel( $is_active ) {
		$fp_share   = Option::fp_mismatch_share(
			get_option( Option::POW_FP_MATCHED_TOTAL, 0 ),
			get_option( Option::POW_FP_MISMATCHED_TOTAL, 0 )
		);
		$echo_count = Echo_Store::count();
		$diag_nonce = wp_create_nonce( self::AJAX_DIAG_TASK );
		?>
	<section class="gdpr-tab-panel" id="<?php echo esc_attr( self::TAB_DIAGNOSTICS ); ?>"<?php echo $is_active ? '' : ' hidden'; ?>>
		<div class="gdpr-card">

			<div class="gdpr-option-row gdpr-action-row" id="gdpr-self-test">
				<div class="gdpr-option-main">
					<span class="gdpr-option-label"><?php esc_html_e( 'Self-test', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></span>
					<p class="gdpr-option-short"><?php esc_html_e( 'Runs the whole invisible check against your own site and answers in one sentence.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></p>
				</div>
				<div class="gdpr-option-control">
					<button type="button" class="button button-secondary" id="gdpr-self-test-btn"
						data-nonce="<?php echo esc_attr( wp_create_nonce( self::AJAX_SELF_TEST ) ); ?>"
						data-running="<?php esc_attr_e( 'Testing…', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>"
						data-failed="<?php esc_attr_e( 'The test itself could not be run. Reload the page and try again.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>"
							data-verdict-ok="<?php esc_attr_e( 'Everything works', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>"
							data-verdict-problem="<?php esc_attr_e( 'Something is wrong', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>">
						<?php esc_html_e( 'Run self-test', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					</button>
					<button type="button" class="gdpr-help-toggle" aria-expanded="false" aria-controls="help_gdpr_self_test">?</button>
					<div class="gdpr-help-popover" id="help_gdpr_self_test" hidden>
						<?php esc_html_e( 'Fetches a puzzle from this site, solves it and hands it back in — exactly the handshake a visitor\'s browser performs. It says whether that works and, if not, what to do about it. This is the first thing to run when submissions are being flagged as spam.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					</div>
				</div>
				<div class="gdpr-action-result" id="gdpr-self-test-result" hidden></div>
			</div>

			<div class="gdpr-option-row gdpr-action-row" data-diag-task="reset_fp">
				<div class="gdpr-option-main">
					<span class="gdpr-option-label"><?php esc_html_e( 'Address measurement', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></span>
					<p class="gdpr-option-short"><?php esc_html_e( 'How often a solved puzzle came back from a different address than it was handed to — the sign of a cache or proxy in front of your site.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></p>
				</div>
				<div class="gdpr-option-control">
					<span class="gdpr-action-value" data-diag-value="fp">
						<?php
						echo esc_html(
							$fp_share['total'] > 0
								/* translators: 1: percentage from another address, 2: number of measured puzzles */
								? sprintf( __( '%1$d%% of %2$d measured', 'gdpr-compliant-recaptcha-for-all-forms' ), $fp_share['percent'], $fp_share['total'] )
								: __( 'nothing measured yet', 'gdpr-compliant-recaptcha-for-all-forms' )
						);
						?>
					</span>
					<button type="button" class="button button-secondary" data-diag-run="reset_fp"
						data-nonce="<?php echo esc_attr( $diag_nonce ); ?>"
						<?php disabled( 0, $fp_share['total'] ); ?>>
						<?php esc_html_e( 'Reset', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					</button>
					<button type="button" class="gdpr-help-toggle" aria-expanded="false" aria-controls="help_gdpr_reset_fp">?</button>
					<div class="gdpr-help-popover" id="help_gdpr_reset_fp" hidden>
						<?php esc_html_e( 'Each puzzle is handed to one visitor and solved a moment later. This measures how often the solution comes back from a different IP address than the puzzle went to. Submissions are accepted either way — a high share simply means a cache or proxy sits in front of your site, or the visitor\'s address changes between requests. If it is high, check the "Trusted proxies" setting. Resetting starts a fresh measurement, e.g. after changing that setting.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					</div>
				</div>
				<div class="gdpr-action-result" hidden></div>
			</div>

			<div class="gdpr-option-row gdpr-action-row" data-diag-task="reset_echo">
				<div class="gdpr-option-main">
					<span class="gdpr-option-label"><?php esc_html_e( 'Repeat-sender lock', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></span>
					<p class="gdpr-option-short"><?php esc_html_e( 'Values from recent spam, briefly remembered as one-way hashes so the same sender is caught again on any form.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></p>
				</div>
				<div class="gdpr-option-control">
					<span class="gdpr-action-value" data-diag-value="echo">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %d: number of values currently held in the repeat-sender lock */
								_n( '%d value held', '%d values held', $echo_count, 'gdpr-compliant-recaptcha-for-all-forms' ),
								$echo_count
							)
						);
						?>
					</span>
					<button type="button" class="button button-secondary" data-diag-run="reset_echo"
						data-nonce="<?php echo esc_attr( $diag_nonce ); ?>"
						data-confirm="<?php esc_attr_e( 'Release all held values?', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>"
						data-confirm-yes="<?php esc_attr_e( 'Release', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>"
						data-confirm-no="<?php esc_attr_e( 'Cancel', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>"
						<?php disabled( 0, $echo_count ); ?>>
						<?php esc_html_e( 'Release', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					</button>
					<button type="button" class="gdpr-help-toggle" aria-expanded="false" aria-controls="help_gdpr_reset_echo">?</button>
					<div class="gdpr-help-popover" id="help_gdpr_reset_echo" hidden>
						<?php esc_html_e( 'The repeat-sender lock briefly remembers values from spam submissions (as one-way hashes) so the same sender is caught again on any form. Releasing frees every value it currently holds at once — use it if a legitimate sender got caught. No data is lost, and the lock rebuilds itself as new spam arrives.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					</div>
				</div>
				<div class="gdpr-action-result" hidden></div>
			</div>

		</div>
	</section>
		<?php
	}

	/**
	 * Run one of the two diagnostic resets and answer with the FRESH value, so the row
	 * can update itself — the changed number is the success feedback, no toast needed.
	 *
	 * Admin-only and nonce-guarded, like the self-test: one of these clears a spam
	 * defence, which is nothing a stranger who knows an action name may trigger.
	 *
	 * @return void
	 */
	public function diag_task_callback() {
		$nonce = isset( $_POST['security_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['security_nonce'] ) ) : '';
		$task  = isset( $_POST['task'] ) ? sanitize_key( wp_unslash( $_POST['task'] ) ) : '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $nonce, self::AJAX_DIAG_TASK ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		if ( 'reset_fp' === $task ) {
			delete_option( Option::POW_FP_MATCHED_TOTAL );
			delete_option( Option::POW_FP_MISMATCHED_TOTAL );
			delete_option( Option::POW_FP_LAST_MISMATCH_AT );

			wp_send_json_success(
				array(
					'value'   => __( 'nothing measured yet', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'message' => __( 'Measurement restarted.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'empty'   => true,
				)
			);
		}

		if ( 'reset_echo' === $task ) {
			Echo_Store::clear();

			wp_send_json_success(
				array(
					'value'   => sprintf(
						/* translators: %d: number of values currently held in the repeat-sender lock */
						_n( '%d value held', '%d values held', 0, 'gdpr-compliant-recaptcha-for-all-forms' ),
						0
					),
					'message' => __( 'All held values released.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'empty'   => true,
				)
			);
		}

		wp_send_json_error( array( 'message' => __( 'Unknown task.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
	}
}
