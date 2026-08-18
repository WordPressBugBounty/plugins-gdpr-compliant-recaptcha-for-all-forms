<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Defaults: die drei mitgelieferten Erkennungs-Seeds — welche
 * admin-ajax-Actions, Feld-Muster und REST-Routen eine frische Installation
 * ueberwacht. Seed-Listen und Produkt-Zaehlung: handbuch/gate.md.
 *
 * SCHNITTLINIE (Welle 3, PLAN-DATEIGROESSE.md): Settings_Menu war eine Datei mit
 * 2592 Zeilen. Sie ist entlang ihrer Sektionen aufgeteilt:
 *   - class-settings-menu.php             — Konstruktion, Hooks, Menue, Selbsttest,
 *                                           prepare_options() und der Proxy-Vorschlag.
 *   - trait-settings-defaults.php         — die drei get_default_*()-Seeds (handbuch/gate.md).
 *   - trait-settings-options.php          — Options-Matrix, Teil 1 (Reiter "Most relevant",
 *                                           "Spam Processing").
 *   - trait-settings-options-storage.php  — Options-Matrix, Teil 2 (Reiter "Saving Messages",
 *                                           "Scope", "WordPress Administration", "Algorithm",
 *                                           "AI & Agents").
 *   - trait-settings-status.php           — Status-Leiste und die Proxy-Hinweise darunter.
 *   - trait-settings-save.php             — update_settings(), die Persistenz samt Save-Guards.
 *   - trait-settings-page.php             — das Rendern der Seite (Tabs, Karten, Diagnose).
 *
 * Traits statt zweiter Klassen, und zwar bewusst: diese Methoden sind als
 * `array( $this, ... )`-Hooks registriert, lesen `$this->options`/`$this->plugin_name`
 * und die request-scoped `$pending_*`-Felder, und mehrere Quelltext-Pins in tests/unit
 * haengen an genau dieser Bindung. Ein Trait wird zur Kompilierzeit in die Klasse
 * kopiert — die Aufteilung ist damit ein Umzug, kein Umbau, und kein Aufrufer,
 * kein Hook und keine Sichtbarkeit aendert sich.
 */
trait Settings_Defaults {
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

		// *** WordPress' OWN comment form — the one entry here that is UNCONDITIONAL,
		// because it ships with WordPress and needs no plugin to be present. Everything
		// else below is gated on a detected product; core comments cannot be.
		//
		// Not a guess: wp-comments-post.php reads $_POST['comment'] and
		// $_POST['comment_post_ID'] (wp-includes/comment.php, wp_handle_comment_submission()),
		// and comment_form() renders both on every theme — the classic <textarea
		// name="comment"> plus the hidden comment_post_ID, and identically in the block
		// theme's comment block. The AND-ed pair is deliberate: `comment` alone is a
		// common field name, the pair is the comment form.
		//
		// Why it took until now: comments reach the NON-AJAX branch (a plain POST to
		// wp-comments-post.php), so only a field pattern can ever see them — and the
		// shipped set had none, which left every default installation's comment form
		// unwatched. Measured on the maintainer's own site 2026-08-17: four link-spam
		// comments in four weeks, none of them ever evaluated, because no configured
		// signature matched. The client half was never the problem — the frontend script
		// stamps EVERY non-GET form on the page (scripts/recaptcha-gdpr-pow.js,
		// updateFormTokenFields()), so the comment form has always carried a token; nothing
		// read it. That asymmetry is exactly why this is a one-line seed and not a feature.
		$patterns[] = '{"comment":null,"comment_post_ID":null}';
		self::display_admin_notice( __( 'WordPress comments are now checked – added recognition pattern: {"comment":null,"comment_post_ID":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );

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
}
