<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Default_Routes: der REST-Routen-Seed — welche Routen eine frische
 * Installation ueberwacht (get_default_rest_routes()). Seed-Liste und Produkt-Zaehlung:
 * handbuch/gate.md.
 *
 * SCHNITTLINIE (Welle 3, PLAN-DATEIGROESSE.md): Settings_Menu war eine Datei mit
 * 2592 Zeilen. Sie ist entlang ihrer Sektionen aufgeteilt:
 *   - class-settings-menu.php             — Konstruktion, Hooks, Menue, Selbsttest,
 *                                           prepare_options() und der Proxy-Vorschlag.
 *   - trait-settings-default-actions.php  — get_default_ajax_actions() (handbuch/gate.md).
 *   - trait-settings-default-patterns.php — get_default_recognition_patterns() (handbuch/gate.md).
 *   - trait-settings-default-routes.php   — get_default_rest_routes() (handbuch/gate.md).
 *   - trait-settings-options.php          — Options-Matrix, Teil 1 (Reiter "Most relevant",
 *                                           "Spam Processing").
 *   - trait-settings-options-storage.php  — Options-Matrix, Teil 2 (Reiter "Saving Messages",
 *                                           "Scope", "WordPress Administration", "Algorithm",
 *                                           "AI & Agents").
 *   - trait-settings-status.php           — Status-Leiste und die Proxy-Hinweise darunter.
 *   - trait-settings-save.php             — update_settings(), die Persistenz samt Save-Guards.
 *   - trait-settings-page.php             — das Rendern der Seite (Tabs, Karten, Diagnose).
 *
 * WEITERER SCHNITT (PLAN-BUILDER-SEED.md Phase 3, 2026-08-19): der Welle-3-Eintrag
 * trait-settings-defaults.php buendelte alle drei get_default_*()-Seeds in einer Datei
 * (373 Zeilen) — zu wenig Platz fuer die geplanten Builder-Seeding-Wellen (8-12 neue
 * Eintraege je Welle, mehrere Wellen geplant), also ist er entlang seiner drei Getter
 * weiter aufgeteilt in trait-settings-default-actions.php /
 * trait-settings-default-patterns.php / trait-settings-default-routes.php (DIESE Datei).
 *
 * DREI TRAITS DIREKT, KEIN SAMMEL-TRAIT: Settings_Menu bindet alle drei (und die uebrigen
 * fuenf Sektionen) direkt per `use` ein, statt ueber einen vierten Trait, der die drei
 * seinerseits `use`t. Ein Sammel-Trait waere dieselbe Kompilierzeit-Kopie mit einer
 * zusaetzlichen Indirektionsstufe, die man beim Lesen erst aufloesen muesste, ohne dass
 * dafuer irgendein Aufrufer, Hook oder eine Sichtbarkeit gewinnt — Settings_Menu bindet
 * mit dieser Aenderung acht statt sechs Traits direkt ein, kein Bruch mit dem Bestand.
 *
 * Traits statt zweiter Klassen, und zwar bewusst: diese Methoden sind als
 * `array( $this, ... )`-Hooks registriert, lesen `$this->options`/`$this->plugin_name`
 * und die request-scoped `$pending_*`-Felder, und mehrere Quelltext-Pins in tests/unit
 * haengen an genau dieser Bindung. Ein Trait wird zur Kompilierzeit in die Klasse
 * kopiert — die Aufteilung ist damit ein Umzug, kein Umbau, und kein Aufrufer,
 * kein Hook und keine Sichtbarkeit aendert sich.
 */
trait Settings_Default_Routes {
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

		// *** MetForm (PLAN-BUILDER-SEED.md Welle 2, ERHEBUNG-BUILDER.md §4.1). Submits
		// over its own REST namespace, no admin-ajax SUBMIT path. Verified against the
		// current wp.org zip (metform 4.2.0, main file metform/metform.php):
		// MetForm\Base\Api::init() (base/api.php:24-30) registers, on `rest_api_init`,
		// `register_rest_route( untrailingslashit( 'metform/v1/' . $this->prefix ),
		// '/(?P<action>\w+)/' . ltrim( $this->param, '/' ), [ 'permission_callback' =>
		// '__return_true' ] )` — anonymous. MetForm\Core\Entries\Api (core/entries/api.php:
		// 13-17) sets `$this->prefix = 'entries'`, `$this->param = '/(?P<id>\w+)'`, so the
		// full route is `metform/v1/entries/{action}/{id}`; dispatch is by method+action
		// name (`Base\Api::action()`, base/api.php:33-43: `strtolower(method) . '_' .
		// action`), and `post_insert()` (core/entries/api.php:19) is the actual submission
		// handler. The client confirms the exact segment: utils/util.php:530 renders every
		// form wrapper with `data-action="<rest_url>metform/v1/entries/insert/<form_id>"`
		// (the only occurrence of "entries/insert" in the whole zip), and
		// public/assets/js/app.js constructs `new FormData` from that same wrapper before
		// posting to it — FormData, matching the table this wave was handed.
		// Seeded as `metform/v1/entries/insert/*` (namespace-suffix wildcard covering the
		// numeric form id), NOT a bare `metform/v1/entries/*`: MetForm\Core\Entries\Api
		// also answers `get_export`, `get_get_response_list`, `get_paypal`, `get_stripe`,
		// `get_store_mailchimp_list`, `get_store_mailerlite_groups` and more under the SAME
		// `entries` prefix (core/entries/api.php), every one of them gated by
		// `current_user_can( 'manage_options' )` and reachable from MetForm's own admin
		// screens — a wildcard would put those admin-only endpoints behind this plugin's
		// spam gate too. Fixing the action segment to the literal `insert` keeps the seed
		// off all of them, and `Stamp::check_rest_routes()` filters to `REQUEST_METHOD ===
		// 'POST'` before any route comparison runs at all (class-stamp.php), so even a
		// same-path GET/DELETE admin call — none exists here, checked — could never reach
		// this gate regardless. MetForm\Core\Forms\Api (core/forms/api.php) is a wholly
		// separate `metform/v1/forms/*` namespace (admin form settings/builder, all
		// `manage_options`-gated) and shares no segment with `entries/insert`, so it is
		// unaffected either way. MetForm itself is NOT registered anywhere else in this
		// plugin (ERHEBUNG-BUILDER.md §1) — it has stood in the readme's "Works with" list
		// for years without a matching seed; this entry closes that gap, it opens none.
		if ( array_key_exists( 'metform/metform.php', $installed_plugins ) ) {
			$routes[] = 'metform/v1/entries/insert/*';
			self::display_admin_notice( __( 'MetForm detected – added REST route: metform/v1/entries/insert/*', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** UserFeedback (PLAN-BUILDER-SEED.md Welle 2, ERHEBUNG-BUILDER.md §4.1). Submits
		// over its own REST namespace with a JSON body — the one entry in this wave whose
		// body shape is the one AP3's token injection once regressed on (the Spectra
		// defect, HANDBUCH.md §12), so the injection path was re-checked by hand rather than
		// assumed. Verified against the current wp.org zip (slug `userfeedback-lite`,
		// version 1.11.3 — the free plugin is named "UserFeedback Lite", main file
		// userfeedback-lite/userfeedback.php, NOT the naively-guessed
		// `userfeedback/userfeedback.php`, the same class of slug mistake ISSUES.md
		// documents for Everest/WS Forms). UserFeedback_Frontend::register_frontend_routes()
		// (includes/frontend/class-userfeedback-frontend.php:57-65) registers, on
		// `rest_api_init`, `register_rest_route( 'userfeedback/v1', '/surveys/(?P<id>\w+)
		// /responses', [ 'methods' => 'POST', 'permission_callback' => '__return_true' ] )`
		// — anonymous. Client: assets/vue/js/chunk-common.js bundles an axios-based REST
		// client defaulting to base path `userfeedback/v1/` (`class r{constructor(e=
		// "userfeedback/v1/")…}`) and posts `s.post(\`surveys/${e}/responses\`, t)` with a
		// plain JS object `t` as the body — axios' default `transformRequest` JSON.stringify
		// (`"application/json"` ships in the same bundle's vendor chunk) turns that into a
		// JSON string before XMLHttpRequest ever sees it.
		// JSON-INJECTION CHECK (the point of this comment): by the time that string reaches
		// `XMLHttpRequest.prototype.send( data )`, `recaptcha-gdpr-pow.js`'s override
		// (`addFirstStamp()`'s XHR wrapper) already applies `injectTokenIntoBody( data )` to
		// every non-plugin POST — the branch at `typeof body === 'string'` +
		// `isValidJson( body )` parses it, adds `gdpr_pow_token` to the parsed plain object
		// (guarded against arrays and an already-present token) and re-serializes with
		// `JSON.stringify`, i.e. exactly this shape is hit, not fallen through. Server side,
		// `Stamp::capture_request_data()` (trait-stamp-capture.php) already reads ANY
		// `Content-Type: application/json` body via `php://input` +
		// `Field_Envelopes::decode_body()` regardless of which builder sent it — nothing
		// builder-specific was needed on that side either. Confirmed working, not merely
		// plausible.
		// Seeded with the wildcard in the MIDDLE (`RestRoute::matches()`, single-segment
		// form, not the trailing namespace-suffix form) because the exact same literal path
		// `userfeedback/v1/surveys/{id}/responses` is ALSO registered — twice — for
		// UserFeedback's OWN admin "Results" screen: GET (list responses,
		// includes/admin/class-userfeedback-results.php:61-67) and DELETE (delete
		// responses, class-userfeedback-results.php:127-146), both `permission_callback =>
		// view_results_permission_check`. Neither collides in practice: `check_rest_routes()`
		// (class-stamp.php:502) returns `false` outright unless `$_SERVER['REQUEST_METHOD']
		// === 'POST'`, before the route is even extracted, so the admin's GET/DELETE calls
		// to this identical path never reach the route comparison at all — checked
		// explicitly rather than assumed, this is exactly the class of near-miss
		// (Formidable's `frm_action`, MailPoet's whole API) CLAUDE.md requires checking
		// against the product's own admin views for. The two admin POSTs on this
		// namespace (`/surveys/{id}/responses/trash`, `/surveys/{id}/responses/restore`,
		// class-userfeedback-results.php:85-125) add a 6th path segment and fail the exact
		// 5-segment match regardless of method, so they were never a risk either way.
		if ( array_key_exists( 'userfeedback-lite/userfeedback.php', $installed_plugins ) ) {
			$routes[] = 'userfeedback/v1/surveys/*/responses';
			self::display_admin_notice( __( 'UserFeedback detected – added REST route: userfeedback/v1/surveys/*/responses', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		return implode( "\n", $routes );
	}
}
