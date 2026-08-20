<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Default_Patterns: der Feld-Muster-Seed — welche Formular-Signaturen
 * eine frische Installation ueberwacht (get_default_recognition_patterns()). Seed-Liste
 * und Produkt-Zaehlung: handbuch/gate.md.
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
 * trait-settings-default-patterns.php (DIESE Datei) / trait-settings-default-routes.php.
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
trait Settings_Default_Patterns {
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
		// `_wpcf7` is the ONE real request key, verified against the wp.org zip 6.1.7:
		// read in includes/controller.php:22 (`wpcf7_superglobal_post( '_wpcf7' )`),
		// rendered unconditionally in includes/contact-form.php:711.
		//
		// Six sibling entries stood here until 2026-08-19 and none of them was ever a
		// request key (ERHEBUNG-BUILDER.md §3.1): `wpcf7_submit` is a CAPABILITY
		// (includes/capabilities.php:14) and a `do_action()` hook (contact-form.php:1089),
		// `wpcf7_contact_form` is the POST TYPE (load.php:187) plus a function name, and
		// `wpcf7_file_upload` / `wpcf7_attachment` / `wpcf7_post_submission` /
		// `wpcf7_save_post` occur ZERO times in the whole zip. They are removed, not
		// replaced — CF7 loses no coverage: `_wpcf7` plus the REST route
		// `contact-form-7/v1/contact-forms/*/feedback` in get_default_rest_routes()
		// carry both submission paths.
		if ( array_key_exists( 'contact-form-7/wp-contact-form-7.php', $installed_plugins ) ) {
			$patterns[] = '{"_wpcf7":null}';
			self::display_admin_notice( __( 'Contact Form 7 detected – added recognition pattern: {"_wpcf7":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** WooCommerce ***
		// `add-to-cart` is the ONE real request key of the ten that stood here until
		// 2026-08-19, verified against the wp.org zip 11.0.1: read in
		// includes/class-wc-form-handler.php:914 (`$_REQUEST['add-to-cart']`), rendered
		// by templates/single-product/add-to-cart/simple.php:49, grouped.php:132 and
		// variation-add-to-cart-button.php:35.
		//
		// The nine removed entries could never match (ERHEBUNG-BUILDER.md §3.1):
		// `woocommerce_payment_complete` (class-wc-order.php:186) and
		// `woocommerce_created_customer` (wc-user-functions.php:198) are `do_action()`
		// hooks that fire on the SERVER after processing and can structurally never
		// appear in $_REQUEST; `woocommerce_checkout` is a shortcode name plus a
		// Customizer section id; `woocommerce_order`, `woocommerce_login`,
		// `woocommerce_review` and `woocommerce_comment` occur ZERO times in the zip;
		// `remove-from-cart` and `update-cart` carry the wrong separator.
		//
		// NO REPLACEMENT for `update-cart`, deliberately. The real field IS `update_cart`
		// (class-wc-form-handler.php:702, templates/cart/cart.php:190) — but the cart
		// update is ALREADY hard-wired into Stamp::__construct() and checked more
		// NARROWLY there: class-stamp.php:303-307 requires `update_cart` AND `cart` AND
		// `woocommerce-cart-nonce` together (plus `wc-ajax=checkout` for the checkout).
		// A `{"update_cart":null}` pattern would be redundant AND broader than the
		// existing check, because it lacks those two extra conditions.
		//
		// NO REPLACEMENT for `remove-from-cart` either: the real `remove_item`
		// (class-wc-form-handler.php:718) is a nonce-protected GET link — no free text,
		// no spam vector — and check_existing_patterns() has no REQUEST_METHOD gate, so
		// a pattern on it would only import the GET-side false-block risk.
		//
		// NO REPLACEMENT for `woocommerce_checkout` / `woocommerce_login`: checkout and
		// login are the risk class (payment data, credentials) and stay outside the
		// shipped seed lists by plan (PLAN-BUILDER-SEED.md).
		if ( array_key_exists( 'woocommerce/woocommerce.php', $installed_plugins ) ) {
			$patterns[] = '{"add-to-cart":null}';
			self::display_admin_notice( __( 'WooCommerce detected – added recognition pattern: {"add-to-cart":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Gravity Forms (custom submission method) ***
		// `gform_submit` is rendered unconditionally (form_display.php:1927 and :5130)
		// and read at :5366/:5370. `gform_file_upload`, removed 2026-08-19, was never a
		// POST field: it exists only as the PREFIX of filter names
		// (`gform_file_upload_tmp_dir`, forms_model.php:5968) and as the dynamic nonce
		// ACTION `gform_file_upload_{form}_{field}` (includes/upload.php:317-318). No
		// replacement — `gform_submit` covers every complete submission, file
		// attachments included. Source is the pronamic/gravityforms mirror 3.0.2, a
		// third-party mirror: strong enough to REMOVE a line (fail-safe), never strong
		// enough to add one (ISSUES.md "Drei Defekte…").
		if ( array_key_exists( 'gravityforms/gravityforms.php', $installed_plugins ) ) {
			$patterns[] = '{"gform_submit":null}';
			self::display_admin_notice( __( 'Gravity Forms detected – added recognition pattern: {"gform_submit":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
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
			// The notice must name the line ACTUALLY added above. It said
			// `{"thrive_comments_submit":null}` until 2026-08-19 — a value that occurs
			// nowhere in this plugin, i.e. a wrong answer at exactly the place an operator
			// looks up what is being monitored.
			self::display_admin_notice( __( 'Thrive Comments detected – added recognition pattern: {"comment_content":null,"comment_post_ID":null,"tva_term":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Formidable Forms ***
		// The VALUE `create` carries this entry, not the field name. Formidable renders
		// exactly ONE form view for both halves of the product — classes/views/
		// frm-entries/form.php is included from wp-admin screens as well as from the
		// public page — and the one thing that differs is the value of `frm_action`:
		// classes/views/frm-entries/new.php sets `$form_action = 'create';` literally,
		// one line above the `require` of that view, so EVERY rendered entry form sends
		// `frm_action=create`. It is not derived from a form id, a setting or the
		// request, which makes it identical on every installation (unlike Divi's
		// `et_pb_contactform_submit_0`), and every render path funnels through it:
		// the `[formidable]` shortcode, the Gutenberg block and the widget all reach
		// FrmFormsController::show_form() -> get_form_contents() -> new.php.
		// `item_meta` is AND-ed on top because `item_meta[0]` is rendered
		// unconditionally in the same view: it pins that this is an entry SUBMISSION,
		// and keeps a bare `?frm_action=create` query string from being evaluated
		// (check_existing_patterns() reads $_REQUEST and has no REQUEST_METHOD gate —
		// the measured WooCommerce `add-to-cart` lesson, BACKLOG.md).
		//
		// DO NOT widen this to `{"frm_action":null}`. That candidate was checked and
		// REJECTED (ERHEBUNG-BUILDER.md §3.3) and then MEASURED on a live 6.34 install
		// (2026-08-19): with it seeded, Formidable's global-settings save, style save,
		// XML import and even the forms-list screen all answered with the plugin's
		// 113-byte "classified as spam" page, and the form-settings/builder screens
		// could not even be reached (they are `?frm_action=settings|edit` GETs).
		// wp-admin never receives the PoW script (add_script_to_header() only hangs on
		// wp_enqueue_scripts / login_enqueue_scripts) and POW_BLOCK is on by default,
		// so an operator could not free themselves. Pattern_Matcher::overbroad_lines()
		// would NOT have warned: it only knows WordPress CORE screens, not a third
		// party's backend (ISSUES.md). `form_key` is no better a discriminator — it is
		// in frm-forms/settings-advanced.php as well.
		// The `create` value avoids all of it: the six admin POSTs send `list`,
		// `update`, `update_settings`, `process-form`, `save` and `import_xml`, and the
		// strict comparison in Pattern_Matcher::matches() means none of them matches.
		// Re-measured with THIS line seeded: all six saves succeed, no spam row.
		//
		// THE ONE ADMIN SCREEN IT DOES COST, named rather than hidden: the Style
		// editor's live PREVIEW (page=formidable-styles) embeds a real, standalone,
		// submittable frontend-shaped form (FrmStylesPreviewHelper -> show_form() ->
		// new.php, hence `frm_action=create`). Clicking its Submit button now returns
		// the spam page instead of creating a test entry. Measured, and accepted: it is
		// a preview Formidable itself labels as incomplete, nothing is edited in it, and
		// no setting is lost — the style settings form beside it is a separate <form>
		// with `frm_action=save` and is unaffected. Formidable's OTHER preview
		// (admin-ajax.php?action=frm_forms_preview) is NOT affected: it is DOING_AJAX,
		// so only the action list applies there and `frm_entries_create` does not match
		// `frm_forms_preview` (measured too).
		//
		// The `{"formidable_submit":null}` entry that stood here until 2026-08-19
		// occurred ZERO times in Formidable 6.34 and never matched anything; between
		// then and now Formidable had no signature at all. The AJAX submit mode needs a
		// SECOND entry, in get_default_ajax_actions() — see the comment there.
		if ( array_key_exists( 'formidable/formidable.php', $installed_plugins ) ) {
			$patterns[] = '{"frm_action":"create","item_meta":null}';
			self::display_admin_notice( __( 'Formidable Forms detected – added recognition pattern: {"frm_action":"create","item_meta":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// WP User Frontend has NO seeded pattern, and needs none: it submits through
		// admin-ajax, so its detection lives in get_default_ajax_actions()
		// (`wpuf_submit_post`, gate path `wp-user-frontend/wpuf.php`) — see the comment
		// there for both defects of the `{"wpuf_submit":null}` entry that stood here
		// until 2026-08-19. Same move as WS Form and Otter Blocks, which went the other
		// way, into get_default_rest_routes().

		// Jotform, Typeform and Zoho Forms have NO seeded entry, and they CANNOT get
		// one — this is a constructional limit, not a gap to fill (ERHEBUNG-BUILDER.md
		// §3.1). All three wp.org plugins are pure embeds of a FOREIGN ORIGIN: Jotform
		// renders `<script src="//www.jotform.com/jsform/…">` (embed-form/
		// jotform-wp-embed.php:87, 1.4.0), Typeform is a Gutenberg block with no
		// server-side processing at all (typeform/index.php, 2.9.1), Zoho builds an
		// `<iframe>` on forms.zoho.com (zoho-forms/zohoForms.php:60-80, 4.0.4). None of
		// the three registers a `wp_ajax(_nopriv)_*` hook, an `admin_post` handler or a
		// REST route — no submission ever reaches this WordPress installation, so there
		// is nothing here to evaluate.
		// Their three pattern entries additionally carried gate paths that exist on no
		// installation (`jotform/jotform.php` — the slug is `embed-form`;
		// `typeform/typeform.php` — really `typeform/index.php`;
		// `zoho-forms/zoho-forms.php` — really `zohoForms.php`). Fixing the gate path
		// would be WORSE than removing the entry: it would tell the operator "Zoho Forms
		// detected – added recognition pattern" for a protection that cannot exist.
		// Do not add them back.

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
}
