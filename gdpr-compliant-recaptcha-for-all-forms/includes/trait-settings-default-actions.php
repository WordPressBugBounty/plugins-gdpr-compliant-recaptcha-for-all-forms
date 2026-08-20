<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Default_Actions: der admin-ajax-Seed — welche Actions eine frische
 * Installation ueberwacht (get_default_ajax_actions()). Seed-Liste und Produkt-Zaehlung:
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
 * weiter aufgeteilt in trait-settings-default-actions.php (DIESE Datei) /
 * trait-settings-default-patterns.php / trait-settings-default-routes.php.
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
trait Settings_Default_Actions {
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

		// *** Jetpack Forms (uses WordPress AJAX). The registered action is
		// `grunion-contact-form` — Jetpack's form module still carries its original
		// Grunion name. Verified against the wp.org zip, Jetpack 16.1.1, BOTH halves:
		// server side `add_action( 'wp_ajax_grunion-contact-form', … )` and
		// `add_action( 'wp_ajax_nopriv_grunion-contact-form', … )` in jetpack_vendor/
		// automattic/jetpack-forms/src/contact-form/class-contact-form-plugin.php:226-227;
		// client side `fetch( admin_ajax_url + '?action=grunion-contact-form',
		// { method: 'POST', body: new FormData( form ) } )` in the same package's
		// dist/modules/form/shared.js and view.js. The action travels in the QUERY
		// STRING, which check_explicit_actions() sees because it reads $_REQUEST, and
		// the FormData body is one of the shapes injectTokenIntoBody() knows
		// (scripts/recaptcha-gdpr-pow.js).
		// Until 2026-08-19 this seeded `jetpack_contact_form_submit`, which the zip
		// contains exactly once — as the FILTER `jetpack_contact_form_submit_button_class`
		// (contact-form.php:1682), never as an ajax action. Jetpack was therefore listed
		// as detected and watched nothing at all (ERHEBUNG-BUILDER.md §3.2), the same
		// failure class as ISSUES.md "Drei Defekte…". The plugin-file gate
		// `jetpack/jetpack.php` was and is correct. ***
		if ( array_key_exists( 'jetpack/jetpack.php', $installed_plugins ) ) {
			$actions[] = 'grunion-contact-form';
			self::display_admin_notice( __( 'Jetpack Forms detected – added action: grunion-contact-form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** WP User Frontend (uses WordPress AJAX). Two independent defects were fixed
		// here on 2026-08-19 (ERHEBUNG-BUILDER.md §3.2), which is why this product moved
		// from get_default_recognition_patterns() into this getter:
		//   1. WRONG SIGNATURE CLASS. The old `{"wpuf_submit":null}` pattern was not a
		//      form field at all — `wpuf_submit` exists in WPUF 4.3.10 only as a CSS
		//      class (includes/functions/user/edit-user.php:200). The real signature is
		//      the ajax action `wpuf_submit_post`: registered in includes/Ajax.php:26 via
		//      register_ajax(), whose default `nopriv => true` (Ajax.php:71-88) produces
		//      `wp_ajax_nopriv_wpuf_submit_post`, and rendered client-side as a plain
		//      `<input type="hidden" name="action" value="wpuf_submit_post">` by all four
		//      form render paths (includes/Frontend_Render_Form.php:60,
		//      includes/class-frontend-render-form.php:163, includes/Render_Form.php:574,
		//      class/render-form.php:718).
		//   2. WRONG GATE PATH. It hung on `wp-user-frontend/wp-user-frontend.php`, which
		//      exists on no installation: WPUF's main file is `wpuf.php` (the
		//      `Plugin Name: WP User Frontend` header sits there). get_plugins() keys are
		//      compared byte-exactly by array_key_exists(), so that gate could never fire
		//      on any host — the same defect as the old `ws-forms/ws-forms.php`. ***
		if ( array_key_exists( 'wp-user-frontend/wpuf.php', $installed_plugins ) ) {
			$actions[] = 'wpuf_submit_post';
			self::display_admin_notice( __( 'WP User Frontend detected – added action: wpuf_submit_post', 'gdpr-compliant-recaptcha-for-all-forms' ) );
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

		// *** Formidable Forms, AJAX submit mode (uses WordPress AJAX). The SECOND of
		// Formidable's two entries — the field pattern in
		// get_default_recognition_patterns() covers the DEFAULT, classic-POST submit,
		// and is structurally blind here: an admin-ajax request reaches the ajax branch
		// of Stamp::__construct(), which matches over the action list ONLY
		// (handbuch/gate.md, "Welcher Zweig welche Klasse nutzt"). Measured on a live
		// 6.34 install (2026-08-19): with the pattern seeded but no action, a submission
		// from a form with "Submit this form with AJAX" switched on was not evaluated at
		// all — one checkbox in the form settings would have turned the protection off.
		// Same failure shape as the Newsletter finding in ERHEBUNG-BUILDER.md §4.1.
		//
		// The action value is `frm_entries_create`: js/formidable.js#getFormErrors()
		// posts `jQuery(form).serialize() + '&action=frm_entries_' + <frm_action>` to
		// `frm_js.ajax_url` (= FrmAppHelper::get_ajax_url(), admin-ajax.php), and
		// `frm_action` is the literal `create` from views/frm-entries/new.php, so the
		// value is fixed. Server side it is handled by
		// FrmEntriesAJAXSubmitController::ajax_create(), hooked on `wp_loaded` priority
		// 5 (FrmHooksController.php) rather than on `wp_ajax(_nopriv)_*` — which is why
		// grepping for a `wp_ajax_` registration finds nothing here and why the value
		// was verified against a real submission instead. It is a frontend-only value:
		// no wp-admin screen sends it.
		if ( array_key_exists( 'formidable/formidable.php', $installed_plugins ) ) {
			$actions[] = 'frm_entries_create';
			self::display_admin_notice( __( 'Formidable Forms detected – added action: frm_entries_create', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Elementor Pro Forms (correct action) ***
		if ( array_key_exists( 'elementor-pro/elementor-pro.php', $installed_plugins ) ) {
			$actions[] = 'elementor_pro_forms_send_form';
			self::display_admin_notice( __( 'Elementor Pro Forms detected – added action: elementor_pro_forms_send_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		return implode( "\n", $actions );
	}
}
