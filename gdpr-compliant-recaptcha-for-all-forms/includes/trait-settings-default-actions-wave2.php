<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Default_Actions_Wave2: die zweite Haelfte des admin-ajax-Seeds
 * (get_default_ajax_actions()), abgespalten von trait-settings-default-actions.php am
 * 2026-08-28 (Welle 3 der Seed-Ausweitung), als jene Datei mit 517 Zeilen keine weitere
 * Welle mehr hielt (Deckel 600, CLAUDE.md "Dateigroessen"). Seed-Liste und
 * Produkt-Zaehlung: handbuch/seeds.md; WELCHER Zweig die Liste ueberhaupt liest:
 * handbuch/gate.md.
 *
 * SCHNITTLINIE: Settings_Default_Actions (trait-settings-default-actions.php) haelt den
 * urspruenglichen Bestand bis einschliesslich YITH WooCommerce Wishlist in
 * wave_1_ajax_actions() und bleibt die einzige Datei mit der OEFFENTLICHEN
 * get_default_ajax_actions(), die beide Haelften zusammenfuehrt
 * (array_merge(wave_1_ajax_actions(), wave_2_ajax_actions())). DIESE Datei traegt Welle 2
 * (wpDiscuz, Kadence Blocks, Essential Blocks, Popup Maker, MailPoet) und Welle 3
 * (Newsletter, CoBlocks, Popup Builder) in wave_2_ajax_actions() — ein Umzug, kein Umbau:
 * kein Aufrufer, kein Hook und keine Sichtbarkeit aendert sich, und jeder Kommentar
 * unten ist wortgleich zum Stand vor dem Schnitt, ausser wo er einen neuen Eintrag
 * dieser Welle ankuendigt.
 *
 * DREI TRAITS DIREKT, KEIN SAMMEL-TRAIT — Begruendung: trait-settings-default-actions.php.
 *
 * Traits statt zweiter Klassen, und zwar bewusst: diese Methode liest keinen
 * Instanzzustand, aber `self::display_admin_notice()` ist eine Methode von Settings_Menu
 * selbst, und mehrere Quelltext-Pins in tests/unit haengen an genau dieser Bindung (die
 * Datei wird per `file_get_contents()` gelesen, nicht per Reflection instanziiert). Ein
 * Trait wird zur Kompilierzeit in die Klasse kopiert — Settings_Menu bindet mit dieser
 * Datei neun statt acht Traits direkt ein, kein Bruch mit dem Bestand.
 */
trait Settings_Default_Actions_Wave2 {
	/**
	 * Welle 2 (2026-08-26, ERHEBUNG-BUILDER.md §4.1: wpDiscuz, Kadence Blocks, Essential
	 * Blocks, Popup Maker) plus MailPoet (2026-08-28, Owner-Frage 2 aus §6) plus Welle 3
	 * der Seed-Ausweitung (2026-08-28: Newsletter, CoBlocks, Popup Builder). Aufgerufen
	 * ausschliesslich aus Settings_Default_Actions::get_default_ajax_actions().
	 *
	 * @param array<string, mixed> $installed_plugins get_plugins() — file => header data.
	 * @return string[] Action lines, unindexed.
	 */
	private static function wave_2_ajax_actions( array $installed_plugins ): array {
		$actions = array();

		// *** wpDiscuz (uses WordPress AJAX). Welle 2 of PLAN-BUILDER-SEED.md Phase 3,
		// candidate from ERHEBUNG-BUILDER.md §4.1. TWO actions, because wpDiscuz has two
		// separate comment forms and neither shares the other's action: the regular
		// comment form and the inline ("feedback") comment form.
		//
		// Verified against the wp.org zip, wpDiscuz 7.6.65, BOTH halves for BOTH values:
		//   server: class.WpdiscuzCore.php:139-140 registers `wp_ajax_wpdAddComment` AND
		//           `wp_ajax_nopriv_wpdAddComment`; :179-180 the same pair for
		//           `wpdAddInlineComment`.
		//   client: assets/js/wpdiscuz.js:601 `data.append('action', 'wpdAddComment')` on
		//           a `new FormData()`, and :2530 the same for `wpdAddInlineComment` —
		//           both posted through getAjaxObj() (:2867) with `contentType: false`,
		//           i.e. a FormData body, one of the shapes injectTokenIntoBody()
		//           understands (scripts/recaptcha-gdpr-pow.js).
		//
		// THE PLUGIN FILE IS NOT NAMED AFTER THE SLUG. wpDiscuz ships its header in
		// `wpdiscuz/class.WpdiscuzCore.php`, not `wpdiscuz/wpdiscuz.php`. get_plugins()
		// keys are compared byte-exactly, so the guessed spelling would have produced the
		// dead gate of the old `wp-user-frontend/wp-user-frontend.php` (see the sibling
		// wave 1 file) — checked against the zip's own `Plugin Name:` header, not derived
		// from the slug.
		//
		// THE SECOND TRANSPORT DOES NOT COST COVERAGE. With "native AJAX" switched off,
		// wpDiscuz posts to its own endpoint `utils/ajax/wpdiscuz-ajax.php` instead of
		// admin-ajax.php — but that file `define("DOING_AJAX", true)` BEFORE its
		// `require_once wp-load.php` (:4/:10), so our constructor still takes the ajax
		// branch and still matches over the action list. Both transports carry the same
		// `action` value; one entry covers both.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND (CLAUDE.md, four-point duty (d)):
		// neither name occurs anywhere under the settings pages (`options/`). Every
		// remaining occurrence in the zip is a comparison of the REQUEST's action against
		// the literal (forms/wpDiscuzForm.php:81, forms/wpdFormAttr/Field/Field.php:217)
		// or the dispatch table of the custom endpoint (utils/ajax/wpdiscuz-ajax.php:27,
		// :35). SECOND READING (the field-name one, since 2026-08-26): no form field,
		// hidden input or ajax payload key of that name exists in the zip — both values
		// travel as the `action` value only.
		if ( array_key_exists( 'wpdiscuz/class.WpdiscuzCore.php', $installed_plugins ) ) {
			$actions[] = 'wpdAddComment';
			$actions[] = 'wpdAddInlineComment';
			self::display_admin_notice( __( 'wpDiscuz detected – added actions: wpdAddComment, wpdAddInlineComment', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Kadence Blocks (uses WordPress AJAX). TWO actions for the same reason as
		// wpDiscuz: Kadence ships two independent form blocks with two handlers — the
		// classic "Form" block and the newer "Advanced Form" (its own post type).
		//
		// Verified against the wp.org zip, Kadence Blocks 3.7.9.1, BOTH halves:
		//   server: includes/form-ajax.php:35-36 registers `wp_ajax_kb_process_ajax_submit`
		//           AND `wp_ajax_nopriv_kb_process_ajax_submit`;
		//           includes/advanced-form/advanced-form-ajax.php:46-47 the same pair for
		//           `kb_process_advanced_form_submit`.
		//   client: neither value is typed in the frontend scripts — BOTH ride in a hidden
		//           field of the rendered form. `<input type="hidden" name="action"
		//           value="kb_process_ajax_submit">` comes out of the block's save()
		//           (dist/blocks-form.js, current shape plus every deprecation), and
		//           includes/blocks/class-kadence-blocks-advanced-form-block.php:423
		//           renders the advanced form's equivalent server-side. The transports
		//           differ and both are known shapes: kb-form.min.js posts
		//           `form.serialize()` (an urlencoded STRING) via `$.post(…ajaxurl…)`,
		//           kb-advanced-form-block.min.js posts `new FormData(form)` via
		//           `fetch(kb_adv_form_params.ajaxurl, …)`.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND (CLAUDE.md, four-point duty (d)):
		// the whole zip contains no further occurrence of either value beyond the four
		// registration lines, the two rendered hidden fields and one internal
		// `wp_handle_upload()` argument (advanced-form-ajax.php:390) — nothing an admin
		// screen sends. The advanced form is edited in wp-admin, but it saves through the
		// block editor's REST route, not through its own submit action. SECOND READING:
		// no field of either name exists; both are `action` VALUES only.
		if ( array_key_exists( 'kadence-blocks/kadence-blocks.php', $installed_plugins ) ) {
			$actions[] = 'kb_process_ajax_submit';
			$actions[] = 'kb_process_advanced_form_submit';
			self::display_admin_notice( __( 'Kadence Blocks detected – added actions: kb_process_ajax_submit, kb_process_advanced_form_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Essential Blocks (uses WordPress AJAX). Verified against the wp.org zip,
		// Essential Blocks 6.4.x — the third component is left off HERE on purpose: this
		// product's version shares OUR major line, and scripts/check-release-state.mjs
		// cannot tell a foreign three-part number from a promise about our own next
		// release (it says so itself, and names Contact Form 7 as the precedent). The
		// exact version verified against is pinned in
		// tests/unit/EssentialBlocksActionSeedTest.php, which that check does not scan.
		// BOTH halves:
		//   server: includes/Integrations/Form.php:12-15 declares `eb_form_submit` with
		//           `'public' => true`, and that flag is what adds the nopriv hook —
		//           includes/Integrations/ThirdPartyIntegration.php:36-39 registers
		//           `wp_ajax_eb_form_submit` always and `wp_ajax_nopriv_eb_form_submit`
		//           only for `public`. The product's two OTHER form actions
		//           (`eb_fetch_form_data`, `eb_save_form_data`) are `public => false`,
		//           i.e. admin-only, and are deliberately NOT seeded.
		//   client: src/blocks/form/src/frontend.js:55 `ajaxData.append("action",
		//           "eb_form_submit")` on a FormData, posted at :117 via
		//           `fetch(EssentialBlocksLocalize.ajax_url, { method: "POST", body:
		//           ajaxData })` (shipped as assets/blocks/form/frontend.js).
		//
		// NOTE ON THE BODY SHAPE, because it decides where the token has to come from:
		// this client does NOT send the form. It builds a BLANK FormData, appends
		// action/form_id/nonce, and puts the field values into a single JSON string under
		// `form_data` (:115). A hidden token input inside the form therefore never
		// arrives as a top-level field — the token gets there only because the fetch
		// wrapper appends `gdpr_pow_token` to the FormData body itself
		// (injectTokenIntoBody(), scripts/recaptcha-gdpr-pow.js). Same class of detail as
		// the Spectra URLSearchParams defect, HANDBUCH.md §12 cause 5.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND (CLAUDE.md, four-point duty (d)):
		// clean. Every other occurrence of the string in the zip is longer than the value
		// and therefore no match at all — the filters `eb_form_submit_btn_attr` /
		// `…_btn_classes` (includes/Blocks/Form.php:114/:119), the hooks
		// `eb_form_submit_before_email` / `…_after_email`, and the CSS class
		// `eb_form_submit_response` in the editor assets. SECOND READING: no field named
		// `eb_form_submit` exists anywhere.
		if ( array_key_exists( 'essential-blocks/essential-blocks.php', $installed_plugins ) ) {
			$actions[] = 'eb_form_submit';
			self::display_admin_notice( __( 'Essential Blocks detected – added action: eb_form_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Popup Maker (uses WordPress AJAX). Its subscription form — the one form the
		// plugin ships itself, shortcode `[pum_sub_form]` — is the target here.
		//
		// Verified against the wp.org zip, Popup Maker 1.24.0, BOTH halves:
		//   server: classes/Newsletters.php:58-59 registers `wp_ajax_pum_sub_form` AND
		//           `wp_ajax_nopriv_pum_sub_form`.
		//   client: dist/assets/site.js — `$.ajax({ type: "POST", url: pum_vars.ajaxurl,
		//           data: { action: "pum_sub_form", values: n } })` where `n` is
		//           `form.pumSerializeObject()`. The body is urlencoded and NESTED: the
		//           form's own fields arrive as `values[…]`, and the handler reads
		//           exactly that (`$_REQUEST['values']`, Newsletters.php:74). The token
		//           is unaffected — it is appended to the urlencoded string as a
		//           top-level `gdpr_pow_token` (injectTokenIntoBody()); jQuery percent-
		//           encodes the brackets of `values[…]`, so that body still matches the
		//           urlencoded branch there.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND (CLAUDE.md, four-point duty (d)):
		// the value is heavily present in wp-admin, and none of it is a request. It is
		// the SHORTCODE name (classes/Shortcode/Subscribe.php:34, and the content scans
		// in Site/Assets.php:139 and includes/functions/popups/migrations.php:56), a CSS
		// class on the rendered form (Subscribe.php:513), a family of filter/hook names
		// (`pum_sub_form_shortcode_fields`, `pum_sub_form_validation`, …), two cookie
		// event keys (classes/Cookies.php:121/:124) and a set of DOM ids in the shortcode
		// editor (`#pum-shortcode-editor-pum_sub_form`, dist/assets/admin-shortcode-ui.js).
		// The plugin's ELEVEN admin-ajax actions are all separate names (`pum_do_shortcode`,
		// `pum_object_search`, `pum_save_enabled_state`, …); the shortcode preview sends
		// `action=pum_do_shortcode` and carries the `[pum_sub_form …]` text as a VALUE of
		// its `shortcode` field, which matches neither reading. SECOND READING: no field
		// named `pum_sub_form` exists in the zip — a CSS class is not a request key (that
		// confusion is exactly what the old `{"wpuf_submit":null}` pattern was, see the
		// sibling wave 1 file).
		if ( array_key_exists( 'popup-maker/popup-maker.php', $installed_plugins ) ) {
			$actions[] = 'pum_sub_form';
			self::display_admin_notice( __( 'Popup Maker detected – added action: pum_sub_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** MailPoet — the ONE half of it that can be seeded (2026-08-28, Owner-Frage 2
		// aus ERHEBUNG-BUILDER.md §6). This is the only entry in this list that is NOT a
		// `wp_ajax_*` action: `mailpoet_subscription_form` is an `admin_post_*` action, so it
		// arrives over admin-post.php and is matched in the NON-ajax branch of the triage
		// (admin-post.php is not a wp-admin SCREEN — Overbroad_Pattern_Guard::
		// NON_SCREEN_ENDPOINTS — so the screen exemption does not swallow it). The list is
		// read in both branches, which is why it belongs here and not in a new getter.
		//
		// Verified against the wp.org zip, MailPoet 5.36.1, BOTH halves:
		//   server: lib/Config/Hooks.php:307-314 registers `admin_post_mailpoet_subscription_form`
		//           AND `admin_post_nopriv_mailpoet_subscription_form` onto
		//           Subscription\Form::onSubmit(), which itself refuses anything whose
		//           `action` is not exactly this value (lib/Subscription/Form.php:60).
		//   client: views/form/front_end_form.html:38 — EVERY rendered front-end form carries
		//           `method="post" action="…admin-post.php?action=mailpoet_subscription_form"`,
		//           plus the same URL in lib/Captcha/CaptchaFormRenderer.php:112 for the
		//           captcha step. The body is flat (`data[form_id]`, `token`, `api_version`,
		//           `endpoint=subscribers`, `mailpoet_method=subscribe` and the visible fields).
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND (CLAUDE.md, four-point duty (d)): the
		// string occurs six times in the whole zip — the two registrations, the guard in
		// Form.php, the two front-end renderers and the compiled Twig of the same template.
		// It appears in no admin view and in no admin JS bundle. SECOND READING (a listed
		// line also matches as a top-level FIELD NAME, trait-stamp-triage.php:230): no field of that
		// name exists anywhere in the zip.
		//
		// WHY NOT `mailpoet`, the obvious candidate: that value is the name of the plugin's
		// ENTIRE JSON API (lib/API/JSON/API.php:86-97, `wp_ajax_mailpoet` +
		// `wp_ajax_nopriv_mailpoet`), which the wp-admin screens and the form editor use for
		// every call they make. Seeding it would have answered the administrator's own
		// backend with the spam page, and wp-admin gets no PoW script, so there would have
		// been no way back in. That is ERHEBUNG-BUILDER.md §4.2, and it stands.
		//
		// THE SECOND HALF, THE JAVASCRIPT PATH — a RULE line, seeded 2026-08-28 after the
		// mechanism for it shipped the same day (`Action_Rules`, handbuch/matchers.md, "Die
		// Regelzeilen der Action-Liste"). Until then this was the documented gap: with
		// JavaScript the same form goes over admin-ajax as `action=mailpoet`, and that is
		// the name of the WHOLE JSON API (see the paragraph above), so no plain line could
		// express it. A rule line can, because it pins VALUES:
		//
		//   {"action":"mailpoet","endpoint":"subscribers","method":"subscribe"}
		//
		// Verified against the wp.org zip, MailPoet 5.36.1, BOTH halves:
		//   client: assets/dist/js/public.js (one minified line, the module the enqueued
		//           public.min.js is built from — AssetsController::setupFrontEndDependencies()
		//           enqueues `public.min.js`, byte-identical in the values below).
		//           submitSubscribeForm() calls `MailPoet.Ajax.post({ url:
		//           window.MailPoetForm.ajax_url, endpoint: "subscribers", action:
		//           "subscribe", data: … })`, and MailPoet.Ajax.getParams() turns that into
		//           the WIRE fields `{ action: "mailpoet", api_version, token, endpoint,
		//           method: <the caller's `action`>, data }`. Note the rename: the caller's
		//           `action` becomes the wire's `method`. request() then hands that object
		//           to jQuery `$.post({ data: params })` — DEFAULT jQuery serialisation, so
		//           the body is `application/x-www-form-urlencoded` and `action`, `endpoint`
		//           and `method` sit TOP-LEVEL (only the payload nests, as `data[…]`).
		//           No JSON body is involved, so Pattern_Matcher::matches() sees all three
		//           as plain top-level fields of $_REQUEST.
		//   server: lib/API/JSON/API.php:86-97 registers `wp_ajax_mailpoet` +
		//           `wp_ajax_nopriv_mailpoet`; :144-149 reads `endpoint` and `method`
		//           (`mailpoet_method` is an accepted alias, used by the no-JS form above);
		//           lib/API/JSON/v1/Subscribers.php:29-31 declares `subscribe` as the ONE
		//           method of that endpoint with NO_ACCESS_RESTRICTION, every other one
		//           requires `manage_subscribers`. The pinned pair is, by the product's own
		//           permission table, the visitor call and nothing else.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND (CLAUDE.md, four-point duty (d)) — this
		// is the whole reason the line pins values instead of the name: `method=subscribe`
		// occurs in NO admin bundle. Counted over every file under assets/: the wire value
		// is produced by `action:"subscribe"` in a MailPoet.Ajax call, and that literal
		// exists only in public.js / public.min.js — never in admin.js, commons.js,
		// settings.js, form_editor.js, newsletter_editor.js, automation*.js, tags.js,
		// custom_fields.js or the email-editor bundles. `endpoint:"subscribers"` does occur
		// once in admin.js (the "Add/Edit subscriber" screen), but that screen is the
		// generic admin form component, which sends `method=get` / `method=save`; the AND
		// is therefore never satisfied there. In PHP/views the string `subscribe` appears as
		// a `method` value only through the alias field `mailpoet_method` (views/form/
		// front_end_form.html:52, lib/Captcha/CaptchaFormRenderer.php:108) — both front-end
		// renderers, and a different key, so they do not match this line either.
		// The one wp-admin place that renders a real front-end form is the form-editor
		// PREVIEW, and it never submits at all: public.js returns early on
		// `formDiv.data("is-preview")`.
		//
		// SECOND READING (a listed line also matches as a top-level FIELD NAME,
		// trait-stamp-triage.php): does not apply — for a `{`-line check_explicit_actions()
		// consults Action_Rules only and skips both older readings.
		//
		// Also NOT seeded: `mailpoet_subscription_update`, the "manage subscription" form of
		// an existing subscriber (Hooks.php:297-304). It is reachable only with a
		// subscriber-specific link, carries no free text worth classifying, and blocking it
		// would hit the same legal duty the Newsletter rejection below describes.
		if ( array_key_exists( 'mailpoet/mailpoet.php', $installed_plugins ) ) {
			$actions[] = 'mailpoet_subscription_form';
			$actions[] = '{"action":"mailpoet","endpoint":"subscribers","method":"subscribe"}';
			self::display_admin_notice( __( 'MailPoet detected – added action: mailpoet_subscription_form (and the JavaScript subscribe call)', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Newsletter (The Newsletter Plugin) — Welle 3 der Seed-Ausweitung
		// (2026-08-28), the answer to the candidate BACKLOG.md carried since Welle 2 —
		// VERENGT in derselben Session nach Abnahme from a plain Klartext action line to
		// the RULE line `{"action":"tnp","nlang":null}` (Action_Rules, shipped the same
		// day, class-action-rules.php). See that class and handbuch/matchers.md, "Die
		// Regelzeilen der Action-Liste", before touching this entry.
		//
		// `tnp` AS A PLAIN, UNQUALIFIED KLARTEXT LINE REMAINS REJECTED FOREVER, and the
		// long analysis below stays verbatim: it is Newsletter's ENTIRE front-controller,
		// not the subscribe endpoint, and on its own it would classify every confirmation
		// and unsubscribe link (GET, tokenless, routed through admin-ajax by the shipped
		// `links=ajax` default) as spam. That analysis is unchanged by what follows.
		//
		// `tnp` AS THE PINNED `action` OF A RULE LINE is a different animal, and it is
		// the one this entry actually uses: Action_Rules::pinned_action() only arms a
		// line that pins `action` to a non-empty string, and Pattern_Matcher::matches()
		// then requires EVERY condition in the line to hold — so
		// `{"action":"tnp","nlang":null}` is a strict SUBSET of the plain `tnp` line,
		// exactly the way MailPoet's `{"action":"mailpoet","endpoint":"subscribers",
		// "method":"subscribe"}` rule narrows the plain value `mailpoet` above. It can
		// only match LESS than plain `tnp` would have, never more — the rejection above
		// still holds for the value alone, and is exactly what the `nlang` condition is
		// there to rule back out.
		//
		// ERHEBUNG-BUILDER.md §4.1 lists `tnp` as accepted for Welle 2; re-verifying it
		// against the zip (Newsletter 9.3.5) turned up a cost the survey did not see.
		//
		// The value itself is real and both halves check out: plugin.php:156-157
		// registers `wp_ajax_tnp` AND `wp_ajax_nopriv_tnp`, and main.js:17 posts
		// `fetch(newsletter_data.action_url + '?action=tnp&na=sa', { method: 'POST', body:
		// new FormData(this) })` for any form carrying the class `tnp-ajax`
		// (`action_url` = admin-ajax.php, plugin.php:401).
		//
		// WHY IT IS STILL WRONG: `action=tnp` is not the subscribe endpoint, it is
		// Newsletter's ENTIRE front-controller. The real operation rides in a SECOND
		// parameter, `na` (plugin.php:198 `$this->action = sanitize_key($_REQUEST['na'])`),
		// and `na` also carries `c` (confirm), `u`/`uc` (unsubscribe), `r`/`rc`
		// (reactivate) and `p` (profile) — the links inside every sent newsletter, built
		// by build_action_url() (includes/module-base.php:982). Those are GET requests
		// clicked out of a mail client, so they carry no PoW token and no page of ours
		// preceded them. And the plugin routes them through admin-ajax BY DEFAULT:
		// get_action_base_url() (module-base.php:963) returns
		// `admin-ajax.php?action=tnp` whenever the main option `links` is non-empty, and
		// its shipped default is `'ajax'` (includes/defaults.php:36; NewsletterModule::
		// get_options() merges defaults under the stored values, includes/module.php:62).
		//
		// Consequence, traced through our own gate: admin-ajax.php defines DOING_AJAX, so
		// triage_request() takes the ajax branch, where check_explicit_actions() would
		// match `tnp` on reading 1 (the plain action value) — with $_POST empty, because
		// the click is a GET. check_submit() then runs classify_missing_proof_of_work()
		// unconditionally, check_request() finds no token and no IP row, and with
		// POW_BLOCK (default on) the request dies in wp_send_json_error(). That is every
		// confirmation link and every unsubscribe link on a default-configured install
		// answering with a JSON error blob: no double opt-in can complete, no subscriber
		// can unsubscribe, and the operator carries the legal duty that the link was
		// there to fulfil. Same shape as the MailPoet rejection in ERHEBUNG-BUILDER.md
		// §4.2, one layer out — it locks out the visitors instead of the administrator.
		//
		// `tnp` ITSELF cannot be narrowed as a PLAIN action value. The action list cannot
		// say "only when `na=s`" the way a PATTERN pins a value
		// (`{"frm_action":"create"}`, see the sibling wave 1 file's Formidable entry), and
		// patterns are not consulted in the ajax branch at all.
		//
		// THE PATTERN HALF WAS WITHDRAWN TOO, and for the same reason one step further.
		// Welle 2 first seeded `{"na":null,"ne":null}` in get_default_recognition_patterns()
		// as the classic-POST half. It was taken back out before shipping, because the
		// `links` option does not only govern the mail links: get_action_base_url() builds
		// the `action` attribute of EVERY subscription form through the same call
		// (subscription/subscription.php:1138, :1699, :1827, :1905 all go through
		// build_action_url()). With the shipped default `links=ajax` the plain, non-ajax
		// form therefore posts to admin-ajax.php as well — ajax branch, patterns never
		// read. The entry would have acted only on installs whose operator switched
		// `links` to "Standard", while its changelog line promised out-of-the-box
		// detection. An entry that looks like protection and is none on a default install
		// is the exact failure class this whole survey exists to end (Everest Forms,
		// WS Forms — ISSUES.md "Drei Defekte…"). `{"na":null,"ne":null}` MUST NEVER be
		// seeded — tests/unit/NewsletterActionSeedTest.php pins that negative.
		//
		// THE ENTRY MADE HERE INSTEAD PINS `nlang` ONTO THE `tnp` VALUE, in one RULE line
		// (Action_Rules, class-action-rules.php): `{"action":"tnp","nlang":null}`. This
		// replaces an earlier, narrower Welle-3 shape that used a SECOND reading of a
		// plain action-list line instead (trait-stamp-triage.php:230:
		// check_explicit_actions() matches a listed line as an action value AND,
		// independently, as a top-level FIELD NAME) — that reading is superseded here by
		// the rule line doing the same narrowing more directly, on the SAME field.
		//
		// THE FIELD IS `nlang`: get_form_hidden_fields() (subscription/subscription.php:1262)
		// renders `<input type="hidden" name="nlang" …>` UNCONDITIONALLY — outside every
		// `if` in that method — and all four form-rendering entry points call it:
		// get_subscription_form_custom() (:1152), get_subscription_form() (:1716),
		// get_form() (:1828) and get_subscription_form_minimal() (:1915). Verified against
		// the 9.3.5 zip: `nlang` occurs ONLY in subscription/subscription.php (also read
		// at :250, :654, :669) and in NO admin view, and the mail links built by
		// build_action_url() carry only `na`/`nk`/`nek` — never `nlang`. That is what
		// separates the two cases where plain `tnp` could not: a subscribe POST always
		// carries `nlang` (even with an empty value on a single-language site — isset()
		// is true for an empty string), a mail-link GET never does — so pinning `nlang`
		// onto `tnp` reproduces exactly the narrowing the field-name reading gave, while
		// staying inside the RULE form the rest of the action list now understands.
		//
		// `ne`, the email field, was considered and REJECTED as a further, AND-ed
		// condition (the shape Formidable's `item_meta` AND-condition uses): it is NOT
		// rendered unconditionally by all four variants. shortcode_newsletter_field()
		// (:1377) only emits it when the `email` field is part of the form's configured
		// field list, and both get_subscription_form_custom() (the `[newsletter]`
		// shortcode wrapping admin-authored shortcode content) and get_form() (an
		// admin-edited HTML block) can omit it entirely — unlike Formidable's
		// `item_meta[0]`, which one single view always renders. `nlang` does not collide
		// with any other seeded product (checked against every existing line in this file
		// and in trait-settings-default-patterns.php) and appears in exactly one file of
		// the whole zip, so `{"action":"tnp","nlang":null}` monitors nothing outside
		// Newsletter's own subscription rendering.
		//
		// TWO TRANSPORTS, TWO ENTRIES — the mirror of Formidable's classic-POST-plus-AJAX
		// split, one file over instead of one file down:
		//   * DEFAULT config (`links=ajax`, includes/defaults.php:36): the RULE line HERE
		//     catches it, because admin-ajax.php defines DOING_AJAX and the ajax branch
		//     consults ONLY the action list, where a rule line now applies.
		//   * `links=Standard` config: the form then posts to the CURRENT PAGE, no
		//     `action` parameter at all (get_action_base_url() returns get_home_url()),
		//     so the request takes the non-ajax branch, where the action list is
		//     structurally blind without an `action` value (the early exit in
		//     check_explicit_actions() requires one). That path needs the field PATTERN
		//     `{"nlang":null,"na":null}` in get_default_recognition_patterns() instead —
		//     see the entry there, trait-settings-default-patterns.php.
		//
		// KNOWN BLIND SPOT, stated here so nobody reads this as full coverage: the
		// minimal WIDGET (widget/minimal.php:34-43) builds its markup by hand — it
		// renders `nr`/`ne`/submit but never calls get_form_hidden_fields(), so it emits
		// no `nlang` and is not covered by either entry. Accepted the same way Popup
		// Maker's shortcode-only coverage is: the widget is one render path among several,
		// not the product's only one.
		if ( array_key_exists( 'newsletter/plugin.php', $installed_plugins ) ) {
			$actions[] = '{"action":"tnp","nlang":null}';
			self::display_admin_notice( __( 'Newsletter detected – added action: {"action":"tnp","nlang":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** CoBlocks, block `coblocks/form` (custom submission method). Verified
		// against the wp.org zip, CoBlocks 3.1.17, BOTH halves:
		//   server: includes/class-coblocks-form.php:816 reads
		//           `filter_input(INPUT_POST, 'action')` and refuses anything that is not
		//           exactly `coblocks-form-submit`; process_form_submission() then sends
		//           the mail.
		//   client: the SAME file renders the form's markup — :788
		//           `<input type="hidden" name="action" value="coblocks-form-submit">`,
		//           unconditionally, right next to the submit button, on a plain
		//           `<form method="post">` posted to the PAGE'S OWN permalink (:179,
		//           `set_url_scheme( get_the_permalink() )`) — no iframe, no foreign
		//           origin, no admin-ajax involved at all.
		//
		// GATE PATH VERIFIED: the plugin header sits in `coblocks/class-coblocks.php`,
		// not `coblocks/coblocks.php`.
		//
		// WHY A PLAIN ACTION-LIST ENTRY STILL WORKS ON A CLASSIC POST: this is not an
		// admin-ajax submission, but check_explicit_actions() reads
		// `$this->whole_request_data['action']` (= $_REQUEST) regardless of transport,
		// and the non-ajax branch of the triage consults the action list exactly like the
		// pattern list — "Pattern ODER Action ODER Route" (handbuch/gate.md, "Welcher
		// Zweig welche Klasse nutzt"). A Klartext line therefore matches this classic POST
		// on reading 1 (the action VALUE) the same way it would on admin-ajax.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND (CLAUDE.md, four-point duty (d)):
		// `coblocks-form-submit` occurs exactly four times in the whole zip — the nonce
		// field, the rendered hidden input, and the two server-side comparisons, all in
		// this one file. Zero hits under `includes/admin/` (crop-settings' two
		// unrelated `wp_ajax_coblocks_crop_settings*` hooks are the only admin-ajax
		// actions this product registers). SECOND READING: no field of that name exists
		// anywhere in the zip — it is an `action` VALUE only.
		if ( array_key_exists( 'coblocks/class-coblocks.php', $installed_plugins ) ) {
			$actions[] = 'coblocks-form-submit';
			self::display_admin_notice( __( 'CoBlocks detected – added action: coblocks-form-submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Popup Builder, the popup's subscription form (uses WordPress AJAX).
		// Verified against the wp.org zip, Popup Builder 4.4.5, BOTH halves:
		//   server: com/classes/Ajax.php:56-57 registers
		//           `wp_ajax_sgpb_subscription_submission` AND
		//           `wp_ajax_nopriv_sgpb_subscription_submission`; subscriptionSubmission()
		//           (:928) writes the entry to the database.
		//   client: public/js/Subscription.js:11 `jQuery.post(SGPB_JS_PARAMS.ajaxUrl,
		//           {action:'sgpb_subscription_submission', nonce:…, formData:…, …})`.
		//
		// GATE PATH VERIFIED: the plugin header sits in `popup-builder/popup-builder.php`.
		//
		// NOT TO BE CONFUSED with `sgpb_process_after_submission` (Ajax.php:53-54), a
		// fire-and-forget hook the SAME client calls immediately AFTER a successful
		// submission (Subscription.js:13) purely to run post-success behaviour — it never
		// writes the entry and is deliberately NOT seeded.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND (CLAUDE.md, four-point duty (d)): this
		// zip ships no dedicated admin directory at all (`com/helpers/AdminHelper.php` is
		// the only "admin"-named file, and it does not mention this action). The whole zip
		// registers 30 `wp_ajax_*` hooks; `sgpb_subscription_submission` occurs exactly
		// three times — the two registrations and the one client call. SECOND READING: no
		// field of that name exists anywhere in the zip.
		if ( array_key_exists( 'popup-builder/popup-builder.php', $installed_plugins ) ) {
			$actions[] = 'sgpb_subscription_submission';
			self::display_admin_notice( __( 'Popup Builder detected – added action: sgpb_subscription_submission', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		return $actions;
	}
}
