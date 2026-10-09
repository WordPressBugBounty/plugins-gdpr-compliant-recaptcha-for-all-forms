<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/seeds.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Default_Actions_Wave3: die dritte Datei des admin-ajax-Seeds, abgespalten
 * am 2026-09-24, als trait-settings-default-actions-wave2.php mit 504 von 600 Zeilen die
 * siebenteilige Welle 4 nicht mehr hielt (Deckel: CLAUDE.md „Dateigroessen").
 *
 * SCHNITTLINIE: Settings_Default_Actions traegt Welle 1 und bleibt die einzige Datei mit
 * der OEFFENTLICHEN get_default_ajax_actions(), die alle Haelften zusammenfuehrt.
 * Settings_Default_Actions_Wave2 traegt Welle 2 und 3. DIESE Datei traegt Welle 4:
 * Hustle, MailerLite, Email Subscribers, Quiz and Survey Master, WP-Polls, Form Maker,
 * Gutena Forms, Happyforms — und seit Welle 5 FormLayer, My Sticky Elements und
 * Cool FormKit, seit Welle 6 (wave_6_ajax_actions()) neun weitere. Grundlage je Eintrag ist ERHEBUNG-BUILDER-2.md (2026-09-24), jede Signatur
 * gegen die echte wp.org-Zip belegt.
 *
 * Trait statt zweiter Klasse, aus demselben Grund wie in Welle 2:
 * `self::display_admin_notice()` ist eine Methode von Settings_Menu selbst, und mehrere
 * Quelltext-Pins in tests/unit haengen an dieser Bindung.
 */
trait Settings_Default_Actions_Wave3 {

	/**
	 * Welle 4 der Seed-Ausweitung (2026-09-24).
	 *
	 * @param array<string,mixed> $installed_plugins Ergebnis von get_plugins().
	 * @return array<int,string> Zeilen fuer die Action-Liste.
	 */
	private static function wave_3_ajax_actions( array $installed_plugins ): array {
		$actions = array();

		// HUSTLE (wordpress-popup, 90.000 Installationen) — Popups, Slide-ins und
		// eingebettete Formulare zur E-Mail-Sammlung.
		//   server: `add_action( 'wp_ajax_nopriv_hustle_module_form_submit', … )`, die
		//           Einsendung jedes Moduls laeuft ueber diesen einen Handler.
		//   client: `assets/js/front.min.js` — das Frontend-Bundle, einziger Ort in der Zip,
		//           an dem der Name ausserhalb der Registrierung vorkommt.
		//
		// GATE PATH VERIFIED: der Plugin-Header sitzt in `wordpress-popup/popover.php` —
		// NICHT in einer Datei namens wie der Slug. Wer hier `wordpress-popup.php` raet,
		// baut ein Gate, das nie zutrifft, und der Eintrag waere wirkungslos.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND (CLAUDE.md, Pflicht (4)): der Name
		// kommt in keiner Admin-Datei der Zip vor. Hustles Backend nutzt eigene
		// `hustle_*`-Actions, keine davon traegt `_form_submit`.
		if ( array_key_exists( 'wordpress-popup/popover.php', $installed_plugins ) ) {
			$actions[] = 'hustle_module_form_submit';
			self::display_admin_notice( __( 'Hustle detected – added action: hustle_module_form_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// MAILERLITE SIGNUP FORMS (official-mailerlite-sign-up-forms, 100.000).
		//   server: `add_action( 'wp_ajax_nopriv_mailerlite_subscribe_form', … )` in
		//           `src/Modules/Form.php`.
		//   client: `src/Views/CustomForm.php` rendert ein verstecktes
		//           `<input name="action" value="mailerlite_subscribe_form">` und sendet
		//           per fetch() urlencoded an admin-ajax.php.
		//
		// BEKANNTE LUECKE, ausdruecklich benannt statt still gelassen: das Produkt hat DREI
		// Formulartypen, und nur einer davon erreicht diese Installation. „Embedded/Popup"
		// und „Iframe" laden von static.mailerlite.com und senden auch dorthin — sie sind
		// konstruktiv unschuetzbar, wie Typeform oder Jotform. Geschuetzt ist allein der
		// Typ „Custom Form". Wer das spaeter nachruesten will, findet hier den Grund,
		// warum es nicht geht.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: der Name kommt in der Zip genau
		// dreimal vor — zwei Hook-Registrierungen und das versteckte Feld. Nichts unter
		// `src/Admin/`.
		if ( array_key_exists( 'official-mailerlite-sign-up-forms/mailerlite.php', $installed_plugins ) ) {
			$actions[] = 'mailerlite_subscribe_form';
			self::display_admin_notice( __( 'MailerLite detected – added action: mailerlite_subscribe_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// EMAIL SUBSCRIBERS & NEWSLETTERS (email-subscribers, 50.000).
		//   server: `add_action( 'wp_ajax_nopriv_es_add_subscriber', … )` — der
		//           Abo-Handler des Frontend-Formulars.
		//   client: `lite/public/js/email-subscribers-public.js` — das oeffentliche
		//           Abo-Skript, einziger Client-Treffer der Zip.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: das Produkt hat ein grosses Backend
		// mit eigenen Ajax-Endpunkten, aber `es_add_subscriber` kommt in keiner
		// Admin-Datei vor. Die drei weiteren `_nopriv`-Hooks der Zip
		// (`ig_es_convert_to_mjml`, `ig_es_run_action_scheduler_task`,
		// `ig_es_trigger_mailing_queue_sending`) sind Hintergrundverarbeitung, kein
		// Besucherformular, und sind bewusst NICHT geseedet.
		if ( array_key_exists( 'email-subscribers/email-subscribers.php', $installed_plugins ) ) {
			$actions[] = 'es_add_subscriber';
			self::display_admin_notice( __( 'Email Subscribers detected – added action: es_add_subscriber', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// QUIZ AND SURVEY MASTER (quiz-master-next, 40.000).
		//   server: `add_action( 'wp_ajax_nopriv_qmn_process_quiz', … )` in
		//           `php/classes/class-qmn-quiz-manager.php`.
		//   client: BEIDE Renderer senden diese Action — `js/qsm-quiz.js` und
		//           `renderer/assets/js/qsm-quiz-navigation.js`, jeweils als FormData.
		//           Dass der alte und der neue Renderer denselben Weg nehmen, ist der
		//           Grund, warum ein Eintrag genuegt.
		//
		// GATE PATH VERIFIED: `quiz-master-next/mlw_quizmaster2.php` — auch hier heisst die
		// Hauptdatei nicht wie der Slug.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: kein Treffer unter `php/admin/`.
		if ( array_key_exists( 'quiz-master-next/mlw_quizmaster2.php', $installed_plugins ) ) {
			$actions[] = 'qmn_process_quiz';
			self::display_admin_notice( __( 'Quiz and Survey Master detected – added action: qmn_process_quiz', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// WP-POLLS (wp-polls, 40.000) — ALS REGELZEILE, NICHT ALS KLARTEXT.
		//
		// Der Action-Wert heisst schlicht `polls`. Seit 2026-08-26 matcht
		// check_explicit_actions() eine gelistete Zeile sowohl als Action-WERT als auch als
		// Top-Level-FELDNAME (handbuch/matchers.md) — eine Klartextzeile `polls` faenge
		// deshalb jeden fremden Request mit einem Feld dieses Namens mit. Die seit 6.1.0
		// moegliche JSON-Regelzeile nagelt den Fall fest: sie armiert nur mit gepinntem
		// `action`-String und ist damit die Verengung derselben Zeile.
		//   server: `add_action( 'wp_ajax_nopriv_polls', … )` in
		//           `includes/class-wp-polls-vote.php`.
		//   client: `js/wp-polls.js` sendet per fetch() `method: 'POST'` mit
		//           URLSearchParams — kein GET. Das zaehlt, seit 6.1.0 GET-Aufrufe gar
		//           nicht mehr bewertet: ein GET-Kandidat waere wertlos.
		//   `poll_id` ist in jeder Stimmabgabe gesetzt und macht den Pin tragfaehig.
		//
		// AM 2026-09-24 IN DER LAUFENDEN INSTANZ GEMESSEN, nicht hergeleitet — drei Faelle,
		// jeder gegen wp-env mit demselben fremden Request
		// (`action=acme_newsletter&polls=2&email=…`):
		//   · Scope traegt die Klartextzeile `polls`  -> GEBLOCKT (Spam-Antwort). Der
		//     Fehlblock ist real, nicht theoretisch.
		//   · dieselbe Zeile, Request OHNE Feld `polls` -> durchgelassen. Es liegt also am
		//     Feldnamen, nicht an etwas anderem.
		//   · Scope traegt die Regelzeile unten       -> durchgelassen.
		// Ebenfalls gemessen: Scope_Sync traegt diese Zeile beim Aktivieren von wp-polls
		// selbsttaetig in den Scope nach, und ein Vote ohne Token wird danach geblockt.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: das Backend sendet `polls-admin`,
		// einen anderen Wert, registriert unter eigenem Hook. Auch ohne den Pin waere es
		// nicht betroffen — der Pin schuetzt gegen FREMDE Requests, nicht gegen dieses
		// Produkt.
		if ( array_key_exists( 'wp-polls/wp-polls.php', $installed_plugins ) ) {
			$actions[] = '{"action":"polls","poll_id":null}';
			self::display_admin_notice( __( 'WP-Polls detected – added rule line for action: polls', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// FORM MAKER BY 10WEB (form-maker, 30.000).
		//   server: `add_action( 'wp_ajax_nopriv_fm_submit_form', … )`.
		//   client: `js/main_div_front_end.js` (`fm_submit()`), FormData per POST.
		//
		// DIESE ZEILE ALLEIN DECKT DIE WERKSEINSTELLUNG NICHT AB. Der Ajax-Modus ist
		// werkseitig AUS (`fm_ajax_submit` Default 0, `form-maker.php:114-115`); der
		// Default-Weg ist ein klassischer POST des Formulars auf sich selbst. Dessen
		// Gate-Feld `save_or_submit<ID>` traegt die Formular-ID im Namen und ist damit
		// kein Muster, das sich schreiben liesse. Deshalb traegt
		// trait-settings-default-patterns.php zusaetzlich `{"fm-current-page":null}` —
		// das Feld rendert jedes Formular unbedingt, in beiden Modi. Wer eine der beiden
		// Zeilen entfernt, halbiert die Abdeckung dieses Produkts.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: der einzige weitere Treffer liegt in
		// `frontend/views/form_maker.php` — Frontend trotz des Wortes „views" im Pfad.
		// Nichts unter `admin/`.
		if ( array_key_exists( 'form-maker/form-maker.php', $installed_plugins ) ) {
			$actions[] = 'fm_submit_form';
			self::display_admin_notice( __( 'Form Maker detected – added action: fm_submit_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// GUTENA FORMS (gutena-forms, 20.000).
		//   server: `add_action( 'wp_ajax_nopriv_gutena_forms_submit', … )`.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: `includes/admin/class-manage-store.php`
		// erscheint im Grep, meint aber `gutena_forms_submitted_data` — einen internen
		// Hook, der NACH dem Speichern feuert und nie ein Request-Feld ist. Der Name
		// unterscheidet sich, die Kollision ist keine. Genau diese Verwechslung ist der
		// Grund, warum die Pflichtpruefung gegen das Backend hier notiert wird und nicht
		// nur abgehakt.
		if ( array_key_exists( 'gutena-forms/gutena-forms.php', $installed_plugins ) ) {
			$actions[] = 'gutena_forms_submit';
			self::display_admin_notice( __( 'Gutena Forms detected – added action: gutena_forms_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// HAPPYFORMS (happyforms, 20.000).
		//   server: kein wp_ajax und keine REST-Route. `parse_request` und `admin_init`
		//           zeigen beide auf `admin_post()`, das auf
		//           `$_REQUEST['action'] === 'happyforms_message'` reagiert
		//           (`inc/classes/class-message-controller.php:58,88-89`). `parse_request`
		//           feuert fuer jeden Request, auch anonym — eine `_nopriv`-Frage stellt
		//           sich hier nicht.
		//   client: `bundles/js/frontend.js` sendet das serialisierte Formular urlencoded;
		//           das versteckte Feld kommt aus `happyforms_action_field()`.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: der Formular-Editor im Customizer
		// nutzt Actions mit Bindestrich (`happyforms-update-form` u. a.). Der exakte Wert
		// `happyforms_message` kommt in der ganzen Zip nur an dieser einen Stelle vor.
		if ( array_key_exists( 'happyforms/happyforms.php', $installed_plugins ) ) {
			$actions[] = 'happyforms_message';
			self::display_admin_notice( __( 'Happyforms detected – added action: happyforms_message', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// ===== WELLE 5 (2026-09-24), Grundlage ERHEBUNG-BUILDER-2.md =====

		// FORMLAYER (formlayer, 100.000 Installationen).
		//   server: `add_action( 'wp_ajax_nopriv_formlayer_submit_form', … )`, main/ajax.php:11-12.
		//   client: `assets/js/frontend.js:58` haengt `action=formlayer_submit_form` an ein
		//           FormData-Objekt.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: der Name kommt in der Zip nur zweimal
		// vor — Handler und die eine Frontend-Zeile. Nichts in main/admin.php, nichts im
		// Admin-JS.
		if ( array_key_exists( 'formlayer/formlayer.php', $installed_plugins ) ) {
			$actions[] = 'formlayer_submit_form';
			self::display_admin_notice( __( 'FormLayer detected – added action: formlayer_submit_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// ALL-IN-ONE STICKY FLOATING CONTACT FORM / MY STICKY ELEMENTS (mystickyelements,
		// 40.000) — das schwebende Kontaktformular am Bildschirmrand.
		//   server: `add_action( 'wp_ajax_nopriv_mystickyelements_contact_form', … )`,
		//           mystickyelements-front.php:15-16.
		//   client: `dist/js/mystickyelements-fronted.js` baut
		//           `action=mystickyelements_contact_form&…serialize()` und postet
		//           urlencoded.
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND — hier war ein Fast-Fehler zu klaeren:
		// die Admin-Vorschau (`admin/sticktelements-preview.php`) rendert Felder mit
		// DENSELBEN IDs (`contact-form-name` usw.). Es sind aber reine DOM-Selektoren ohne
		// `name`-Attribut, in keinem Formular und ohne Submit-Handler; die echten
		// Einstellungsfelder heissen verschachtelt `contact-form[name]`, tragen als
		// Top-Level also `contact-form`. Das Admin-Bundle sendet diese Action nirgends.
		// Beide Lesarten geprueft (Action-Wert und Feldname), keine Kollision.
		if ( array_key_exists( 'mystickyelements/mystickyelements.php', $installed_plugins ) ) {
			$actions[] = 'mystickyelements_contact_form';
			self::display_admin_notice( __( 'My Sticky Elements detected – added action: mystickyelements_contact_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// COOL FORMKIT LITE (extensions-for-elementor-form, 20.000) — ein eigenstaendiges
		// Formular-Widget fuer Elementor OHNE Pro, kein blosser Aufsatz.
		//   server: `wp_ajax_nopriv_coolformkit_forms_send_form`,
		//           modules/forms/components/ajax-handler.php:250-251.
		//   client: `form-sender.js` sendet FormData mit dieser Action und einem EIGENEN
		//           Nonce (`cool-form-submission`).
		//
		// ZWEI ZEILEN, UND DIE ZWEITE IST DER INTERESSANTE FUND: dieselbe Zip registriert
		// zusaetzlich `elementor_pro_atomic_forms_send_form` — Elementor Pros NEUE
		// Formular-Action neben der laengst geseedeten `elementor_pro_forms_send_form`.
		// Elementor Pro selbst hat kein wp.org-Zip und ist damit nicht verifizierbar; hier
		// aber schon, weil DIESE Zip den Handler registriert. Deshalb steht die Zeile unter
		// dem Cool-FormKit-Gate und nicht unter dem von Elementor Pro: geseedet wird, was
		// belegt ist, nicht was plausibel waere.
		if ( array_key_exists( 'extensions-for-elementor-form/extensions-for-elementor-form.php', $installed_plugins ) ) {
			$actions[] = 'coolformkit_forms_send_form';
			$actions[] = 'elementor_pro_atomic_forms_send_form';
			self::display_admin_notice( __( 'Cool FormKit detected – added actions: coolformkit_forms_send_form, elementor_pro_atomic_forms_send_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		return $actions;
	}

	/**
	 * Welle 6 der Seed-Ausweitung (2026-09-25). Grundlage: ERHEBUNG-BUILDER-2.md,
	 * Abschnitt „Welle 6" — jede Zeile am Quelltext des Stable-Tags belegt (Server- und
	 * Client-Haelfte), gegen das Backend des Produkts gegengeprueft, beide Lesarten
	 * (Action-Wert und Top-Level-Feldname) ohne Kollision.
	 *
	 * @param array<string, mixed> $installed_plugins get_plugins() — file => header data.
	 * @return string[] Action lines, unindexed.
	 */
	private static function wave_6_ajax_actions( array $installed_plugins ): array {
		$actions = array();

		// ROYAL ELEMENTOR ADDONS 1.7.1068 (600.000) — Formular-Widget.
		//   server: classes/modules/forms/wpr-send-email.php:21 (nopriv).
		//   client: assets/js/frontend.js:9744-9751 ($.ajax POST).
		// NUR die E-Mail-Action: ein Formular kann bis zu vier Ajax-Anfragen gleichzeitig
		// senden (E-Mail, Speichern, Webhook, Mailchimp — die drei letzten sind Pro), und
		// ein Token traegt nur drei Nutzungen (Stamp::TOKEN_MAX_USES). Benannte Luecke: der
		// Speichern-Endpunkt bleibt direkt ansprechbar.
		if ( array_key_exists( 'royal-elementor-addons/wpr-addons.php', $installed_plugins ) ) {
			$actions[] = 'wpr_form_builder_email';
			self::display_admin_notice( __( 'Royal Elementor Addons detected – added action: wpr_form_builder_email', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// HAPPY ADDONS 3.50.0 (400.000) — Mailchimp-Widget.
		//   server: base.php:94. client: assets/js/happy-addons.js:866-878.
		if ( array_key_exists( 'happy-elementor-addons/plugin.php', $installed_plugins ) ) {
			$actions[] = 'ha_mailchimp_ajax';
			self::display_admin_notice( __( 'Happy Addons detected – added action: ha_mailchimp_ajax', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// CHATY 3.6.1 (300.000) — Kontaktformular im Chat-Knopf.
		//   server: includes/class-frontend.php:81. client: dist/js/script.js (FormData aus
		//   .chaty-ajax-contact-form, verstecktes action-Feld). Tracking laeuft ueber andere Namen.
		if ( array_key_exists( 'chaty/cht-icons.php', $installed_plugins ) ) {
			$actions[] = 'chaty_front_form_save_data';
			self::display_admin_notice( __( 'Chaty detected – added action: chaty_front_form_save_data', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// JEG KIT 3.2.19 (300.000) — Mailchimp-Element. KEIN admin-ajax: POST an
		// `/?jkit-ajax-request=jkit_elements`, ausgewertet in parse_request ueber die
		// Query-Variable `action` (class/ajax/class-ajax.php:106-119, Praefix
		// jkit_element_ajax_). Die Action-Liste greift damit im Nicht-Ajax-Zweig, wie bei
		// CoBlocks. Das Backend nutzt wp_ajax_jkit_* (:41-50), andere Namen.
		if ( array_key_exists( 'jeg-elementor-kit/jeg-elementor-kit.php', $installed_plugins ) ) {
			$actions[] = 'jkit_element_ajax_jkit_mailchimp';
			self::display_admin_notice( __( 'Jeg Kit detected – added action: jkit_element_ajax_jkit_mailchimp', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// ELEMENT PACK LITE 8.8.5 (100.000) — Kontaktformular.
		//   server: modules/contact-form/module.php:270. client: widgets/contact-form.php:
		//   1274, 1448 + ep-contact-form.min.js (fetch POST).
		if ( array_key_exists( 'bdthemes-element-pack-lite/bdthemes-element-pack-lite.php', $installed_plugins ) ) {
			$actions[] = 'element_pack_contact_form';
			self::display_admin_notice( __( 'Element Pack Lite detected – added action: element_pack_contact_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// DEPICTER 4.8.1 (80.000) — Formular-Ebene im Slider.
		//   server: app/routes/ajax.php:516-518 (POST, auch fuer Gaeste). client:
		//   Elements/Form.php:70, 205 + player/external-layers/form/layer.js (fetch FormData).
		//   Das Backend nutzt lead-index/list/update.
		if ( array_key_exists( 'depicter/depicter.php', $installed_plugins ) ) {
			$actions[] = 'depicter-lead-submit';
			self::display_admin_notice( __( 'Depicter detected – added action: depicter-lead-submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// CUSTOMER REVIEWS FOR WOOCOMMERCE 5.122.0 (80.000) — Bewertung, Frage, lokales
		// Bewertungsformular. server: class-cr-all-reviews.php:28, class-cr-qna.php:23,
		// class-cr-local-forms-ajax.php:21. client: js/frontend.js:1113, 1178, 1235,
		// js/form.js:88. Nicht im Backend.
		if ( array_key_exists( 'customer-reviews-woocommerce/ivole.php', $installed_plugins ) ) {
			$actions[] = 'cr_submit_review';
			$actions[] = 'cr_new_qna';
			$actions[] = 'cr_local_forms_submit';
			self::display_admin_notice( __( 'Customer Reviews for WooCommerce detected – added actions: cr_submit_review, cr_new_qna, cr_local_forms_submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// STRONG TESTIMONIALS 3.3.12 (80.000) — Einsendeformular. wpmtst_form2 ist der
		// Ajax-Weg, wpmtst_form der klassische POST, den `init` liest
		// (class-strong-testimonials-form.php:27, 32, 91; client form-validation.js:218,
		// functions-template-form.php:54). Kein Feld dieses Namens, nicht im Backend.
		if ( array_key_exists( 'strong-testimonials/strong-testimonials.php', $installed_plugins ) ) {
			$actions[] = 'wpmtst_form2';
			$actions[] = 'wpmtst_form';
			self::display_admin_notice( __( 'Strong Testimonials detected – added actions: wpmtst_form2, wpmtst_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// HELLO PLUS 1.7.8 (70.000) — Formular-Widget.
		//   server: modules/forms/components/ajax-handler.php:260. client: form-sender.js:
		//   8, 62-66, 158 (fetch FormData).
		if ( array_key_exists( 'hello-plus/hello-plus.php', $installed_plugins ) ) {
			$actions[] = 'helloplus_forms_lite_send_form';
			self::display_admin_notice( __( 'Hello Plus detected – added action: helloplus_forms_lite_send_form', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// SITE REVIEWS 8.3.2 — der Ajax-Ausweichweg (RouterHooks.php:16, Router.php):
		// Regelzeile, weil `glsr_public_action` alle oeffentlichen Aktionen des Produkts
		// traegt; gepinnt auf submit-review.
		if ( array_key_exists( 'site-reviews/site-reviews.php', $installed_plugins ) ) {
			$actions[] = '{"action":"glsr_public_action","site-reviews":{"_action":"submit-review"}}';
			self::display_admin_notice( __( 'Site Reviews detected – added action rule: glsr_public_action (submit-review)', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		return $actions;
	}
}
