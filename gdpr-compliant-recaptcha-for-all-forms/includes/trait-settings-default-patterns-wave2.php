<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/seeds.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Default_Patterns_Wave2: die zweite Datei des Muster-Seeds, abgespalten am
 * 2026-09-24, als trait-settings-default-patterns.php mit 534 von 600 Zeilen die vier
 * Muster der Welle 4 nicht mehr hielt (Deckel: CLAUDE.md „Dateigroessen").
 *
 * SCHNITTLINIE: Settings_Default_Patterns haelt den Bestand und bleibt die einzige Datei
 * mit der OEFFENTLICHEN get_default_recognition_patterns(), die beide Haelften
 * zusammenfuehrt. DIESE Datei traegt die Muster der Welle 4: Brevo, Form Maker
 * (Default-Modus), Mailchimp List Subscribe, Calculated Fields Form. Grundlage je Eintrag
 * ist ERHEBUNG-BUILDER-2.md (2026-09-24), jede Signatur gegen die echte wp.org-Zip belegt.
 *
 * ALLE VIER EINTRAEGE SIND WERTGEBUNDEN ODER UND-VERKNUEPFT, und das ist kein Zufall: es
 * sind genau die Produkte, deren Feldname allein auch im eigenen Backend vorkommt. Der
 * Ueberbreiten-Waechter sieht das nicht — er kennt nur WordPress-Kern-Screens
 * (handbuch/gate.md). Wer hier einen Wert entfernt, um „breiter zu fangen", sperrt den
 * Betreiber aus dem Backend genau des Produkts aus, das wir zu schuetzen vorgeben.
 */
trait Settings_Default_Patterns_Wave2 {

	/**
	 * Welle 4 der Seed-Ausweitung (2026-09-24), Muster-Anteil.
	 *
	 * @param array<string,mixed> $installed_plugins Ergebnis von get_plugins().
	 * @return array<int,string> Musterzeilen.
	 */
	private static function wave_2_recognition_patterns( array $installed_plugins ): array {
		$patterns = array();

		// BREVO, vormals Sendinblue (mailin, 100.000 Installationen).
		//   server: kein Ajax-Handler. `sendinblue.php:447` prueft am `init`-Hook
		//           `$_POST['sib_form_action'] === 'subscribe_form_submit'`.
		//   client: `js/mailin-front.js:139-141` postet per jQuery an die aktuelle Seite —
		//           das Formular traegt kein `action`-Attribut, `formURL` bleibt leer.
		//   Body urlencoded.
		//
		// WERTGEBUNDEN, nicht nur der Schluessel: `sib_form_action` ist ein
		// Dispatch-Feldname, der Wert unterscheidet die Faelle. Der Schluessel allein
		// waere die breitere und damit schlechtere Zeile.
		if ( array_key_exists( 'mailin/sendinblue.php', $installed_plugins ) ) {
			$patterns[] = '{"sib_form_action":"subscribe_form_submit"}';
			self::display_admin_notice( __( 'Brevo detected – added pattern: sib_form_action', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// FORM MAKER BY 10WEB (form-maker, 30.000) — die ZWEITE HAELFTE des Eintrags.
		//
		// Die Action-Zeile `fm_submit_form` in trait-settings-default-actions-wave3.php
		// deckt nur den Ajax-Modus, und der ist WERKSEITIG AUS (`fm_ajax_submit` Default
		// 0). Der Default-Weg ist ein klassischer POST des Formulars auf sich selbst; sein
		// Gate-Feld heisst `save_or_submit<ID>` und traegt die Formular-ID im Namen, ist
		// also kein schreibbares Muster. `fm-current-page` dagegen rendert jedes Formular
		// unbedingt, in beiden Modi (`frontend/views/form_maker.php:1829`, direkt vor
		// `</form>`).
		//
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: der Feldname kommt ausserhalb der
		// beiden Frontend-Dateien nicht vor. Die Formular-Vorschau des Editors oeffnet
		// einen echten oeffentlichen Post (`get_post_permalink()`), rendert also nicht im
		// wp-admin-Kontext.
		//
		// WER EINE DER BEIDEN ZEILEN ENTFERNT, halbiert die Abdeckung dieses Produkts —
		// und zwar still, weil beide Modi dasselbe Formular zeigen.
		if ( array_key_exists( 'form-maker/form-maker.php', $installed_plugins ) ) {
			$patterns[] = '{"fm-current-page":null}';
			self::display_admin_notice( __( 'Form Maker detected – added pattern: fm-current-page', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// MAILCHIMP LIST SUBSCRIBE FORM (mailchimp, 60.000).
		//   server: kein Ajax fuer die Anmeldung (nur `mailchimp_sf_track_form_view` fuer
		//           Analytics). `includes/class-mailchimp-form-submission.php:24` haengt am
		//           `init`-Hook und verlangt
		//           `$_POST['mcsf_action'] === 'mc_submit_signup_form'`.
		//   client: reines HTML-Formular, `mailchimp_widget.php:95-98`, verstecktes Feld
		//           mit genau diesem Wert. Body urlencoded.
		//
		// DER WERT IST HIER DER GANZE UNTERSCHIED, und das ist gemessen, nicht vorsichtig:
		// `mcsf_action` ist der generische Dispatch-Feldname des Produkts und steht auch in
		// drei Admin-Templates — `update_mc_list_id` (settings.php:95), `logout`
		// (header.php:38), `change_form_settings` (setup-page.php:13). Alle drei posten auf
		// `admin.php?page=mailchimp_sf_options`, einen Screen eines Fremdprodukts, den der
		// Ueberbreiten-Waechter nicht kennt. Eine Zeile `{"mcsf_action":null}` wuerde den
		// Betreiber aus seinen eigenen Mailchimp-Einstellungen aussperren — dieselbe
		// Fehlerklasse wie Formidables `frm_action` und MailPoets API-Name.
		if ( array_key_exists( 'mailchimp/mailchimp.php', $installed_plugins ) ) {
			$patterns[] = '{"mcsf_action":"mc_submit_signup_form"}';
			self::display_admin_notice( __( 'Mailchimp List Subscribe detected – added pattern: mcsf_action', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// CALCULATED FIELDS FORM (calculated-fields-form, 40.000).
		//   server: kein Ajax fuer die Einsendung (die REST-Route in
		//           `inc/cpcff_mcp_server.inc.php` ist ein Agenten-Endpunkt, nicht der
		//           Submit). `cp_calculatedfieldsf_free.php:67` haengt am `init`-Hook und
		//           unterscheidet die echte Einsendung an genau diesen beiden Feldern
		//           (Zeilen 235-238).
		//   client: klassisches HTML-Formular mit `enctype="multipart/form-data"`; im
		//           „Ajax-Modus" derselbe POST gegen ein verstecktes iFrame, also derselbe
		//           `init`-Hook.
		//
		// UND-VERKNUEPFT, und die zweite Haelfte ist die tragende: `cp_calculatedfieldsf_id`
		// allein steht auch in einem Admin-Formular (`inc/cpcff_admin_int.inc.php:191`,
		// Revision uebernehmen). `cp_calculatedfieldsf_pform_psequence` kommt in der ganzen
		// Zip ausschliesslich in Public-Dateien vor. Ein Muster nur auf der ID waere die
		// Aussperrung des Betreibers aus dem Formular-Editor.
		if ( array_key_exists( 'calculated-fields-form/cp_calculatedfieldsf_free.php', $installed_plugins ) ) {
			$patterns[] = '{"cp_calculatedfieldsf_id":null,"cp_calculatedfieldsf_pform_psequence":null}';
			self::display_admin_notice( __( 'Calculated Fields Form detected – added pattern: cp_calculatedfieldsf_id', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// VISUAL FORM BUILDER (visual-form-builder, 20.000) — Welle 5.
		//   server: kein Ajax, kein REST. `public/class-form-display.php:53` haengt am
		//           `init`-Hook; `Visual_Form_Builder_Email::submit_check()` verlangt
		//           `$_POST['form_id']` UND `$_POST['vfb-submit']`.
		//   client: jedes gerenderte Formular traegt beide Felder unbedingt, multipart.
		//
		// UND-VERKNUEPFT, UND DIE ZWEITE HAELFTE TRAEGT: `form_id` allein steht auch in der
		// Admin-Formularbearbeitung (`admin/class-forms-edit.php`), waere also die
		// Aussperr-Zeile. `vfb-submit` kommt unter `admin/` kein einziges Mal vor —
		// gemessen, nicht angenommen. Dass das Produkt seine eigene Verarbeitung an
		// derselben Kombination festmacht, ist die beste Bestaetigung, die eine Signatur
		// haben kann.
		//
		// AM 2026-09-24 IN DER LAUFENDEN INSTANZ GEMESSEN, drei Faelle gegen wp-env mit
		// dieser Zeile im Scope:
		//   · POST mit `form_id` UND `vfb-submit`, ohne Token -> GEBLOCKT.
		//   · POST mit nur `form_id` (das ist die Admin-Lesart) -> durchgelassen.
		//   · POST mit nur `vfb-submit`                         -> durchgelassen.
		// Die UND-Verknuepfung verhindert die Aussperrung also nachweislich, sie ist nicht
		// blosse Vorsicht.
		//
		// NEBENBEFUND, falls jemand hier einen Abruf-Fall baut: das Produkt selbst
		// antwortet auf genau diese Kombination mit HTTP 500, wenn die Formular-ID nicht
		// existiert (gemessen; ohne das Plugin liefert derselbe Request 200). Das ist sein
		// Fehler, nicht unserer — ein Testfall muss ein echtes Formular anlegen.
		if ( array_key_exists( 'visual-form-builder/visual-form-builder.php', $installed_plugins ) ) {
			$patterns[] = '{"form_id":null,"vfb-submit":null}';
			self::display_admin_notice( __( 'Visual Form Builder detected – added pattern: vfb-submit', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// *** Welle 6 (2026-09-25), ERHEBUNG-BUILDER-2.md ***
		// SITE REVIEWS 8.3.2 (60.000) — drei Wege, drei Zeilen: REST (Routen-Getter), Ajax
		// (Regelzeile in der Action-Liste, s. get_default_ajax_actions()) und der klassische
		// POST, den Router::routePublicPostRequest() auf `init` liest (Router.php:85-104).
		// Dieses Muster deckt den dritten: `site-reviews[_action]=submit-review` kommt nur
		// im oeffentlichen Code vor; das Backend sendet andere _action-Werte.
		if ( array_key_exists( 'site-reviews/site-reviews.php', $installed_plugins ) ) {
			$patterns[] = '{"site-reviews":{"_action":"submit-review"}}';
			self::display_admin_notice( __( 'Site Reviews detected – added recognition pattern: {"site-reviews":{"_action":"submit-review"}}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// WP ULTIMATE REVIEW 2.4.3 (60.000) — klassischer POST (app/content.php:56,
		// 189-196; views/public/meta-box-view.php:384, 603). Der Name des Absende-Knopfs,
		// NICHT der Datenschluessel: die Backend-Metabox sendet xs_submit_review_data[…]
		// (views/admin/meta-box-html.php:63-133).
		if ( array_key_exists( 'wp-ultimate-review/wp-ultimate-review.php', $installed_plugins ) ) {
			$patterns[] = '{"xs_review_form_public_data":null}';
			self::display_admin_notice( __( 'WP Ultimate Review detected – added recognition pattern: {"xs_review_form_public_data":null}', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		return $patterns;
	}
}
