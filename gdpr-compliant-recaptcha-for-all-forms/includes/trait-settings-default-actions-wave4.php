<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/seeds.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Default_Actions_Wave4: die vierte Datei des admin-ajax-Seeds, angelegt am
 * 2026-10-09 fuer Welle 7. trait-settings-default-actions-wave3.php haette die Welle mit
 * ihren Belegkommentaren noch gerade aufgenommen und waere danach am Deckel gestanden
 * (CLAUDE.md „Dateigroessen") — eine eigene Datei je Welle haelt die naechste Welle frei.
 *
 * SCHNITTLINIE: Settings_Default_Actions bleibt die einzige Datei mit der OEFFENTLICHEN
 * get_default_ajax_actions(), die alle Haelften zusammenfuehrt. DIESE Datei traegt Welle 7
 * (wave_7_ajax_actions()). Grundlage je Eintrag ist ERHEBUNG-BUILDER-2.md, Abschnitt
 * „Welle 7": jede Zeile am Quelltext der aktuellen wp.org-Zip belegt (Server- UND
 * Client-Haelfte), gegen das Backend des Produkts gegengeprueft, beide Lesarten
 * (Action-Wert und Top-Level-Feldname) ohne Kollision.
 *
 * Trait statt zweiter Klasse, aus demselben Grund wie in den Vorgaengerdateien:
 * `self::display_admin_notice()` ist eine Methode von Settings_Menu selbst.
 */
trait Settings_Default_Actions_Wave4 {

	/**
	 * Welle 7 der Seed-Ausweitung (2026-10-09).
	 *
	 * @param array<string, mixed> $installed_plugins get_plugins() — file => header data.
	 * @return string[] Action lines, unindexed.
	 */
	private static function wave_7_ajax_actions( array $installed_plugins ): array {
		$actions = array();

		// GWOLLE GUESTBOOK 5.1.1 (gwolle-gb, 20.000) — der Ajax-Handler des Gaestebuchs.
		//   server: frontend/gb-form-ajax.php:43-44 (nopriv), ruft dieselbe
		//           gwolle_gb_frontend_posthandling() wie der klassische Weg.
		//   client: frontend/js/gwolle-gb-frontend.js:434-449 waere der Absender (FormData
		//           aus JEDEM <input> des Formulars, also auch unserem Token-Feld) — aber
		//           sein Selektor `.gwolle_gb_form_ajax` trifft in 5.1.1 kein Element: das
		//           Formular traegt `gwolle-gb-form-ajax` (frontend/gb-form.php:151).
		// AM 2026-10-09 IM ECHTEN BROWSER GEMESSEN: auch mit eingeschaltetem Ajax
		// (Werkseinstellung) postet das Formular klassisch auf die eigene Seite. Den
		// Besucherweg deckt deshalb das Muster `{"gwolle_gb_function":"add_entry"}`
		// (trait-settings-default-patterns-wave2.php). Diese Zeile deckt den Handler, den
		// ein Bot direkt ansprechen kann, um das Muster zu umgehen — und den Ajax-Weg, sobald
		// Gwolle seinen Selektor repariert. Kein echter Besucher sendet sie heute, sie kann
		// also niemanden aussperren.
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: der Name steht in der ganzen Zip nur in
		// diesen zwei Dateien; im Frontend-JS zusaetzlich als CSS-Klasse, nie als Feldname.
		// Das Backend nutzt `gwolle_gb_ajax` (admin/gb-ajax-management.php:330).
		if ( array_key_exists( 'gwolle-gb/gwolle-gb.php', $installed_plugins ) ) {
			$actions[] = 'gwolle_gb_form_ajax';
			self::display_admin_notice( __( 'Gwolle Guestbook detected – added action: gwolle_gb_form_ajax', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// WP CUSTOMER REVIEWS 3.8.1 (wp-customer-reviews, 20.000) — ALS ZWEI REGELZEILEN.
		//   server: wp-customer-reviews-3.php:1417-1418 (nopriv `wpcr3-ajax`), der Rumpf
		//           ajax() :1174 verteilt nach `ajaxAct2`: "form" (neue Bewertung, :1240) oder
		//           "pager" (Blaettern in der Bewertungsliste, :1361).
		//   client: js/wp-customer-reviews.js — die Action reist in der Query der URL
		//           (`admin-ajax.php?action=wpcr3-ajax`, :1391 der PHP-Datei), der Rumpf ist
		//           ein jQuery-POST (:45-50). Das Formular haengt `wpcr3_ajaxAct2=form` an
		//           (:123), der Pager schickt `ajaxAct2=pager` (:201). Es gibt kein <form>,
		//           das Token kommt ueber die XHR-Injektion.
		// WARUM NICHT DIE KLARTEXTZEILE `wpcr3-ajax`: sie bewertete auch jeden Klick auf eine
		// Seitenzahl der Bewertungsliste — ein POST ohne Freitext, der vor dem ersten
		// geloesten PoW geblockt werden koennte (dieselbe Abwaegung wie beim Warenkorb,
		// handbuch/seeds.md). Die Regelzeilen nageln den Wert "form" fest.
		// ZWEI ZEILEN, weil der Server das Praefix `wpcr3_` aus JEDEM Schluessel streicht
		// (:1188-1191): `ajaxAct2=form` ohne Praefix ist fuer ihn dieselbe Einsendung.
		// BENANNTE LUECKE: str_replace() streicht das Praefix auch mitten im Namen, ein
		// gebastelter Schluessel wie `ajaxAwpcr3_ct2` erreicht den Formular-Zweig an beiden
		// Zeilen vorbei. Der echte Client und jeder, der ihn nachahmt, ist gedeckt.
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: das Backend sendet
		// `wpcr3_enabled_posts` (include/admin/wp-customer-reviews-3-admin.php:122);
		// `wpcr3-ajax` steht in keiner Admin-Datei. Regelzeilen haben keine Feldname-Lesart.
		if ( array_key_exists( 'wp-customer-reviews/wp-customer-reviews-3.php', $installed_plugins ) ) {
			$actions[] = '{"action":"wpcr3-ajax","wpcr3_ajaxAct2":"form"}';
			$actions[] = '{"action":"wpcr3-ajax","ajaxAct2":"form"}';
			self::display_admin_notice( __( 'WP Customer Reviews detected – added rule lines for action: wpcr3-ajax (review form)', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// BRAVE POPUP BUILDER 0.8.8 (brave-popup-builder, 20.000) — Formular-Element in
		// Popups, Optins und Umfragen.
		//   server: lib/helpers/forms.php:3-4 (nopriv).
		//   client: assets/frontend/brave.js:527 baut den Rumpf (formData als JSON-String,
		//           popupID, formID, security, action), brave_ajax_send() :911-930 schickt
		//           ihn per XHR urlencoded an admin-ajax — das Token kommt ueber die
		//           XHR-Injektion.
		// GATE PATH VERIFIED: die Hauptdatei heisst `index.php`, nicht wie der Slug.
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: der Name steht in der Zip nur in diesen
		// zwei Dateien; das Admin-Bundle (assets/js/admin_popups.js) enthaelt ihn nicht.
		// Login/Registrierung des Produkts laufen ueber andere Namen und sind nicht geseedet.
		if ( array_key_exists( 'brave-popup-builder/index.php', $installed_plugins ) ) {
			$actions[] = 'bravepop_form_submission';
			self::display_admin_notice( __( 'Brave Popup Builder detected – added action: bravepop_form_submission', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// JETPACK CRM 6.8.x (zero-bs-crm, 30.000; die genaue Zip steht im BUILDER_MANIFEST —
		// eine volle 6er-Nummer hier laese check-release-state.mjs als Zusage UNSERER
		// naechsten Version) — die Lead-Formulare des Moduls „Forms"
		// (Shortcode `[jetpackcrm_form]`, auch als Iframe-Einbettung von dieser Installation).
		//   server: includes/ZeroBSCRM.AJAX.php:1646-1647 (nopriv); die admin_post-Variante
		//           darunter ist auskommentiert.
		//   client: js/ZeroBSCRM.public.leadform.js:85, 97, 112 (je Formular-Stil ein von Hand
		//           gebautes Objekt), jQuery.ajax POST :167-172 — kein <form>-Serialisieren,
		//           das Token kommt ueber die XHR-Injektion.
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: der Name steht nur in diesem Skript und
		// im Handler, unter admin/ nirgends. Nicht geseedet: `zbs_lead_form_views` (ein
		// Zaehler) und `zbs_quotes_accept_quote` (Angebotsannahme im Kundenportal — ein
		// Fehlblock kostete ein Geschaeft, und es gibt dort keinen Freitext).
		if ( array_key_exists( 'zero-bs-crm/ZeroBSCRM.php', $installed_plugins ) ) {
			$actions[] = 'zbs_lead_form_capture';
			self::display_admin_notice( __( 'Jetpack CRM detected – added action: zbs_lead_form_capture', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// HIREZOOT, vormals WP JOB OPENINGS (wp-job-openings, 30.000) — das Bewerbungsformular.
		// Ausgeliefert wird 4.1.0 aus dem trunk (Stable tag 4.1.0, im SVN gibt es keinen
		// Tag dazu); verifiziert gegen trunk 4.1.0 UND den letzten Tag 4.0.5, beide gleich.
		//   server: inc/class-awsm-job-openings-form.php:34-35 (nopriv) und derselbe Name als
		//           klassischer POST auf die Stellenseite (insert_application() :420-428 am
		//           Hook `before_awsm_job_details`) — die Action-Liste greift dort im
		//           Nicht-Ajax-Zweig, wie bei CoBlocks.
		//   client: inc/templates/single-job/form.php:58, 77 (verstecktes action-Feld im
		//           <form>), assets/js/public/job-application.js:60-77 (FormData des Formulars,
		//           also samt unserem Token-Feld; multipart wegen des Lebenslaufs).
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: der Name steht nur in diesen beiden
		// Dateien; unter admin/ und in den Admin-Bundles nirgends. Eine Bewerbung legt kein
		// Konto an (Bewerber sind ein eigener Beitragstyp).
		if ( array_key_exists( 'wp-job-openings/wp-job-openings.php', $installed_plugins ) ) {
			$actions[] = 'awsm_applicant_form_submission';
			self::display_admin_notice( __( 'HireZoot (WP Job Openings) detected – added action: awsm_applicant_form_submission', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// BACK IN STOCK NOTIFIER FOR WOOCOMMERCE 7.4.5 (20.000) — das Warteliste-Formular
		// auf ausverkauften Produkten. Der Ajax-Weg ist die Werkseinstellung; den REST-Weg
		// (Schalter `ajax_submission_via`) deckt die Route
		// `back-in-stock/v1/subscriber/create` in trait-settings-default-routes.php.
		//   server: includes/class-ajax.php:18-19 (nopriv).
		//   client: assets/js/frontend-dev.js:238-250 (von Hand gebautes Objekt), jQuery POST
		//           :362-368 — das Token kommt ueber die XHR-Injektion.
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: der Name steht nur im Handler und im
		// Frontend-Skript; assets/js/admin.js und includes/admin/ kennen ihn nicht. Ein
		// Abonnent ist ein eigener Beitragstyp, kein WordPress-Konto.
		if ( array_key_exists( 'back-in-stock-notifier-for-woocommerce/cwginstocknotifier.php', $installed_plugins ) ) {
			$actions[] = 'cwginstock_product_subscribe';
			self::display_admin_notice( __( 'Back In Stock Notifier detected – added action: cwginstock_product_subscribe', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		// DIRECTORIST 8.10.3 (directorist, 20.000) — die zwei Freitext-Formulare der
		// Eintragsseite: „Kontakt zum Inhaber" und „Missbrauch melden".
		//   server: includes/classes/class-ajax-handler.php:33-34 (Meldung) und :37-38
		//           (Kontakt), beide nopriv.
		//   client: assets/build/js/public/single-listing.js — Kontakt: serializeArray des
		//           Formulars plus action, $.post; Meldung: von Hand gebautes Objekt, $.post.
		//           Das Kontaktformular hat KEIN method-Attribut
		//           (templates/single/section-contact_listings_owner.php:32), unser Client
		//           stempelt es deshalb nicht — das Token kommt ueber die XHR-Injektion.
		// GATE PATH VERIFIED: die Hauptdatei heisst `directorist-base.php`.
		// CHECKED AGAINST THE PRODUCT'S OWN BACKEND: beide Namen stehen nur im Handler, in
		// diesem einen Frontend-Bundle und (Kontakt) als action-ATTRIBUT des Formulars — nie
		// als Feldname, in keinem Admin-Bundle. Bewertungen laufen ueber das Kern-
		// Kommentarformular (comment_post_ID, ohnehin ab Werk geseedet).
		// Registrierung und Eintrag-Einreichen (legt fuer Gaeste ein Konto an) stehen in der
		// RISIKOKLASSE (Risk_Catalog), nicht hier.
		if ( array_key_exists( 'directorist/directorist-base.php', $installed_plugins ) ) {
			$actions[] = 'atbdp_public_send_contact_email';
			$actions[] = 'atbdp_public_report_abuse';
			self::display_admin_notice( __( 'Directorist detected – added actions: atbdp_public_send_contact_email, atbdp_public_report_abuse', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		return $actions;
	}
}
