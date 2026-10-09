<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/feedback.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.

/**
 * Class Deactivation_Diagnostics: der technische Abzug, den der Deaktivierungs-Dialog
 * ANBIETET und der Absender freigibt.
 *
 * WARUM DAS EINE EIGENE KLASSE IST UND NICHT DREI ZEILEN IM DIALOG: der Abzug ist die
 * einzige Stelle im Plugin, an der Daten die Installation verlassen, die der Absender
 * nicht selbst getippt hat. Was hier hineingerät, muss einzeln begründbar sein, und das
 * geht nur, wenn es einen Ort gibt, an dem alles davon steht.
 *
 * DREI REGELN, DIE HIER NICHT VERHANDELBAR SIND:
 *
 * 1. NICHTS AUS DEN ERFASSTEN NACHRICHTEN. Die gespeicherten Einsendungen gehören den
 *    Besuchern der Seite, nicht dem Betreiber — er darf sie nicht weitergeben, auch nicht
 *    mit bestem Willen. Dieser Abzug enthält Zahlen ÜBER die Erfassung, nie Inhalte
 *    daraus.
 * 2. KEINE SEITENADRESSE. Der Dialog sagt zu, dass die Adresse der Seite nicht gespeichert
 *    wird; ein Abzug, der sie einpackt, würde diese Zusage brechen — an genau der Stelle,
 *    an der das Plugin genau sein muss.
 * 3. WAS HIER STEHT, SIEHT DER ABSENDER WÖRTLICH. `as_plain_text()` ist keine
 *    Zusammenfassung für die Anzeige, sondern GENAU das, was gesendet wird. Wer ein Feld
 *    ergänzt, ergänzt es damit zwangsläufig auch in der Anzeige — die beiden können nicht
 *    auseinanderlaufen, weil es nur eine Quelle gibt.
 *
 * Die Liste der aktiven Plugins ist der einzige Punkt, an dem man streiten kann. Sie steht
 * drin, weil „funktioniert nicht" fast immer ein Zusammenspiel zweier Plugins ist und die
 * Antwort ohne sie eine Rückfrage wäre — und sie ist der Grund, warum der Abzug ein
 * eigenes Häkchen hat statt stillschweigend mitzufahren.
 */
class Deactivation_Diagnostics {

	/**
	 * Obergrenze für die Plugin-Liste. Mehr sagt nichts mehr und blaeht den Body.
	 */
	const MAX_PLUGINS = 40;

	/**
	 * Der Abzug als flaches Feld-Wert-Paar-Array.
	 *
	 * @return array<string,string>
	 */
	public static function collect() {
		global $wp_version;

		$out = array(
			'WordPress' => is_string( $wp_version ) ? $wp_version : '',
			'PHP'       => PHP_VERSION,
			'Plugin'    => RCM_Main::VERSION,
			'Locale'    => get_locale(),
			'Multisite' => is_multisite() ? 'yes' : 'no',
		);

		// `exists()` statt eines instanceof: wp_get_theme() liefert immer ein WP_Theme,
		// auch fuer ein Verzeichnis, das gar nicht da ist — die Frage ist nicht, ob ein
		// Objekt kam, sondern ob es ein Theme gibt.
		$theme = wp_get_theme();
		if ( $theme->exists() ) {
			$out['Theme'] = trim( $theme->get( 'Name' ) . ' ' . $theme->get( 'Version' ) );
		}

		$out['Mode']       = self::mode();
		$out['Difficulty'] = (string) (int) get_option( Option::POW_DIFFICULTY );
		$out['Plugins']    = self::active_plugins();

		return $out;
	}

	/**
	 * Der Betriebsmodus in einem Wort — die Angabe, die bei „funktioniert nicht" als
	 * erste gebraucht wird, weil im Analyse- und im Flag-Modus nichts geblockt wird und
	 * ein „es blockt nicht" dort kein Fehler ist.
	 *
	 * @return string
	 */
	private static function mode() {
		if ( get_option( Option::POW_ANALYSIS_MODE ) ) {
			return 'analysis';
		}
		if ( get_option( Option::POW_FLAG_SPAM ) ) {
			return 'flag';
		}
		return 'blocking';
	}

	/**
	 * Aktive Plugins als `slug@version`, alphabetisch, gedeckelt.
	 *
	 * Slug und Version, nicht der Anzeigename: der Name ist übersetzt und je nach
	 * Sprache ein anderer String, der Verzeichnisname ist stabil und der, unter dem man
	 * das Produkt nachschlägt.
	 *
	 * @return string
	 */
	private static function active_plugins() {
		include_once ABSPATH . 'wp-admin/includes/plugin.php';

		$all    = get_plugins();
		$active = (array) get_option( 'active_plugins', array() );
		sort( $active );

		$list = array();
		foreach ( $active as $file ) {
			if ( count( $list ) >= self::MAX_PLUGINS ) {
				$list[] = '…';
				break;
			}
			$slug    = strtok( (string) $file, '/' );
			$version = isset( $all[ $file ]['Version'] ) ? $all[ $file ]['Version'] : '';
			$list[]  = '' === $version ? $slug : $slug . '@' . $version;
		}

		return implode( ', ', $list );
	}

	/**
	 * Der Abzug als Klartext — die eine Form, die gesendet UND angezeigt wird.
	 *
	 * @return string
	 */
	public static function as_plain_text() {
		$lines = array();
		foreach ( self::collect() as $key => $value ) {
			$lines[] = $key . ': ' . $value;
		}

		return implode( "\n", $lines );
	}
}
