<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/feedback.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.

/**
 * Class Deactivation_Feedback: the box that asks what went wrong when an administrator
 * deactivates this plugin, and the one place that knows where the answer is sent.
 *
 * THE DIALOG IS OLD, THIS CLASS IS NOT. The script has shipped for years; what it did
 * not have was a receiver (every POST hit a 404, silently), a word to the operator
 * about where the text goes, or an owner in PHP. All three are the point of this class.
 *
 * WHY THE DISCLOSURE IS NOT OPTIONAL POLITENESS. This is the only place in the entire
 * plugin that talks to a server other than the site's own, and readme.txt otherwise
 * promises the opposite in four places ("no external requests", "no data leaves your
 * server"). wordpress.org guideline 7 requires that a transmission like this be
 * disclosed and consented to. So the rule this class enforces is:
 *
 *   nothing is transmitted unless a human typed something AND pressed the button that
 *   says it will be sent, after reading one sentence naming the recipient.
 *
 * An empty box deactivates the plugin and sends nothing at all — that is not an
 * edge case, it is the default path and the one most people take.
 *
 * NO E-MAIL FIELD, ON PURPOSE. A reply address would turn a one-line note into
 * contact-data processing, with everything that entails, and there is a working
 * channel for people who want an answer: the wordpress.org support forum. The dialog
 * therefore promises nothing it cannot keep — the old wording ("we'll fix it within
 * days") was a promise with no return path attached.
 *
 * WHY BOTH URLS LIVE HERE AS CONSTANTS. Until now the endpoint existed only inside the
 * JavaScript, which is why nobody noticed for years that it pointed at nothing. A
 * constant in PHP is greppable, is testable without a browser, and is handed to the
 * script instead of hardcoded in it.
 */
class Deactivation_Feedback {

	/**
	 * Where the feedback goes.
	 *
	 * The receiver lives in this repository under server/programmiere.de/ and is
	 * deployed with server/deploy-programmiere.sh. It answers 200 to everything.
	 */
	const ENDPOINT = 'https://programmiere.de/GDPRCompliantRecaptcha/update.php';

	/**
	 * Das Support-Forum auf wp.org. Ziel des Hinweises bei den zwei behebbaren
	 * Gruenden — der eine Weg, auf dem ein Problem eine Antwort bekommt.
	 */
	const SUPPORT_URL = 'https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/';

	/** The privacy notice the dialog links to — what is stored, for how long, by whom. */
	const PRIVACY_URL = 'https://programmiere.de/GDPRCompliantRecaptcha/';

	/** Longest message accepted, in characters. The receiver cuts at the same number. */
	const MAX_CHARS = 500;

	/** Plugin slug, i.e. the row on plugins.php whose deactivate link is intercepted. */
	const SLUG = 'gdpr-compliant-recaptcha-for-all-forms';

	/**
	 * Register the hook.
	 *
	 * @return void
	 */
	public function run() {
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
	}

	/**
	 * Load dialog script and style on the plugins screen, and nowhere else.
	 *
	 * On `admin_enqueue_scripts` rather than the `admin_init` this used to hang on:
	 * admin_init is not an asset hook, it just happened to run early enough to get
	 * away with it, and it does not receive the screen it is running on — which is why
	 * the old code had to reach for the $pagenow global to answer a question the hook
	 * hands over for free.
	 *
	 * @param string $hook_suffix Screen the admin is currently on.
	 * @return void
	 */
	public function enqueue( $hook_suffix ) {
		if ( 'plugins.php' !== $hook_suffix ) {
			return;
		}

		// `__DIR__` (a directory, not a file) as the second argument is deliberate and
		// works: plugins_url() runs it through dirname( plugin_basename() ), so passing
		// plugin/includes/ yields the plugin root — which is what both paths below are
		// relative to. Unusual enough to say so rather than leave the next reader to
		// check it.
		wp_enqueue_style(
			'gdpr-deactivation-feedback',
			plugins_url( '/css/style_deactivation_feedback.css', __DIR__ ),
			array(),
			RCM_Main::VERSION
		);

		wp_enqueue_script(
			'gdpr-deactivation-feedback',
			plugins_url( '/scripts/recaptcha-gdpr-pro-state.js', __DIR__ ),
			array(),
			RCM_Main::VERSION,
			true
		);

		wp_localize_script( 'gdpr-deactivation-feedback', 'gdprDeactivate', self::script_data() );
	}

	/**
	 * Everything the dialog needs, as one array.
	 *
	 * Separate from enqueue() so the wording can be read — and asserted on — without a
	 * WordPress request: every user-visible string of this feature is in here, and
	 * nowhere in the JavaScript.
	 *
	 * @return array<string, mixed>
	 */
	public static function script_data() {
		return array(
			'slug'             => self::SLUG,
			'plugin'           => self::SLUG,
			'version'          => RCM_Main::VERSION,
			'endpoint'         => self::ENDPOINT,
			'maxChars'         => self::MAX_CHARS,
			'privacy'          => self::PRIVACY_URL,
			/* translators: dialog heading shown when the plugin is being deactivated. */
			'heading'          => __( 'Before you go — what went wrong?', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'intro'            => __( 'If something did not work, a sentence about it is worth more than any statistic. It is optional.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'label'            => __( 'What happened?', 'gdpr-compliant-recaptcha-for-all-forms' ),
			// The disclosure. Names the recipient, names what is kept, names what is
			// not, and says how to send nothing — in that order, because that is the
			// order in which the questions occur to the person reading it.
			//
			// "STORED WITH YOUR MESSAGE", not a bare "stored" — Fable's acceptance review
			// caught this as the same error one level down. The receiver writes no IP
			// address, but the SERVER'S ACCESS LOG does, for about seven days, exactly
			// as the privacy notice says out loud. A flat "nothing else is stored" would
			// contradict our own notice, so the claim is scoped to the record this
			// feature keeps — which is the thing the reader is actually asking about.
			//
			// "STORED", NOT "TRANSMITTED", and the difference is not a hedge. Measured
			// in a real browser while building this: a cross-origin POST always carries
			// an `Origin` header, i.e. the site's own domain, and no fetch option can
			// suppress it — the way `referrerPolicy: 'no-referrer'` suppresses the far
			// more revealing wp-admin URL. The receiver writes neither to disk. Claiming
			// the domain is never transmitted would therefore have been a sentence this
			// plugin cannot keep, in the one place where it must.
			'notice'           => __( 'Your message goes to the plugin author at programmiere.de and is kept for 90 days. The plugin name and version number travel with it. Nothing else is stored with your message — not your IP address, not your site address, nothing from your forms. Technical details are only sent if you tick the box, and you can read them first. Deactivate without sending to transmit nothing at all.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'privacyOf'        => __( 'Privacy notice', 'gdpr-compliant-recaptcha-for-all-forms' ),

			// DIE GRUENDE ZUM ANKLICKEN. Anlass: die ersten elf Eingaenge nach dem
			// Scharfschalten des Empfaengers waren „eee" (zweimal), „just a test",
			// „don't work", „Does not work" — ein leeres Freitextfeld erntet leere
			// Antworten. Wer nichts tippt, hinterlaesst mit einem Klick trotzdem eine
			// Kategorie, und aus „don't work" wird eine zaehlbare Klasse.
			//
			// KEIN PFLICHTFELD: die Auswahl darf leer bleiben, sonst wird aus einer
			// freiwilligen Rueckmeldung eine Huerde vor dem Deaktivieren.
			'reasonLabel'      => __( 'Why are you deactivating?', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'reasons'          => array(
				array(
					'value' => 'not_working',
					'label' => __( 'It did not work', 'gdpr-compliant-recaptcha-for-all-forms' ),
				),
				array(
					'value' => 'false_positives',
					'label' => __( 'It blocked real visitors', 'gdpr-compliant-recaptcha-for-all-forms' ),
				),
				array(
					'value' => 'too_complicated',
					'label' => __( 'Too complicated to set up', 'gdpr-compliant-recaptcha-for-all-forms' ),
				),
				array(
					'value' => 'other_plugin',
					'label' => __( 'I found another plugin', 'gdpr-compliant-recaptcha-for-all-forms' ),
				),
				array(
					'value' => 'temporary',
					'label' => __( 'Only temporarily — I will be back', 'gdpr-compliant-recaptcha-for-all-forms' ),
				),
			),

			// DER EIGENTLICHE HEBEL, und er schickt Leute WEG von diesem Dialog: „it did
			// not work" ist kein Feedback, sondern ein ungeloester Supportfall, der
			// gerade das Plugin verlaesst. Ein geloester Forenthread haelt den Nutzer,
			// ist oeffentlich sichtbar und kann eine Bewertung werden — eine
			// Deaktivierungs-Meldung kann nichts davon. Deshalb erscheint dieser Hinweis
			// genau bei den zwei Gruenden, die sich beheben lassen.
			'supportFor'       => array( 'not_working', 'false_positives' ),
			'supportHint'      => __( 'This is usually fixable, and faster than you think. If you post it in the support forum, you get an answer — this box cannot reply to you.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'supportLabel'     => __( 'Open the support forum', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'supportUrl'       => self::SUPPORT_URL,

			// DER TECHNISCHE ABZUG. Er faehrt NUR mit gesetztem Haken mit, und der
			// Absender sieht vorher woertlich, was das ist — `diagnostics` ist genau der
			// String, der auf die Leitung geht, keine Beschreibung davon
			// (Deactivation_Diagnostics::as_plain_text(), dort auch die drei Regeln,
			// was niemals hineingehoert).
			'diagnostics'      => Deactivation_Diagnostics::as_plain_text(),
			'diagnosticsLabel' => __( 'Also send technical details (versions, active plugins, my settings)', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'diagnosticsShow'  => __( 'Show exactly what that is', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'send'             => __( 'Send and deactivate', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'skip'             => __( 'Deactivate without sending', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'cancel'           => __( 'Cancel', 'gdpr-compliant-recaptcha-for-all-forms' ),
		);
	}
}
