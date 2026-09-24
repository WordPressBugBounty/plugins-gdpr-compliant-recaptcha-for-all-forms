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
			'slug'      => self::SLUG,
			'plugin'    => self::SLUG,
			'version'   => RCM_Main::VERSION,
			'endpoint'  => self::ENDPOINT,
			'maxChars'  => self::MAX_CHARS,
			'privacy'   => self::PRIVACY_URL,
			/* translators: dialog heading shown when the plugin is being deactivated. */
			'heading'   => __( 'Before you go — what went wrong?', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'intro'     => __( 'If something did not work, a sentence about it is worth more than any statistic. It is optional.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'label'     => __( 'What happened?', 'gdpr-compliant-recaptcha-for-all-forms' ),
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
			'notice'    => __( 'Your message goes to the plugin author at programmiere.de and is kept for 90 days. The plugin name and version number travel with it, so a message can be told apart from one about a different plugin. Nothing else is stored with your message — not your IP address, not your site address, nothing from your forms. Deactivate without sending to transmit nothing at all.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'privacyOf' => __( 'Privacy notice', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'send'      => __( 'Send and deactivate', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'skip'      => __( 'Deactivate without sending', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'cancel'    => __( 'Cancel', 'gdpr-compliant-recaptcha-for-all-forms' ),
		);
	}
}
