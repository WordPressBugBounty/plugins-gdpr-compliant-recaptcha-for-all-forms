<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/translations.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.

/**
 * The one-off, dismissible call for translators — shown to an administrator whose admin
 * language is less than 90% translated on translate.wordpress.org, once per language.
 *
 * WHY 90%: WordPress.org builds a language pack, which WordPress then installs on its own,
 * only once 90% of the stable strings of a language are approved. Below that line every
 * translated string is invisible to users; above it this notice has nothing left to ask.
 *
 * WHY A FROZEN LIST AND NOT A LIVE LOOKUP: the progress per language comes from
 * translation-status.php, written at release time by scripts/update-translation-status.mjs.
 * Asking translate.wordpress.org from the site would be a second connection to another
 * server, and readme.txt promises the spam protection makes none. The list is as old as the
 * release, which is precise enough for "below 90%?". Nothing leaves the site unless the
 * administrator clicks "Help translate" — and then it is their browser opening a page.
 *
 * Same shape as Review_Request (handbuch/admin.md): capability-gated, only on this plugin's
 * own screens (wp.org guideline 11), never touches a setting, every answer is final, and
 * WordPress's own dismiss cross is made permanent through admin-ajax. One difference: the
 * answer is remembered PER LANGUAGE, because the question is about a language — an
 * administrator who switches to another incomplete one is asked about that one once.
 *
 * DONE holds the list of answered locales. It lives here, not on Option, which is at its
 * size cap; uninstall.php removes it all the same through the gdpr_pow_ prefix.
 */
final class Translation_Request {

	/** Approved share at which wp.org builds a language pack, in percent. */
	const PACK_THRESHOLD = 90;

	/** The stable project of this plugin on translate.wordpress.org; locale and slug follow. */
	const PROJECT_URL = 'https://translate.wordpress.org/projects/wp-plugins/gdpr-compliant-recaptcha-for-all-forms/stable/';

	/** Option key: the WordPress locales whose call has been answered (an array). */
	const DONE = Option::PREFIX . 'pow_translation_request_done';

	/** The query argument carrying the answer, and the nonce action of all paths. */
	const ACTION = 'gdpr_pow_translation_request';

	/** The admin-ajax action behind the core dismiss cross. */
	const AJAX_DISMISS = 'gdpr_pow_translation_dismiss';

	/** Answer: off to translate.wordpress.org (the marker is set on the way out). */
	const ANSWER_HELP = 'help';

	/** Answer: no. */
	const ANSWER_NO = 'no';

	/**
	 * The frozen list, loaded once per request.
	 *
	 * @var array<string, array<int, int|string>>|null
	 */
	private static $status = null;

	/**
	 * Wire the notice, the two links and the dismiss cross.
	 *
	 * @return void
	 */
	public function run() {
		add_action( 'admin_notices', array( $this, 'render' ) );
		add_action( 'admin_init', array( $this, 'handle_answer' ) );
		add_action( 'wp_ajax_' . self::AJAX_DISMISS, array( $this, 'handle_dismiss' ) );
	}

	/**
	 * The frozen progress list: locale => array( wp.org locale, slug, percent, name ).
	 *
	 * @return array<string, array<int, int|string>>
	 */
	public static function locales() {
		if ( null === self::$status ) {
			$data         = include __DIR__ . '/translation-status.php';
			self::$status = ( is_array( $data ) && isset( $data['locales'] ) && is_array( $data['locales'] ) ) ? $data['locales'] : array();
		}
		return self::$status;
	}

	/**
	 * The list entry of one WordPress locale, or null. Pure.
	 *
	 * Exact match only: de_AT is not de_DE on translate.wordpress.org, and a guessed
	 * neighbour would send the administrator to a language they did not choose.
	 *
	 * @param string $locale  WordPress locale, e.g. fr_FR.
	 * @param array<string, array<int, int|string>> $locales The frozen list.
	 * @return array<int, int|string>|null
	 */
	public static function entry_for( $locale, $locales ) {
		$locale = (string) $locale;
		if ( '' === $locale || ! isset( $locales[ $locale ] ) || count( $locales[ $locale ] ) < 4 ) {
			return null;
		}
		return $locales[ $locale ];
	}

	/**
	 * Whether to ask. Pure decision helper with explicit inputs, same construction as
	 * Review_Request::should_ask() — see TranslationRequestTest.
	 *
	 * @param string     $locale           The administrator's locale.
	 * @param array<int, int|string>|null $entry            Its list entry (entry_for()).
	 * @param array<int|string, mixed>  $answered         Locales already answered.
	 * @param bool       $on_plugin_screen The current screen belongs to this plugin.
	 * @param bool       $can_manage       current_user_can( 'manage_options' ).
	 * @return bool
	 */
	public static function should_ask( $locale, $entry, $answered, $on_plugin_screen, $can_manage ) {
		if ( ! $on_plugin_screen || ! $can_manage || null === $entry ) {
			return false;
		}
		// The source strings are English; a call to translate them into English is noise.
		if ( 1 === preg_match( '/^en(_|$)/', (string) $locale ) ) {
			return false;
		}
		if ( in_array( (string) $locale, array_map( 'strval', (array) $answered ), true ) ) {
			return false;
		}
		return (int) $entry[2] < self::PACK_THRESHOLD;
	}

	/**
	 * The translation page of one language. Pure. The pieces were reduced to
	 * [a-z0-9-] by the generator; checked again here because it ends up in a redirect.
	 *
	 * @param array<int, int|string> $entry A list entry.
	 * @return string '' when the entry does not form a safe URL.
	 */
	public static function translate_url( $entry ) {
		$locale = isset( $entry[0] ) ? (string) $entry[0] : '';
		$slug   = isset( $entry[1] ) ? (string) $entry[1] : '';
		if ( 1 !== preg_match( '/^[a-z0-9-]+$/i', $locale ) || 1 !== preg_match( '/^[a-z0-9-]+$/i', $slug ) ) {
			return '';
		}
		return self::PROJECT_URL . $locale . '/' . $slug . '/';
	}

	/**
	 * Print the call, once per language, to administrators only, on our own screens.
	 *
	 * @return void
	 */
	public function render() {
		$can_manage = current_user_can( 'manage_options' );
		$screen     = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$on_screen  = Review_Request::is_plugin_screen( $screen ? $screen->id : '' );
		if ( ! $can_manage || ! $on_screen ) {
			return;
		}
		$locale = get_user_locale();
		$entry  = self::entry_for( $locale, self::locales() );
		if ( ! self::should_ask( $locale, $entry, $this->answered(), $on_screen, $can_manage ) || '' === self::translate_url( $entry ) ) {
			return;
		}

		echo '<div class="notice notice-info is-dismissible gdpr-pow-translation-notice" data-gdpr-action="'
			. esc_attr( self::AJAX_DISMISS ) . '" data-gdpr-nonce="'
			. esc_attr( wp_create_nonce( self::ACTION ) ) . '"><p><strong>'
			. esc_html(
				sprintf(
					/* translators: 1: a whole number, 2: English name of the language, e.g. "French (France)". */
					__( 'Invisible Anti-Spam is %1$s%% translated into %2$s.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					number_format_i18n( (int) $entry[2] ),
					(string) $entry[3]
				)
			)
			. '</strong><br>'
			. esc_html__( 'Translations are made by volunteers on translate.wordpress.org. Once 90% of the texts are translated and approved there, WordPress installs the translation on every site that uses this language. If you speak it, a few minutes of your time make a real difference. This is the only time the plugin asks.', 'gdpr-compliant-recaptcha-for-all-forms' )
			. '</p><p><a class="button button-primary" href="' . esc_url( $this->answer_url( self::ANSWER_HELP ) )
			. '" target="_blank" rel="noopener">'
			. esc_html__( 'Help translate', 'gdpr-compliant-recaptcha-for-all-forms' )
			. '</a> <a href="' . esc_url( $this->answer_url( self::ANSWER_NO ) ) . '">'
			. esc_html__( 'No thanks', 'gdpr-compliant-recaptcha-for-all-forms' )
			. '</a></p></div>';

		// Literal script, no interpolation — same reasoning as in Review_Request::render().
		echo '<script>document.addEventListener("click",function(e){'
			. 'var b=e.target&&e.target.closest?e.target.closest(".notice-dismiss"):null;if(!b){return;}'
			. 'var n=b.closest(".gdpr-pow-translation-notice");if(!n||!window.ajaxurl||!window.fetch){return;}'
			. 'var d=new FormData();d.append("action",n.getAttribute("data-gdpr-action"));'
			. 'd.append("_wpnonce",n.getAttribute("data-gdpr-nonce"));'
			. 'window.fetch(window.ajaxurl,{method:"POST",credentials:"same-origin",body:d});});</script>';
	}

	/**
	 * Handle the two explicit answers. Both are final for the current language.
	 *
	 * @return void
	 */
	public function handle_answer() {
		if ( ! isset( $_GET[ self::ACTION ] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, self::ACTION ) ) {
			return;
		}
		$answer = sanitize_text_field( wp_unslash( $_GET[ self::ACTION ] ) );
		if ( ! in_array( $answer, array( self::ANSWER_HELP, self::ANSWER_NO ), true ) ) {
			return;
		}
		$locale = get_user_locale();
		$this->remember_answered( $locale );

		if ( self::ANSWER_HELP === $answer ) {
			$url = self::translate_url( self::entry_for( $locale, self::locales() ) );
			if ( '' !== $url ) {
				// phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- off-site URL built from a fixed prefix and two [a-z0-9-] pieces; wp_safe_redirect() would refuse it by design.
				wp_redirect( $url );
				exit;
			}
		}
	}

	/**
	 * Handle WordPress's own dismiss cross, which the inline script routes here.
	 *
	 * @return void
	 */
	public function handle_dismiss() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		check_ajax_referer( self::ACTION );
		$this->remember_answered( get_user_locale() );
		wp_send_json_success();
	}

	/**
	 * The nonce-protected URL of one answer, on the page the administrator is looking at.
	 *
	 * @param string $answer One of the ANSWER_* constants.
	 * @return string
	 */
	private function answer_url( $answer ) {
		return wp_nonce_url( add_query_arg( self::ACTION, $answer ), self::ACTION );
	}

	/**
	 * The locales answered so far.
	 *
	 * @return array<int|string, mixed>
	 */
	private function answered() {
		$stored = get_option( self::DONE, array() );
		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * Add one locale to the answered list — the one write shared by all paths.
	 *
	 * @param string $locale WordPress locale.
	 * @return void
	 */
	private function remember_answered( $locale ) {
		$answered = $this->answered();
		if ( ! in_array( (string) $locale, $answered, true ) ) {
			$answered[] = (string) $locale;
			update_option( self::DONE, $answered, false );
		}
	}
}
