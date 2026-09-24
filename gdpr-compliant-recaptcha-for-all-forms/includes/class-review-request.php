<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.

/**
 * The one-off, dismissible request for a WordPress.org review — shown to an operator the
 * plugin has demonstrably worked for, once, and never again after any answer.
 *
 * Same shape as Gibberish_Notice (handbuch/gibberish.md): dismissible, capability-gated,
 * and it never touches a setting by itself.
 *
 * TRIGGER: A HIGH-WATER MARK, NOT A COUNTER. There is no cumulative spam counter in this
 * plugin — Stamp::increment_spam_counter() only writes 5-minute transients for the
 * under-attack detection, and turning those into a lifetime total would put a write on
 * the front-end path. Instead, whenever an administrator opens one of THIS plugin's admin
 * pages, the current spam-folder stock (Option::get_rows( '', 2 )) is read at most once a
 * day and the stored mark moves to max( stored, current ). That costs nothing on the
 * front end, and emptying the spam folder does not reset the threshold.
 *
 * "CAUGHT", NOT "BLOCKED", in the sentence above — the mark counts submissions SORTED into
 * the spam folder, and whether one was also refused depends on the operator's settings. On
 * a site running in flag-only or analysis mode nothing is blocked at all, so "blocked"
 * would be false in the one sentence that carries the whole argument for a review.
 *
 * THE KNOWN WEAKNESS OF THAT MARK, stated here because it is deliberate and not a bug:
 * the mark hangs on STORED messages. Whoever switches POW_SAVE_SPAM off, or lets the
 * automatic spam deletion (POW_CRON_DELETE_SPAM) run, sees the count plateau below the
 * threshold or stay at zero — the request then never appears at all. That is accepted:
 * the worst case is that we do not ask. It also means the number in the text understates
 * the work done; it can never overstate it, which is the direction that matters when the
 * sentence is an argument for a review.
 *
 * WHERE IT IS ALLOWED TO APPEAR: on this plugin's own admin screens only — not on the
 * dashboard, not on anyone else's page. wordpress.org guideline 11 requires notices to be
 * "limited in scope… contextually or only on the plugin's setting page", so this is a
 * policy boundary, not taste. Guideline 9 forbids pressuring for reviews, hence: no
 * countdown, no reward, no repetition, and every one of the three answers is final.
 *
 * THE CORE DISMISS CROSS IS HANDLED TOO. WordPress's own "is-dismissible" cross is
 * client-side only — a notice that relies on it alone is back on the next page load, and
 * that is the classic defect of this kind of notice. The inline script below turns that
 * cross into the same permanent answer via admin-ajax (AJAX_DISMISS, nonce-checked). If
 * JavaScript is off, the three explicit links still work.
 *
 * OPTION KEYS (all three live on Option, so uninstall.php's reflection over Option's
 * constants removes them; see there):
 * - Option::POW_FIRST_SEEN_AT      — install date, a unix timestamp. NOT the pre-existing
 *                                    boolean Option::POW_INSTALLED, which only records
 *                                    that the tables were created; this one is a date and
 *                                    exists solely to measure standing time.
 * - Option::POW_SPAM_HIGH_WATER    — the mark described above.
 * - Option::POW_REVIEW_REQUEST_DONE — asked and answered, in any of the four ways.
 */
final class Review_Request {

	/**
	 * How long the plugin must have been installed before it asks. An operator who has
	 * had it a month has an opinion worth writing down; one who installed it yesterday
	 * does not.
	 *
	 * @var int
	 */
	const MIN_DAYS = 30;

	/**
	 * How many submissions must have been sorted into the spam folder. The number in the
	 * notice is also the whole argument for the review, so it has to be one that speaks
	 * for itself.
	 *
	 * @var int
	 */
	const MIN_SPAM = 100;

	/** The review form on wordpress.org. */
	const REVIEW_URL = 'https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/reviews/#new-post';

	/** The query argument carrying the answer, and the nonce action of all four paths. */
	const ACTION = 'gdpr_pow_review_request';

	/** The admin-ajax action behind the core dismiss cross. */
	const AJAX_DISMISS = 'gdpr_pow_review_dismiss';

	/** Answer: off to the review form (the marker is set on the way out). */
	const ANSWER_REVIEW = 'review';

	/** Answer: already reviewed. */
	const ANSWER_DID = 'did';

	/** Answer: no. */
	const ANSWER_NO = 'no';

	/** Transient throttling the spam-stock query to once a day. */
	const CACHE = 'gdpr_pow_review_stock_seen';

	/**
	 * Remember when this installation first ran a version gate. Called from activate(),
	 * next to Gibberish_Notice::remember_upgrade().
	 *
	 * add_option(), not update_option(): the date must never move once written. For an
	 * installation that predates this option the date of the NEXT upgrade is the starting
	 * point — deliberately not back-dated, because the plugin never knew the real one and
	 * a guessed date would make the standing-time condition a lie.
	 *
	 * @return void
	 */
	public static function remember_install_date() {
		add_option( Option::POW_FIRST_SEEN_AT, (string) time(), '', false );
	}

	/**
	 * Wire the notice, the three links and the dismiss cross.
	 *
	 * @return void
	 */
	public function run() {
		add_action( 'admin_notices', array( $this, 'render' ) );
		add_action( 'admin_init', array( $this, 'handle_answer' ) );
		add_action( 'wp_ajax_' . self::AJAX_DISMISS, array( $this, 'handle_dismiss' ) );
	}

	/**
	 * Whether the request may be shown. Pure decision helper with explicit inputs (no WP
	 * calls, no $this) so the whole condition list is unit-testable in one place — same
	 * construction as Stamp::should_quarantine(), see ReviewRequestTest.
	 *
	 * The caller wires the WP-dependent inputs (option reads, the screen, the capability).
	 *
	 * @param int  $days_installed   Standing time in whole days (0 if unknown).
	 * @param int  $spam_seen        The high-water mark of spam-sorted submissions.
	 * @param bool $already_answered The operator has answered once — then never again.
	 * @param bool $on_plugin_screen The current screen belongs to this plugin.
	 * @param bool $can_manage       current_user_can( 'manage_options' ).
	 * @return bool
	 */
	public static function should_ask( $days_installed, $spam_seen, $already_answered, $on_plugin_screen, $can_manage ) {
		if ( $already_answered || ! $on_plugin_screen || ! $can_manage ) {
			return false;
		}
		return (int) $days_installed >= self::MIN_DAYS && (int) $spam_seen >= self::MIN_SPAM;
	}

	/**
	 * The mark's only rule: it never goes down. Pure, so "the operator emptied the spam
	 * folder" is an executable case rather than a claim.
	 *
	 * @param int $stored  The mark stored so far.
	 * @param int $current The stock counted right now.
	 * @return int
	 */
	public static function advance_mark( $stored, $current ) {
		return max( (int) $stored, (int) $current );
	}

	/**
	 * Whole days between an installation timestamp and now. Pure. A missing, zero or
	 * future timestamp yields 0 — an unknown standing time must never satisfy MIN_DAYS.
	 *
	 * @param int $installed_at Unix timestamp, 0 when unknown.
	 * @param int $now          Unix timestamp of "now".
	 * @return int
	 */
	public static function days_since( $installed_at, $now ) {
		$installed_at = (int) $installed_at;
		$now          = (int) $now;
		if ( $installed_at <= 0 || $now <= $installed_at ) {
			return 0;
		}
		// 86400 = DAY_IN_SECONDS, spelled out so this helper stays runnable without
		// WordPress — which is the whole point of it being pure.
		return (int) floor( ( $now - $installed_at ) / 86400 );
	}

	/**
	 * Whether a screen id belongs to this plugin. Pure. Every one of our screens carries
	 * the page slug in its id (toplevel_page_gdpr_pow_messages,
	 * settings_page_gdpr_pow_options, …), and every one of our page slugs starts with
	 * Option::PREFIX — so the prefix is the whole test, and no list of screen ids has to
	 * be kept in step with the menu.
	 *
	 * @param string $screen_id The current screen id ('' when there is none).
	 * @return bool
	 */
	public static function is_plugin_screen( $screen_id ) {
		return '' !== (string) $screen_id && false !== strpos( (string) $screen_id, Option::PREFIX );
	}

	/**
	 * Print the request, at most once per installation, to administrators only.
	 *
	 * The cheap conditions are checked before the high-water read on purpose: that read
	 * is the only expensive input, and on the overwhelming majority of page loads one of
	 * the cheap ones already says no. The authoritative decision is still the single
	 * should_ask() call below, so there is one condition list, not two.
	 *
	 * @return void
	 */
	public function render() {
		$can_manage = current_user_can( 'manage_options' );
		$answered   = (bool) get_option( Option::POW_REVIEW_REQUEST_DONE );
		$screen     = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$on_screen  = self::is_plugin_screen( $screen ? $screen->id : '' );

		if ( ! $can_manage || $answered || ! $on_screen ) {
			return;
		}
		$days = self::days_since( get_option( Option::POW_FIRST_SEEN_AT ), time() );
		if ( $days < self::MIN_DAYS ) {
			return;
		}
		$spam = $this->high_water_mark();
		if ( ! self::should_ask( $days, $spam, $answered, $on_screen, $can_manage ) ) {
			return;
		}

		echo '<div class="notice notice-info is-dismissible gdpr-pow-review-notice" data-gdpr-action="'
			. esc_attr( self::AJAX_DISMISS ) . '" data-gdpr-nonce="'
			. esc_attr( wp_create_nonce( self::ACTION ) ) . '"><p><strong>'
			. esc_html(
				sprintf(
					/* translators: %s: number of spam submissions, already formatted for the locale. */
					__( 'Invisible Anti-Spam has caught %s spam submissions on this site.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					number_format_i18n( $spam )
				)
			)
			. '</strong><br>'
			. esc_html__( 'If that saved you some work, a short review on WordPress.org helps other site owners judge whether the plugin is for them. The plugin behaves exactly the same either way, and this is the only time it asks.', 'gdpr-compliant-recaptcha-for-all-forms' )
			. '</p><p><a class="button button-primary" href="' . esc_url( $this->answer_url( self::ANSWER_REVIEW ) )
			. '" target="_blank" rel="noopener">'
			. esc_html__( 'Leave a review', 'gdpr-compliant-recaptcha-for-all-forms' )
			. '</a> <a href="' . esc_url( $this->answer_url( self::ANSWER_DID ) ) . '">'
			. esc_html__( 'I already did', 'gdpr-compliant-recaptcha-for-all-forms' )
			. '</a> <a href="' . esc_url( $this->answer_url( self::ANSWER_NO ) ) . '">'
			. esc_html__( 'No thanks', 'gdpr-compliant-recaptcha-for-all-forms' )
			. '</a></p></div>';

		// Deliberately a literal script with no interpolation: the action and the nonce
		// travel in the data attributes above, so nothing here needs escaping and nothing
		// here can be got at from a translation.
		echo '<script>document.addEventListener("click",function(e){'
			. 'var b=e.target&&e.target.closest?e.target.closest(".notice-dismiss"):null;if(!b){return;}'
			. 'var n=b.closest(".gdpr-pow-review-notice");if(!n||!window.ajaxurl||!window.fetch){return;}'
			. 'var d=new FormData();d.append("action",n.getAttribute("data-gdpr-action"));'
			. 'd.append("_wpnonce",n.getAttribute("data-gdpr-nonce"));'
			. 'window.fetch(window.ajaxurl,{method:"POST",credentials:"same-origin",body:d});});</script>';
	}

	/**
	 * Handle the three explicit answers. All of them are final; only the review link also
	 * leaves for wordpress.org.
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
		if ( ! in_array( $answer, array( self::ANSWER_REVIEW, self::ANSWER_DID, self::ANSWER_NO ), true ) ) {
			return;
		}
		$this->remember_answered();

		if ( self::ANSWER_REVIEW === $answer ) {
			// The link carries target="_blank", so this redirect happens in the new tab
			// and the operator keeps the page he was on.
			// phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- a hardcoded constant off-site URL; wp_safe_redirect() would refuse it by design.
			wp_redirect( self::REVIEW_URL );
			exit;
		}
	}

	/**
	 * Handle WordPress's own dismiss cross, which the inline script above routes here.
	 *
	 * @return void
	 */
	public function handle_dismiss() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		check_ajax_referer( self::ACTION );
		$this->remember_answered();
		wp_send_json_success();
	}

	/**
	 * The nonce-protected URL of one answer, on the page the operator is looking at.
	 *
	 * @param string $answer One of the three ANSWER_* constants.
	 * @return string
	 */
	private function answer_url( $answer ) {
		return wp_nonce_url( add_query_arg( self::ACTION, $answer ), self::ACTION );
	}

	/**
	 * Record that the request has been answered — the one write shared by all four paths.
	 *
	 * Autoloaded on purpose (unlike the other two keys): render() reads it on every single
	 * admin page load, so an extra query per page would be the price of tidiness.
	 *
	 * @return void
	 */
	private function remember_answered() {
		update_option( Option::POW_REVIEW_REQUEST_DONE, '1' );
	}

	/**
	 * Read the spam stock at most once a day and move the mark up. Returns the mark, not
	 * the stock — see the class docblock for why those differ.
	 *
	 * @return int
	 */
	private function high_water_mark() {
		$stored = (int) get_option( Option::POW_SPAM_HIGH_WATER, 0 );
		if ( get_transient( self::CACHE ) ) {
			return $stored;
		}
		// Set before the query, not after: if the count fails or is slow, the next page
		// load must not try again immediately.
		set_transient( self::CACHE, '1', DAY_IN_SECONDS );

		$mark = self::advance_mark( $stored, (int) Option::get_rows( '', 2 ) );
		if ( $mark !== $stored ) {
			update_option( Option::POW_SPAM_HIGH_WATER, $mark, false );
		}
		return $mark;
	}
}
