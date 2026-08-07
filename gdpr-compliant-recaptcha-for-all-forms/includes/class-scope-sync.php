<?php
/**
 * Keeps the monitored-submission scope (POW_EXPLICIT_ACTION / POW_PARAMETER_PATTERN /
 * POW_REST_ROUTES) in sync with the form builders that are actually active.
 *
 * Why this exists: those three options are seeded ONCE at install (gated by
 * POW_INSTALLED, see Settings_Menu::prepare_options()) with the defaults for the
 * builders present THEN. A builder installed/activated LATER therefore never entered
 * the scope and its submissions went unchecked — a silent spam gap.
 *
 * Design (reviewed): a LEDGER (POW_SEEDED_ACTIONS/POW_SEEDED_PATTERNS/POW_SEEDED_ROUTES)
 * records which default entries have already been OFFERED. On each admin request the
 * reconcile step
 * adds any default NOT yet in the ledger to the scope (once) and remembers it, but
 * NEVER re-adds an entry the admin removed and NEVER touches the admin's own entries.
 *
 * Conservative first-run: when the ledger is still absent (existing install upgrading
 * to this version) it is initialised to the FULL current default set WITHOUT changing
 * the scope — so a default the admin had removed is never silently re-added. The
 * pre-existing gap (a builder that was activated after install and is currently
 * unmonitored) is closed via an explicit, dismissible one-click notice instead
 * (render_notices() / handle_actions()), so nothing is re-monitored behind the admin's
 * back — a suddenly-blocking form would otherwise be hard to trace back to this plugin.
 *
 * The reconcile() decision is pure and unit-tested (tests/unit/ScopeSyncReconcileTest.php);
 * everything else is thin WordPress glue (admin-context only, no frontend cost).
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Self-maintaining monitored-scope synchroniser.
 */
final class Scope_Sync {

	/** Transient key holding entries auto-added this request, for the admin notice. */
	const ADDED_TRANSIENT = 'gdpr_pow_scope_added';

	/**
	 * The three synced domains: [ scope-option, ledger-option, defaults-callable ].
	 *
	 * @return array<int, array{0:string,1:string,2:callable}>
	 */
	private static function domains() {
		return array(
			array( Option::POW_EXPLICIT_ACTION, Option::POW_SEEDED_ACTIONS, array( Settings_Menu::class, 'get_default_ajax_actions' ) ),
			array( Option::POW_PARAMETER_PATTERN, Option::POW_SEEDED_PATTERNS, array( Settings_Menu::class, 'get_default_recognition_patterns' ) ),
			array( Option::POW_REST_ROUTES, Option::POW_SEEDED_ROUTES, array( Settings_Menu::class, 'get_default_rest_routes' ) ),
		);
	}

	public function __construct() {
		add_action( 'admin_init', array( $this, 'handle_actions' ), 5 );
		add_action( 'admin_init', array( $this, 'sync' ), 6 );
		add_action( 'admin_notices', array( $this, 'render_notices' ) );
	}

	/**
	 * Split a newline-separated option value into a trimmed, non-empty, de-duplicated
	 * list of lines. Mirrors the PREG_SPLIT_NO_EMPTY parsing the read paths use.
	 *
	 * @param mixed $value Raw option value.
	 * @return string[]
	 */
	public static function parse_lines( $value ) {
		if ( ! is_string( $value ) || '' === $value ) {
			return array();
		}
		$lines  = preg_split( '/\r\n|\n|\r/', $value, -1, PREG_SPLIT_NO_EMPTY );
		$result = array();
		foreach ( (array) $lines as $line ) {
			$line = trim( $line );
			if ( '' !== $line && ! in_array( $line, $result, true ) ) {
				$result[] = $line;
			}
		}
		return $result;
	}

	/**
	 * Serialise a list of lines back into a newline-separated option value.
	 *
	 * @param string[] $lines Lines.
	 * @return string
	 */
	public static function to_lines( array $lines ) {
		return implode( "\n", $lines );
	}

	/**
	 * PURE reconcile step. For every default not yet in the ledger: add it to the scope
	 * if absent (and to the "added" list), and record it in the ledger. Never removes
	 * anything; never re-adds a default that is already in the ledger (admin-removed).
	 *
	 * @param string[] $defaults Currently detected default entries.
	 * @param string[] $ledger   Entries already offered.
	 * @param string[] $scope    Current stored scope.
	 * @return array{0:string[],1:string[],2:string[]} [ scope', ledger', added ].
	 */
	public static function reconcile( array $defaults, array $ledger, array $scope ) {
		$added = array();
		foreach ( $defaults as $entry ) {
			if ( in_array( $entry, $ledger, true ) ) {
				continue;
			}
			$ledger[] = $entry;
			if ( ! in_array( $entry, $scope, true ) ) {
				$scope[] = $entry;
				$added[] = $entry;
			}
		}
		return array( $scope, $ledger, $added );
	}

	/**
	 * Run on every admin request (cheap, idempotent). Establishes the ledger on first
	 * run without touching the scope, then auto-adds any genuinely new default (a
	 * builder activated after this code went live).
	 */
	public function sync() {
		$all_added = array();
		foreach ( self::domains() as $domain ) {
			list( $scope_key, $ledger_key, $defaults_cb ) = $domain;
			$defaults                                     = self::parse_lines( call_user_func( $defaults_cb ) );

			$ledger_raw = get_option( $ledger_key, false );
			if ( false === $ledger_raw ) {
				// Conservative first-run: everything currently detected counts as already
				// offered; the scope is left exactly as the admin has it.
				update_option( $ledger_key, self::to_lines( $defaults ) );
				continue;
			}

			$ledger = self::parse_lines( $ledger_raw );
			$scope  = self::parse_lines( get_option( $scope_key, '' ) );

			list( $scope2, $ledger2, $added ) = self::reconcile( $defaults, $ledger, $scope );

			if ( $ledger2 !== $ledger ) {
				update_option( $ledger_key, self::to_lines( $ledger2 ) );
			}
			if ( ! empty( $added ) ) {
				update_option( $scope_key, self::to_lines( $scope2 ) );
				$all_added = array_merge( $all_added, $added );
			}
		}

		if ( ! empty( $all_added ) ) {
			set_transient( self::ADDED_TRANSIENT, $all_added, MINUTE_IN_SECONDS );
		}
	}

	/**
	 * Default entries that belong to a currently-active builder but are NOT in the
	 * stored scope — the pre-existing gap the one-time notice offers to close.
	 *
	 * @return string[]
	 */
	public static function missing_defaults() {
		$missing = array();
		foreach ( self::domains() as $domain ) {
			list( $scope_key, , $defaults_cb ) = $domain;
			$defaults                          = self::parse_lines( call_user_func( $defaults_cb ) );
			$scope                             = self::parse_lines( get_option( $scope_key, '' ) );
			foreach ( $defaults as $entry ) {
				if ( ! in_array( $entry, $scope, true ) ) {
					$missing[] = $entry;
				}
			}
		}
		return $missing;
	}

	/**
	 * Handle the one-click "add missing" / "dismiss" links from the notice. Runs before
	 * sync() so the scope is settled before the same request renders anything.
	 */
	public function handle_actions() {
		if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonce is verified via check_admin_referer() immediately below before any state change.
		if ( isset( $_GET['gdpr_pow_scope_add'] ) ) {
			check_admin_referer( 'gdpr_pow_scope_add' );
			foreach ( self::domains() as $domain ) {
				list( $scope_key, $ledger_key, $defaults_cb ) = $domain;
				$defaults                                     = self::parse_lines( call_user_func( $defaults_cb ) );
				$scope                                        = self::parse_lines( get_option( $scope_key, '' ) );
				$ledger                                       = self::parse_lines( get_option( $ledger_key, '' ) );
				$changed                                      = false;
				foreach ( $defaults as $entry ) {
					if ( ! in_array( $entry, $scope, true ) ) {
						$scope[] = $entry;
						$changed = true;
					}
					if ( ! in_array( $entry, $ledger, true ) ) {
						$ledger[] = $entry;
					}
				}
				if ( $changed ) {
					update_option( $scope_key, self::to_lines( $scope ) );
				}
				update_option( $ledger_key, self::to_lines( $ledger ) );
			}
			update_option( Option::POW_SCOPE_NOTICE_DISMISSED, '1' );
			self::redirect_clean();
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonce is verified via check_admin_referer() immediately below before any state change.
		if ( isset( $_GET['gdpr_pow_scope_dismiss'] ) ) {
			check_admin_referer( 'gdpr_pow_scope_dismiss' );
			update_option( Option::POW_SCOPE_NOTICE_DISMISSED, '1' );
			self::redirect_clean();
		}
	}

	/**
	 * Redirect back to the current page with the plugin's own query args stripped, so a
	 * reload does not re-trigger the action.
	 */
	private static function redirect_clean() {
		$url = remove_query_arg( array( 'gdpr_pow_scope_add', 'gdpr_pow_scope_dismiss', '_wpnonce' ) );
		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * Show two notices: (1) what was just auto-added (a newly-activated builder), and
	 * (2) the one-time consent notice for pre-existing unmonitored builders.
	 */
	public function render_notices() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$added = get_transient( self::ADDED_TRANSIENT );
		if ( is_array( $added ) && ! empty( $added ) ) {
			delete_transient( self::ADDED_TRANSIENT );
			echo '<div class="notice notice-info is-dismissible"><p>';
			echo esc_html__( 'Invisible Anti-Spam: a newly detected form now has spam protection applied. Covered submission types added:', 'gdpr-compliant-recaptcha-for-all-forms' );
			echo ' <code>' . esc_html( implode( ', ', $added ) ) . '</code>.</p></div>';
		}

		if ( get_option( Option::POW_SCOPE_NOTICE_DISMISSED ) ) {
			return;
		}
		$missing = self::missing_defaults();
		if ( empty( $missing ) ) {
			return;
		}
		$add_url     = wp_nonce_url( add_query_arg( 'gdpr_pow_scope_add', '1' ), 'gdpr_pow_scope_add' );
		$dismiss_url = wp_nonce_url( add_query_arg( 'gdpr_pow_scope_dismiss', '1' ), 'gdpr_pow_scope_dismiss' );
		echo '<div class="notice notice-warning is-dismissible"><p>';
		echo esc_html__( 'Invisible Anti-Spam: these form-submission types appear active on your site but are not yet covered by the spam check:', 'gdpr-compliant-recaptcha-for-all-forms' );
		echo ' <code>' . esc_html( implode( ', ', $missing ) ) . '</code>.</p><p>';
		echo '<a class="button button-primary" href="' . esc_url( $add_url ) . '">' . esc_html__( 'Add to spam check', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $dismiss_url ) . '">' . esc_html__( 'Dismiss', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</a>';
		echo '</p></div>';
	}
}
