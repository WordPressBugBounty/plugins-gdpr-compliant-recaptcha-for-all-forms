<?php
/**
 * Whether a risk class is armed, and the evidence the operator decides on.
 *
 * The WordPress half of the risk class (options, the 30-day tally); which request is a
 * risk request is Risk_Signatures' job. Area doc: handbuch/detection.md, "Risikoklasse".
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/detection.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Arming switches and the "would have been rejected" tally.
 */
final class Risk_Enforcement {

	/**
	 * Bookkeeping, not a setting: class => [ 'Y-m-d' => count ]. Not in the option
	 * matrix, autoload off. Deleted on uninstall with every other `gdpr_pow_` row.
	 */
	const OBSERVED = Option::PREFIX . 'risk_observed';

	/** Done flag of the one-time switch migration (bookkeeping, autoloaded). */
	const MIGRATED = Option::PREFIX . 'risk_switch_migrated';

	/** Classes the migration armed, for the one admin notice (bookkeeping). */
	const MIGRATION_NOTICE = Option::PREFIX . 'risk_switch_migration_notice';

	/** The window the number next to each switch covers. */
	const WINDOW_DAYS = 30;

	/**
	 * The arming option of a class, or '' for an unknown class.
	 *
	 * @param string $risk_class Risk_Signatures::CHECKOUT or ::REGISTRATION.
	 * @return string
	 */
	public static function option_for( string $risk_class ): string {
		$map = array(
			Risk_Signatures::CHECKOUT     => Option::POW_BLOCK_CHECKOUT_FORMS,
			Risk_Signatures::REGISTRATION => Option::POW_BLOCK_REGISTRATION_FORMS,
		);
		return isset( $map[ $risk_class ] ) ? $map[ $risk_class ] : '';
	}

	/**
	 * Is a verdict on this class enforced (blocked, counted, echo-seeded, fail2ban)?
	 * An unknown class is never armed; a request outside the class (null) is not
	 * this method's question — see observe_only().
	 *
	 * @param string $risk_class Class name.
	 * @return bool
	 */
	public static function is_armed( string $risk_class ): bool {
		// Literal constants, not option_for(): every option read in this plugin is
		// provably prefixed (tests/unit/OptionPrefixCoverageTest.php).
		if ( Risk_Signatures::CHECKOUT === $risk_class ) {
			return (bool) get_option( Option::POW_BLOCK_CHECKOUT_FORMS );
		}
		if ( Risk_Signatures::REGISTRATION === $risk_class ) {
			return (bool) get_option( Option::POW_BLOCK_REGISTRATION_FORMS );
		}
		return false;
	}

	/**
	 * THE decision: record the verdict, but enforce nothing? True only for a risk
	 * request whose class is not armed. Computed once per check_submit() (Stamp_Risk).
	 *
	 * @param string|null $risk_class The request's class, or null outside the risk class.
	 * @return bool
	 */
	public static function observe_only( ?string $risk_class ): bool {
		return null !== $risk_class && ! self::is_armed( $risk_class );
	}

	/**
	 * Counts one spam verdict that was recorded but not enforced. Storage-independent
	 * on purpose: a tally hung off stored messages goes silent exactly on sites with
	 * spam storage off (the health counter's lesson, HANDBUCH.md §12).
	 *
	 * @param string $risk_class Class name.
	 * @return void
	 */
	public static function record_observed( string $risk_class ): void {
		$ledger = get_option( self::OBSERVED, array() );
		$ledger = self::bump( is_array( $ledger ) ? $ledger : array(), $risk_class, time() );
		update_option( self::OBSERVED, $ledger, false );
	}

	/**
	 * The number next to the switch: verdicts of the last WINDOW_DAYS days.
	 *
	 * @param string $risk_class Class name.
	 * @return int
	 */
	public static function observed_count( string $risk_class ): int {
		$ledger = get_option( self::OBSERVED, array() );
		return self::sum( is_array( $ledger ) ? $ledger : array(), $risk_class, time() );
	}

	/**
	 * Pure: the ledger with one more verdict for $risk_class today, days outside the
	 * window dropped (so the option cannot grow without bound).
	 *
	 * @param array<string, mixed> $ledger     Current ledger.
	 * @param string               $risk_class Class name.
	 * @param int                  $now        Unix time.
	 * @return array<string, array<string, int>>
	 */
	public static function bump( array $ledger, string $risk_class, int $now ): array {
		$clean = array();
		foreach ( $ledger as $name => $days ) {
			if ( is_array( $days ) ) {
				$clean[ (string) $name ] = self::within_window( $days, $now );
			}
		}
		$today = gmdate( 'Y-m-d', $now );
		if ( ! isset( $clean[ $risk_class ] ) ) {
			$clean[ $risk_class ] = array();
		}
		$clean[ $risk_class ][ $today ] = ( isset( $clean[ $risk_class ][ $today ] ) ? $clean[ $risk_class ][ $today ] : 0 ) + 1;
		return $clean;
	}

	/**
	 * Pure: verdicts for $risk_class within the window.
	 *
	 * @param array<string, mixed> $ledger     Ledger.
	 * @param string               $risk_class Class name.
	 * @param int                  $now        Unix time.
	 * @return int
	 */
	public static function sum( array $ledger, string $risk_class, int $now ): int {
		if ( ! isset( $ledger[ $risk_class ] ) || ! is_array( $ledger[ $risk_class ] ) ) {
			return 0;
		}
		return (int) array_sum( self::within_window( $ledger[ $risk_class ], $now ) );
	}

	/**
	 * Pure: the day buckets of the last WINDOW_DAYS days (today included), as ints.
	 *
	 * @param array<mixed, mixed> $days 'Y-m-d' => count.
	 * @param int                 $now  Unix time.
	 * @return array<string, int>
	 */
	private static function within_window( array $days, int $now ): array {
		$cutoff = gmdate( 'Y-m-d', $now - ( self::WINDOW_DAYS - 1 ) * 86400 );
		$kept   = array();
		foreach ( $days as $day => $count ) {
			$day = (string) $day;
			if ( 1 === preg_match( '/^\d{4}-\d{2}-\d{2}$/', $day ) && $day >= $cutoff ) {
				$kept[ $day ] = (int) $count;
			}
		}
		return $kept;
	}

	/**
	 * ONE-TIME MIGRATION for installations that existed before the risk class. Until
	 * then no shipped default contained a catalog line, so a catalog line already in the
	 * scope was put there by the operator (analysis mode — the readme advertised exactly
	 * that for EDD, WP-Members, BuddyPress). Such a class is ARMED, so the block he
	 * configured survives the update; everything else stays at the default OFF.
	 *
	 * Runs on every load until done (RCM_Main::activate(), outside the version gate, like
	 * Blocked_Values_Migration) and BEFORE admin_init, i.e. before Scope_Sync can add this
	 * version's own risk lines. A fresh install sets the flag without looking
	 * (mark_migrated_fresh_install()).
	 *
	 * @return void
	 */
	public static function maybe_migrate(): void {
		if ( get_option( self::MIGRATED ) ) {
			return;
		}
		$armed = self::classes_to_arm(
			(string) get_option( Option::POW_EXPLICIT_ACTION, '' ),
			(string) get_option( Option::POW_PARAMETER_PATTERN, '' ),
			(string) get_option( Option::POW_REST_ROUTES, '' )
		);
		foreach ( $armed as $risk_class ) {
			if ( Risk_Signatures::CHECKOUT === $risk_class ) {
				update_option( Option::POW_BLOCK_CHECKOUT_FORMS, true );
			} elseif ( Risk_Signatures::REGISTRATION === $risk_class ) {
				update_option( Option::POW_BLOCK_REGISTRATION_FORMS, true );
			}
		}
		if ( $armed ) {
			update_option( self::MIGRATION_NOTICE, $armed, false );
		}
		update_option( self::MIGRATED, 1, true ); // Last, so an interrupted run repeats.
	}

	/**
	 * Pure: which classes have a catalog line in the given scope values.
	 *
	 * @param string $action_list  POW_EXPLICIT_ACTION.
	 * @param string $pattern_list POW_PARAMETER_PATTERN.
	 * @param string $route_list   POW_REST_ROUTES.
	 * @return string[]
	 */
	public static function classes_to_arm( string $action_list, string $pattern_list, string $route_list ): array {
		$lists = array(
			Risk_Signatures::KIND_ACTION  => Scope_Sync::parse_lines( $action_list ),
			Risk_Signatures::KIND_PATTERN => Scope_Sync::parse_lines( $pattern_list ),
			Risk_Signatures::KIND_ROUTE   => Scope_Sync::parse_lines( $route_list ),
		);
		$armed = array();
		foreach ( Risk_Signatures::catalog() as $entry ) {
			if ( in_array( $entry['line'], $lists[ $entry['kind'] ], true ) && ! in_array( $entry['class'], $armed, true ) ) {
				$armed[] = $entry['class'];
			}
		}
		return $armed;
	}

	/**
	 * A fresh install has nothing to preserve: flag set, nothing armed.
	 *
	 * @return void
	 */
	public static function mark_migrated_fresh_install(): void {
		add_option( self::MIGRATED, 1 );
	}

	/**
	 * The one notice after the migration armed something — shown once, to an admin.
	 *
	 * @return void
	 */
	public static function render_migration_notice(): void {
		$armed = get_option( self::MIGRATION_NOTICE );
		if ( ! is_array( $armed ) || ! $armed || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		delete_option( self::MIGRATION_NOTICE );
		echo '<div class="notice notice-info is-dismissible"><p>' . esc_html__( 'GDPR ReCaptcha: your monitored forms already included checkout or registration forms. Blocking spam on them stays on, as before this update — see Settings, Spam Processing.', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</p></div>';
	}
}
