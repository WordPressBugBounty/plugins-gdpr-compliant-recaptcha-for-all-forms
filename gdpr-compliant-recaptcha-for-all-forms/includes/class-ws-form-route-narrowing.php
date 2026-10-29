<?php
/**
 * One-off narrowing of the WS Form REST line earlier versions seeded into "Apply on REST
 * route" (POW_REST_ROUTES): `ws-form/v1/*` becomes `ws-form/v1/submit`.
 *
 * WHY. The namespace wildcard covered all 59 POST paths of WS Form's REST namespace, and
 * 58 of them are the plugin's own admin API (form, field, group and section saves,
 * publish, settings). Measured 2026-10-09 on wp-env: an administrator editing a form in
 * the WS Form backend got HTTP 422 `no_pow:no_token` on every save unless his address had
 * a fresh proof-of-work row from a frontend visit — a false block of the operator's own
 * backend. The only anonymous POST route is `/submit/` (ws-form 1.12.0,
 * api/class-ws-form-api.php:332). The default getter seeds the exact line since then;
 * Scope_Sync deliberately never changes an existing scope (handbuch/gate.md), so the
 * line is replaced here, once.
 *
 * WHAT IS TOUCHED, AND WHAT NEVER IS:
 *  - Exactly the line `ws-form/v1/*`, compared after trim(), is replaced IN PLACE by
 *    `ws-form/v1/submit` (or simply dropped when that line is already in the scope).
 *    Every other line keeps its bytes, order and terminator — `ws-form/v1/submit/*` or
 *    any other spelling is the operator's own decision and stays.
 *  - Nothing is written when the line is not there: a no-op must be a real no-op. An
 *    operator who had removed the wildcard does NOT get the narrow line added.
 *  - Scope_Sync's ledger (POW_SEEDED_ROUTES) gets BOTH lines if it exists and lacks
 *    them: the new default must not be offered again on a site whose operator removed
 *    WS Form's line, and the old one stays recorded as offered. A MISSING ledger is left
 *    alone, for the reason Cart_Seed_Removal gives (creating it would switch Scope_Sync's
 *    first run into reconcile mode).
 *
 * Placement as Cart_Seed_Removal: RCM_Main::activate(), every load, outside the version
 * gate, own done flag set last; options are per site, so each site of a network is
 * migrated on its own first load.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/seeds.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Replaces the formerly seeded WS Form namespace wildcard by the submit endpoint.
 */
final class Ws_Form_Route_Narrowing {

	/** Done flag. Bookkeeping, not a setting; prefixed, so uninstall.php removes it. */
	const DONE = Option::PREFIX . 'pow_ws_form_route_narrowed';

	/** The line earlier versions seeded, verbatim. */
	const WILDCARD_LINE = 'ws-form/v1/*';

	/** The line that replaces it — WS Form's one anonymous POST route. */
	const SUBMIT_LINE = 'ws-form/v1/submit';

	/**
	 * Run once per site.
	 */
	public static function maybe_run(): void {
		if ( get_option( self::DONE ) ) {
			return;
		}

		$routes = get_option( Option::POW_REST_ROUTES, null );
		if ( is_string( $routes ) ) {
			$narrowed = self::narrowed( $routes );
			if ( $narrowed !== $routes ) {
				update_option( Option::POW_REST_ROUTES, $narrowed );
			}
		}

		$ledger = get_option( Option::POW_SEEDED_ROUTES, false );
		if ( false !== $ledger ) {
			$merged = self::ledger_with_both_lines( (string) $ledger );
			if ( $merged !== (string) $ledger ) {
				update_option( Option::POW_SEEDED_ROUTES, $merged );
			}
		}

		update_option( self::DONE, 1, true ); // Last, so an interrupted run repeats.
	}

	/**
	 * The route value with the wildcard line replaced in place. Pure.
	 *
	 * Split keeping each line's own terminator, so every other line comes back byte for
	 * byte. When the submit line is already present, the wildcard line is dropped instead
	 * (and, if it was the last line, the break before it with it).
	 *
	 * @param string $value Stored POW_REST_ROUTES.
	 * @return string
	 */
	public static function narrowed( string $value ): string {
		$parts = preg_split( '/(\r\n|\n|\r)/', $value, -1, PREG_SPLIT_DELIM_CAPTURE );
		if ( false === $parts ) {
			return $value;
		}
		$has_submit = false;
		$count      = count( $parts );
		for ( $i = 0; $i < $count; $i += 2 ) {
			if ( self::SUBMIT_LINE === trim( $parts[ $i ] ) ) {
				$has_submit = true;
			}
		}
		$kept    = array();
		$changed = false;
		for ( $i = 0; $i < $count; $i += 2 ) {
			$line       = $parts[ $i ];
			$terminator = isset( $parts[ $i + 1 ] ) ? $parts[ $i + 1 ] : '';
			if ( self::WILDCARD_LINE === trim( $line ) ) {
				$changed = true;
				if ( $has_submit ) {
					if ( '' === $terminator && ! empty( $kept ) ) {
						$kept[ count( $kept ) - 1 ][1] = '';
					}
					continue;
				}
				$has_submit = true; // A second wildcard line is dropped, not doubled.
				$kept[]     = array( self::SUBMIT_LINE, $terminator );
				continue;
			}
			$kept[] = array( $line, $terminator );
		}
		if ( ! $changed ) {
			return $value;
		}
		$out = '';
		foreach ( $kept as $pair ) {
			$out .= $pair[0] . $pair[1];
		}
		return $out;
	}

	/**
	 * The Scope_Sync ledger with both lines in it. Pure; same line format as
	 * Scope_Sync::to_lines().
	 *
	 * @param string $ledger Stored POW_SEEDED_ROUTES.
	 * @return string Unchanged when both lines are already there.
	 */
	public static function ledger_with_both_lines( string $ledger ): string {
		$lines   = Scope_Sync::parse_lines( $ledger );
		$missing = array_values( array_diff( array( self::WILDCARD_LINE, self::SUBMIT_LINE ), $lines ) );
		if ( empty( $missing ) ) {
			return $ledger;
		}
		return Scope_Sync::to_lines( array_merge( $lines, $missing ) );
	}
}
