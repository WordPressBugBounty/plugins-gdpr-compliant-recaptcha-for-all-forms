<?php
/**
 * One-off removal of the two WooCommerce CART lines that earlier versions seeded into
 * "Apply on pattern" (POW_PARAMETER_PATTERN).
 *
 * WHY. The shopping cart is not checked any more (owner decision 2026-10, handbuch/
 * seeds.md): real shoppers on slow devices clicked "Add to cart" before the proof of work
 * had finished and were answered with HTTP 422 plus the spam overlay. Dropping the lines
 * from Settings_Menu::get_default_recognition_patterns() only helps new installations —
 * Scope_Sync deliberately never removes a default from an existing scope (handbuch/
 * gate.md). So the lines are removed here, once.
 *
 * WHAT IS TOUCHED, AND WHAT NEVER IS:
 *  - Exactly the two lines in CART_LINES, compared after trim(). Every other line keeps
 *    its bytes, its order and its line terminator — a hand-written cart line with any
 *    other spelling (an extra field, a different value) is the operator's own decision
 *    and stays.
 *  - Nothing is written when neither line is present: a no-op must be a real no-op.
 *  - Scope_Sync's ledger (POW_SEEDED_PATTERNS) gets the two lines appended if it exists
 *    and lacks them, so no later reconcile can ever re-add them. A MISSING ledger is left
 *    alone: Scope_Sync's first run initialises it conservatively, and creating it here
 *    would switch that run into reconcile mode, which adds every other default to the
 *    scope behind the operator's back.
 *
 * Same placement as Blocked_Values_Migration (RCM_Main::activate(), every load, outside
 * the version gate, own done flag set last) — reasoning in handbuch/admin.md.
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
 * Removes the formerly seeded WooCommerce cart lines from the monitored patterns.
 */
final class Cart_Seed_Removal {

	/** Done flag. Bookkeeping, not a setting; prefixed, so uninstall.php removes it. */
	const DONE = Option::PREFIX . 'pow_cart_seed_removed';

	/** The two lines earlier versions seeded, verbatim. */
	const CART_LINES = array(
		'{"add-to-cart":null}',
		'{"wc-ajax":"add_to_cart","product_id":null}',
	);

	/**
	 * Run once per installation.
	 */
	public static function maybe_run(): void {
		if ( get_option( self::DONE ) ) {
			return;
		}

		$pattern = get_option( Option::POW_PARAMETER_PATTERN, null );
		if ( is_string( $pattern ) ) {
			$remaining = self::without_cart_lines( $pattern );
			if ( $remaining !== $pattern ) {
				update_option( Option::POW_PARAMETER_PATTERN, $remaining );
			}
		}

		$ledger = get_option( Option::POW_SEEDED_PATTERNS, false );
		if ( false !== $ledger ) {
			$merged = self::ledger_with_cart_lines( (string) $ledger );
			if ( $merged !== (string) $ledger ) {
				update_option( Option::POW_SEEDED_PATTERNS, $merged );
			}
		}

		update_option( self::DONE, 1, true ); // Last, so an interrupted run repeats.
	}

	/**
	 * The pattern value without the two cart lines. Pure.
	 *
	 * Split keeping each line's own terminator, so every surviving line comes back byte
	 * for byte — including CRLF/CR endings, blank lines and lines that are not JSON. When
	 * the last line is removed, the terminator before it goes too, so no stray trailing
	 * break is left behind.
	 *
	 * @param string $value Stored POW_PARAMETER_PATTERN.
	 * @return string
	 */
	public static function without_cart_lines( string $value ): string {
		$parts = preg_split( '/(\r\n|\n|\r)/', $value, -1, PREG_SPLIT_DELIM_CAPTURE );
		if ( false === $parts ) {
			return $value;
		}
		$kept    = array();
		$removed = false;
		$count   = count( $parts );
		for ( $i = 0; $i < $count; $i += 2 ) {
			$line       = $parts[ $i ];
			$terminator = isset( $parts[ $i + 1 ] ) ? $parts[ $i + 1 ] : '';
			if ( in_array( trim( $line ), self::CART_LINES, true ) ) {
				$removed = true;
				if ( '' === $terminator && ! empty( $kept ) ) {
					// Last line removed: drop the break that introduced it.
					$kept[ count( $kept ) - 1 ][1] = '';
				}
				continue;
			}
			$kept[] = array( $line, $terminator );
		}
		if ( ! $removed ) {
			return $value;
		}
		$out = '';
		foreach ( $kept as $pair ) {
			$out .= $pair[0] . $pair[1];
		}
		return $out;
	}

	/**
	 * The Scope_Sync ledger with both cart lines in it. Pure; same line format as
	 * Scope_Sync::to_lines().
	 *
	 * @param string $ledger Stored POW_SEEDED_PATTERNS.
	 * @return string Unchanged when both lines are already there.
	 */
	public static function ledger_with_cart_lines( string $ledger ): string {
		$lines   = Scope_Sync::parse_lines( $ledger );
		$missing = array_values( array_diff( self::CART_LINES, $lines ) );
		if ( empty( $missing ) ) {
			return $ledger;
		}
		return Scope_Sync::to_lines( array_merge( $lines, $missing ) );
	}
}
