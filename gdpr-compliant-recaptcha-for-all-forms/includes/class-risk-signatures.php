<?php
/**
 * The risk class: seed lines whose false positive costs a purchase, a donation or an
 * account instead of a message — and the one place that knows which lines those are.
 *
 * Pure and WordPress-independent (tests/unit/RiskSignaturesTest.php). Design and product
 * verdicts: PLAN-RISIKOKLASSE.md; behaviour: handbuch/detection.md, "Risikoklasse".
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
 * Which shipped seed lines belong to the risk class, and which class a request falls in.
 *
 * A risk line is an ORDINARY seed line — visible, deletable, carried onto existing
 * installs by Scope_Sync, found by the blame diagnosis. The only difference is what
 * happens after the verdict: until the operator arms the class (Risk_Enforcement), a
 * spam verdict on such a request is recorded but not enforced.
 *
 * THE STRING EXISTS ONCE. The three default getters take their risk lines from lines()
 * below, and classify_request() compares against the same catalog — so "is this line a
 * risk line" and "is this request a risk request" cannot drift apart.
 *
 * NO OWN COMPARISON. Every match is delegated to the matcher that interprets that kind
 * of line in production: Action_Rules for the action list, Pattern_Matcher for field
 * patterns, RestRoute for routes. A second matcher here would be a second semantics.
 */
final class Risk_Signatures {

	/** Purchases, donations, payments. */
	const CHECKOUT = 'checkout';

	/** Account creation. */
	const REGISTRATION = 'registration';

	/** Line kinds — one per default getter. */
	const KIND_ACTION  = 'action';
	const KIND_PATTERN = 'pattern';
	const KIND_ROUTE   = 'route';

	/**
	 * Lines that must NEVER be seeded, whatever a future survey concludes. Each was
	 * measured (PLAN-RISIKOKLASSE.md, "Verdikte je Produkt"):
	 * - `cartflows_save_cart_abandonment_data` fires on keyup and 800 ms after page load
	 *   — no visitor intent; a block is silent data loss for the shop.
	 * - `{"form_id":null}` is Ultimate Member's login AND registration alike.
	 * - `{"_wcf_checkout_id":null}` is also in CartFlows' login form.
	 */
	const NEVER_SEED = array(
		'cartflows_save_cart_abandonment_data',
		'{"form_id":null}',
		'{"_wcf_checkout_id":null}',
	);

	/**
	 * The catalog. Each entry: gate (main plugin file, as get_plugins() keys it),
	 * product (for the admin notice), class, kind, line. Evidence per line is in the
	 * comment above it — verified against the product's own source, never guessed.
	 *
	 * @return array<int, array{gate: string, product: string, class: string, kind: string, line: string}>
	 */
	public static function catalog(): array {
		return Risk_Catalog::entries();
	}

	/**
	 * The risk lines of one kind for the installed products — what a default getter
	 * appends. Order follows the catalog; duplicates are dropped.
	 *
	 * @param string               $kind              One of the KIND_* constants.
	 * @param array<string, mixed> $installed_plugins get_plugins() — file => header data.
	 * @return string[]
	 */
	public static function lines( string $kind, array $installed_plugins ): array {
		$lines = array();
		foreach ( self::catalog() as $entry ) {
			if ( $kind === $entry['kind'] && array_key_exists( $entry['gate'], $installed_plugins ) ) {
				$lines[] = $entry['line'];
			}
		}
		return array_values( array_unique( $lines ) );
	}

	/**
	 * The products of one kind whose lines lines() would return — for the admin notice.
	 *
	 * @param string               $kind              One of the KIND_* constants.
	 * @param array<string, mixed> $installed_plugins get_plugins().
	 * @return array<string, string[]> product => its lines of that kind.
	 */
	public static function products( string $kind, array $installed_plugins ): array {
		$products = array();
		foreach ( self::catalog() as $entry ) {
			if ( $kind === $entry['kind'] && array_key_exists( $entry['gate'], $installed_plugins ) ) {
				$products[ $entry['product'] ][] = $entry['line'];
			}
		}
		return $products;
	}

	/**
	 * Which risk class this request falls in, or null. Independent of what is
	 * installed: the request itself is the evidence.
	 *
	 * @param string      $action  The request's `action` field ('' if none).
	 * @param mixed       $request The whole request field map.
	 * @param string|null $route   The extracted REST route, or null.
	 * @return string|null One of CHECKOUT / REGISTRATION, or null.
	 */
	public static function classify_request( string $action, $request, ?string $route ): ?string {
		foreach ( self::catalog() as $entry ) {
			if ( self::entry_matches( $entry, $action, $request, $route ) ) {
				return $entry['class'];
			}
		}
		return null;
	}

	/**
	 * Is this request ALSO in scope through an ordinary line — one that is not a catalog
	 * line? Then it stays enforced, whatever its risk class: an operator who put
	 * `{"a":"register"}` into the scope himself before the risk class existed had a
	 * block, and an update must not take it away silently (acceptance finding
	 * 2026-09-25). Same matchers as the gate, delegation only.
	 *
	 * @param string      $action       The request's `action` field ('' if none).
	 * @param mixed       $request      The whole request field map.
	 * @param string|null $route        The extracted REST route, or null.
	 * @param string      $action_list  POW_EXPLICIT_ACTION.
	 * @param string      $pattern_list POW_PARAMETER_PATTERN.
	 * @param string      $route_list   POW_REST_ROUTES.
	 * @return bool
	 */
	public static function ordinary_line_matches( string $action, $request, ?string $route, string $action_list, string $pattern_list, string $route_list ): bool {
		$lists = array(
			self::KIND_ACTION  => $action_list,
			self::KIND_PATTERN => $pattern_list,
			self::KIND_ROUTE   => $route_list,
		);
		foreach ( $lists as $kind => $list ) {
			$catalog = array();
			foreach ( self::catalog() as $entry ) {
				if ( $kind === $entry['kind'] ) {
					$catalog[] = $entry['line'];
				}
			}
			$lines = preg_split( '/\r\n|\n|\r/', $list, -1, PREG_SPLIT_NO_EMPTY );
			foreach ( false === $lines ? array() : $lines as $line ) {
				if ( in_array( trim( $line ), $catalog, true ) ) {
					continue;
				}
				$entry = array(
					'kind' => $kind,
					'line' => $line,
				);
				if ( self::entry_matches( $entry, $action, $request, $route ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * One catalog entry against one request — delegation only.
	 *
	 * @param array{kind: string, line: string} $entry   Catalog entry.
	 * @param string                            $action  The request's action.
	 * @param mixed                             $request Field map.
	 * @param string|null                       $route   REST route or null.
	 * @return bool
	 */
	private static function entry_matches( array $entry, string $action, $request, ?string $route ): bool {
		switch ( $entry['kind'] ) {
			case self::KIND_ACTION:
				return Action_Rules::list_line_matches( $entry['line'], $action, $request );
			case self::KIND_PATTERN:
				return Pattern_Matcher::line_matches( $entry['line'], $request );
			case self::KIND_ROUTE:
				return null !== $route && RestRoute::matches( $route, $entry['line'] );
		}
		return false;
	}
}
