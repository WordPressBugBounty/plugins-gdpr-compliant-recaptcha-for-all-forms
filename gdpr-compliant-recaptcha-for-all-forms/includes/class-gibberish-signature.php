<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/gibberish.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.

/**
 * Which FORM a saved message belongs to, and whether a rule still points at a form the
 * site watches — the display-side half of the gibberish field selection.
 *
 * Split from Gibberish_Fields in 6.0.0, at the line where the two stop sharing a
 * question. That class answers "given a submission, which fields may be scored" and is
 * called on the live spam path; this one answers "given a stored message, which rule
 * would the operator want" and is called only while rendering admin screens. They also
 * read different things: the first reads one option, this one reads the whole scope.
 *
 * Pure and WordPress-independent, like its sibling: the caller passes the scope values
 * in, so both halves stay directly unit-testable (tests/unit/GibberishFieldsTest.php).
 */
class Gibberish_Signature {

	/**
	 * The signature of a SAVED message, determined at DISPLAY time from what the
	 * message carries AND what the site actually monitors — not stored with it.
	 *
	 * WHY DISPLAY TIME. The obvious design is to write the signature into the message
	 * when it is saved. It is also the wrong one: every message saved before 6.0.0
	 * would then have no signature, and those are exactly the messages that lead an
	 * operator to this feature in the first place — the wrongly refused ones already
	 * sitting in his spam folder. Determined here, the button works on the whole
	 * archive on the day of the update.
	 *
	 * WHY THE SIGNATURE IS TAKEN FROM THE SCOPE, not rebuilt from the request. The first
	 * version wrote whatever the message itself carried, which on a Contact Form 7
	 * message produced `route contact-form-7/v1/contact-forms/121/feedback` — the
	 * concrete route of that one submission, including its form id. The site monitors
	 * `contact-form-7/v1/contact-forms/*​/feedback`, so the rule worked, but it silently
	 * narrowed the operator's choice to a single form: the next CF7 form would need its
	 * own rule, for no reason he asked for. Taking the SCOPE line instead keeps the rule
	 * exactly as wide as the monitoring it hangs off, and it is the line the operator
	 * recognises, because he can see it in his own settings.
	 *
	 * PRECEDENCE among matching scope entries: action, then route, then pattern — most
	 * specific statement about the request first. A CF7 submission over REST genuinely
	 * matches both its route and the `{"_wpcf7":null}` pattern; the route is the path it
	 * actually took, and binding to it is the truthful answer for that message.
	 *
	 * The fallback to the message's own action/route exists for the analysis view,
	 * where a form is deliberately captured BEFORE it is monitored: without it, the one
	 * path meant for setting up a form that has no spam history would have no button.
	 * Such a rule is honest but inert until the form is monitored — which is exactly
	 * what is_active() then says.
	 *
	 * @param string|null $action The message's admin-ajax action, if any.
	 * @param string|null $route  The message's REST route, if any.
	 * @param array{actions: mixed, patterns: mixed, routes: mixed} $scope The CURRENT scope option values.
	 * @param mixed       $fields The message's field map (nested).
	 * @return array{kind: string, signature: string}|null Null when nothing binds.
	 */
	public static function signature_for( $action, $route, $scope, $fields ) {
		$action = is_string( $action ) ? trim( $action ) : '';
		$route  = is_string( $route ) ? ltrim( trim( $route ), '/' ) : '';

		if ( '' !== $action ) {
			foreach ( self::scope_lines( $scope['actions'] ?? null ) as $line ) {
				if ( $line === $action ) {
					return array(
						'kind'      => 'action',
						'signature' => $line,
					);
				}
			}
		}
		if ( '' !== $route ) {
			foreach ( self::scope_lines( $scope['routes'] ?? null ) as $line ) {
				// The scope LINE, wildcards intact — not this submission's concrete
				// route, which would pin the rule to one form id.
				if ( RestRoute::matches( $route, $line ) ) {
					return array(
						'kind'      => 'route',
						'signature' => $line,
					);
				}
			}
		}
		foreach ( self::scope_lines( $scope['patterns'] ?? null ) as $line ) {
			// The SAME matcher the live gate uses — see the class docblock.
			if ( Pattern_Matcher::line_matches( $line, $fields ) ) {
				return array(
					'kind'      => 'pattern',
					'signature' => $line,
				);
			}
		}
		// Nothing monitored matches — the analysis-view case, see the docblock.
		if ( '' !== $action ) {
			return array(
				'kind'      => 'action',
				'signature' => $action,
			);
		}
		if ( '' !== $route ) {
			return array(
				'kind'      => 'route',
				'signature' => $route,
			);
		}
		return null;
	}

	/**
	 * Split one scope option value into its non-empty, trimmed lines.
	 *
	 * @param mixed $value Option value.
	 * @return string[]
	 */
	private static function scope_lines( $value ) {
		if ( ! is_string( $value ) || '' === trim( $value ) ) {
			return array();
		}
		$lines = array();
		foreach ( preg_split( '/\r\n|\n|\r/', $value, -1, PREG_SPLIT_NO_EMPTY ) as $line ) {
			if ( '' !== trim( $line ) ) {
				$lines[] = trim( $line );
			}
		}
		return $lines;
	}

	/**
	 * Rebuild a nested field map from the flattened `parent->child` paths the message
	 * detail rows store.
	 *
	 * Needed because signature_for() matches patterns against the message, and a
	 * pattern may address a nested key (`{"form":{"id":null}}`) — envelope-style
	 * builders post whole forms inside one parameter (handbuch/envelopes.md). Matching
	 * the flat paths instead would silently miss exactly those builders, i.e. offer no
	 * button on the forms most likely to need one.
	 *
	 * @param array<string, mixed> $flat Attribute path => value, as the detail rows
	 *                                   stored it (values are strings in practice, but
	 *                                   this reads whatever a submission left behind).
	 * @return array<string, mixed>
	 */
	public static function rebuild_tree( $flat ) {
		$tree = array();
		foreach ( $flat as $path => $value ) {
			$segments = explode( '->', (string) $path );
			$node     = &$tree;
			foreach ( $segments as $index => $segment ) {
				if ( count( $segments ) - 1 === $index ) {
					$node[ $segment ] = $value;
					break;
				}
				// is_array() as well as isset(): two rows may store `a` AND `a->b`, and
				// assigning into a string offset is an Error on PHP 8. The branch wins —
				// it carries more of the form than the scalar does.
				if ( ! isset( $node[ $segment ] ) || ! is_array( $node[ $segment ] ) ) {
					$node[ $segment ] = array();
				}
				$node = &$node[ $segment ];
			}
			unset( $node );
		}
		return $tree;
	}

	/**
	 * Whether a rule still points at something the site actually monitors.
	 *
	 * A rule whose signature appears in no current scope list scores nothing while
	 * still looking like a rule — the same failure class as an action name that was
	 * never registered anywhere (CLAUDE.md). Shown as "inactive" in the settings list;
	 * NEVER auto-removed, and never a reason to re-add the scope entry: what the
	 * operator removed stays removed (the Scope_Sync contract, handbuch/gate.md).
	 *
	 * Deliberately a NEAR ANSWER, and says so where it is displayed: a broader pattern
	 * elsewhere may still bring the form in, which this cannot know.
	 *
	 * @param array{kind: string, signature: string, fields: string[]} $rule     One rule.
	 * @param mixed                                                   $actions  POW_EXPLICIT_ACTIONS value.
	 * @param mixed                                                   $patterns POW_PARAMETER_PATTERN value.
	 * @param mixed                                                   $routes   POW_REST_ROUTES value.
	 * @return bool
	 */
	public static function is_active( $rule, $actions, $patterns, $routes ) {
		$haystack = 'action' === $rule['kind'] ? $actions : ( 'pattern' === $rule['kind'] ? $patterns : $routes );
		if ( ! is_string( $haystack ) ) {
			return false;
		}
		foreach ( preg_split( '/\r\n|\n|\r/', $haystack, -1, PREG_SPLIT_NO_EMPTY ) as $line ) {
			if ( trim( $line ) === $rule['signature'] ) {
				return true;
			}
		}
		// ROUTES ALSO MATCH BY WILDCARD. Since signature_for() stores the SCOPE line, a
		// button-written rule normally matches the exact-line loop above; a concrete
		// route reaches this branch only from the no-scope fallback or from a hand-typed
		// line (`ws-form/v1/submit/42` against the shipped `ws-form/v1/*`). Comparing
		// lines alone would report those as "not monitored" although they are fully
		// covered. Same matcher as the live gate, for the same reason as everywhere else.
		if ( 'route' === $rule['kind'] ) {
			return RestRoute::matches( $rule['signature'], $haystack );
		}
		return false;
	}
}
