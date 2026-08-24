<?php
/**
 * Pure, WordPress-independent handling of the operator's GIBBERISH FIELD SELECTION —
 * which fields of which form the content heuristic is allowed to look at.
 *
 * WHY THIS CLASS EXISTS. Until 6.0.0 gibberish detection scored EVERY field of every
 * monitored submission and carried a growing pile of exemptions to undo the damage:
 * a name-substring list in Gibberish_Detector, the request's own hashPWFields marker,
 * the analysis half of POW_SKIP_FIELDS, the learned credential names and a public
 * filter. Every support case added one more exemption, because the failure mode is
 * always the same: a field the operator never thinks about legitimately carries a
 * random-looking value (a nonce, a base64 blob, a serial), and a real person's
 * membership application gets refused. See the wp.org thread of 2026-08-24.
 *
 * The fix is not another exemption. It is the opposite default: nothing is scored
 * unless the operator picked it. Selection replaces exemption — that is why this
 * class has no exempt list of any kind, and why the ones listed above are gone.
 *
 * THE LINE FORMAT, one rule per line:
 *
 *     pattern {"_wpcf7":null} => your-message, vf_token
 *     action wpforms_submit => wpforms[fields][1]
 *     route sureforms/v1/submit-form => message
 *
 * The left side is a SIGNATURE: one of the three recognition classes the plugin
 * already has (handbuch/gate.md), written exactly as it appears in the operator's own
 * pattern/action/route list — there is nothing new to learn. The right side is the
 * comma-separated field names, as the FORM really sends them; the third line's
 * `message` is a stand-in, not a claim about SureForms' field naming (it renders
 * `srfm-…` names, measured 2026-08-24).
 *
 * A NESTED name is written as its LEAF: a builder posting
 * `everest_forms[form_fields][message]` becomes a nested array in PHP, and subset()
 * matches names at any level — so the rule says `message`. The per-field button gets
 * this right on its own (the detail rows store `parent->child` and it takes the last
 * segment); typing the bracket expression by hand produces a rule that never matches.
 *
 * `=>` is the separator and not `:`, because a pattern signature contains colons of
 * its own (`{"_wpcf7":null}`) and "the first colon" would cut in the wrong place. It
 * is the LAST `=>` that separates, for the same reason in the other direction.
 *
 * A rule matches a submission only if its signature does. That comparison uses the ONE
 * existing implementation per class (Pattern_Matcher::line_matches(),
 * RestRoute::matches(), string equality for actions) — a second, similar matcher would
 * eventually disagree with the live gate, and nothing would notice, because the two
 * are only ever exercised apart. Same reasoning as Pattern_Matcher's own docblock.
 *
 * Several rules may match one submission; the UNION of their fields is scored. That is
 * deliberate and needs no precedence rule: every rule the operator wrote is a request
 * to look at those fields, so honouring all of them is the only reading that never
 * silently drops one.
 *
 * @package GDPR_Compliant_ReCaptcha
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/detection.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.

/**
 * Parses, serialises and applies the gibberish field selection.
 */
class Gibberish_Fields {

	/**
	 * Signature kinds, in the order the display-time signature detection prefers them
	 * (see Message_Page): an action is the most specific statement about a request, a
	 * route the next, a field pattern the broadest.
	 *
	 * @var string[]
	 */
	const KINDS = array( 'action', 'route', 'pattern' );

	/**
	 * Separator between signature and field list. Two characters, not one, and not a
	 * colon — see the class docblock.
	 *
	 * @var string
	 */
	const SEPARATOR = '=>';

	/**
	 * Parse the option value into rules.
	 *
	 * Deliberately strict and SILENT: an unparsable line is dropped, never guessed at.
	 * The operator normally never types here (the per-field button writes these lines),
	 * so a malformed line means either a hand edit or a corrupted row — and in a
	 * security plugin the safe direction for "I do not understand this" is to score
	 * LESS, not to invent a rule. Dropped only for the PURPOSE OF SCORING: the line
	 * itself survives every write (see split_lines()), and the settings save guard names
	 * it to the operator instead of letting it disappear.
	 *
	 * @param mixed $value Raw option value.
	 * @return array<int, array{kind: string, signature: string, fields: string[]}>
	 */
	public static function parse_lines( $value ) {
		$split = self::split_lines( $value );
		return $split['rules'];
	}

	/**
	 * Parse ONE line, or return null when it is not a usable rule.
	 *
	 * @param string $line Raw line.
	 * @return array{kind: string, signature: string, fields: string[]}|null
	 */
	private static function parse_line( $line ) {
		$line = trim( $line );
		if ( '' === $line ) {
			return null;
		}
		// LAST separator, not the first: a pattern signature may legitimately contain
		// `=>` inside a JSON string value, while the field list never can (a comma-separated
		// list of field names has no place for it).
		$split = strrpos( $line, self::SEPARATOR );
		if ( false === $split ) {
			return null;
		}
		$left  = trim( substr( $line, 0, $split ) );
		$right = substr( $line, $split + strlen( self::SEPARATOR ) );
		// Kind is the first whitespace-delimited word; the signature is everything after
		// it, verbatim — a pattern signature carries braces, quotes and spaces of its own.
		$parts = preg_split( '/\s+/', $left, 2 );
		if ( ! is_array( $parts ) || 2 !== count( $parts ) ) {
			return null;
		}
		$kind      = strtolower( trim( $parts[0] ) );
		$signature = trim( $parts[1] );
		if ( ! in_array( $kind, self::KINDS, true ) || '' === $signature ) {
			return null;
		}
		$fields = self::parse_field_list( $right );
		if ( ! $fields ) {
			return null;
		}
		return array(
			'kind'      => $kind,
			'signature' => $signature,
			'fields'    => $fields,
		);
	}

	/**
	 * Split the right-hand side into field names, dropping empties and duplicates.
	 *
	 * Field names keep their original case here (they are shown back to the operator
	 * and written into rules); comparison against a submission is case-insensitive,
	 * see selected_names().
	 *
	 * @param string $raw Comma-separated field names.
	 * @return string[]
	 */
	private static function parse_field_list( $raw ) {
		$fields = array();
		foreach ( explode( ',', $raw ) as $name ) {
			$name = trim( $name );
			if ( '' !== $name && ! in_array( $name, $fields, true ) ) {
				$fields[] = $name;
			}
		}
		return $fields;
	}

	/**
	 * Split the option value into the rules it yields AND the lines it does not.
	 *
	 * WHY THE UNREADABLE LINES ARE KEPT. Both write paths (the per-field button and the
	 * settings textarea) go parse → mutate → serialise → store. With only the rules in
	 * hand, that round trip DELETES anything the parser could not read: the operator
	 * types a half-finished line, the save guard names it and stores it as typed, and
	 * then one click on a button in some message makes it vanish without a word. Two
	 * ways in must not mean one of them quietly eats the other's work.
	 *
	 * So the leftovers travel with the rules and are appended again on write. They still
	 * score nothing — that part is unchanged and deliberate.
	 *
	 * @param mixed $value Raw option value.
	 * @return array{rules: array<int, array{kind: string, signature: string, fields: string[]}>, leftovers: string[]}
	 */
	public static function split_lines( $value ) {
		$rules     = array();
		$leftovers = array();
		if ( ! is_string( $value ) || '' === trim( $value ) ) {
			return array(
				'rules'     => $rules,
				'leftovers' => $leftovers,
			);
		}
		foreach ( preg_split( '/\r\n|\n|\r/', $value, -1, PREG_SPLIT_NO_EMPTY ) as $line ) {
			$rule = self::parse_line( $line );
			if ( null === $rule ) {
				if ( '' !== trim( $line ) ) {
					$leftovers[] = trim( $line );
				}
				continue;
			}
			$rules[] = $rule;
		}
		return array(
			'rules'     => $rules,
			'leftovers' => $leftovers,
		);
	}

	/**
	 * Serialise rules back into the option value.
	 *
	 * Lines the parser could not read are appended again, unchanged — see split_lines()
	 * for why a write must never drop them.
	 *
	 * @param array<int, array{kind: string, signature: string, fields: string[]}> $rules     Rules.
	 * @param string[]                                                             $leftovers Unreadable lines to preserve.
	 * @return string
	 */
	public static function to_lines( $rules, $leftovers = array() ) {
		$lines = array();
		foreach ( $rules as $rule ) {
			if ( ! $rule['fields'] ) {
				continue;
			}
			$lines[] = $rule['kind'] . ' ' . $rule['signature'] . ' ' . self::SEPARATOR . ' ' . implode( ', ', $rule['fields'] );
		}
		foreach ( $leftovers as $leftover ) {
			$lines[] = $leftover;
		}
		return implode( "\n", $lines );
	}

	/**
	 * The field names to score for THIS submission: the union of every matching rule's
	 * fields.
	 *
	 * @param array<int, array{kind: string, signature: string, fields: string[]}> $rules   Parsed rules.
	 * @param string|null                                                          $action  The admin-ajax action, if any.
	 * @param string|null                                                          $route   The REST route, if any.
	 * @param mixed                                                                $request The request field map, for pattern rules.
	 * @return string[] Field names, original case, deduplicated.
	 */
	public static function selected_names( $rules, $action, $route, $request ) {
		$names = array();
		foreach ( $rules as $rule ) {
			if ( ! self::signature_matches( $rule, $action, $route, $request ) ) {
				continue;
			}
			foreach ( $rule['fields'] as $field ) {
				if ( ! in_array( $field, $names, true ) ) {
					$names[] = $field;
				}
			}
		}
		return $names;
	}

	/**
	 * Whether one rule's signature applies to this submission.
	 *
	 * Each branch delegates to the SAME implementation the live gate uses — see the
	 * class docblock on why there is no second matcher here.
	 *
	 * @param array{kind: string, signature: string, fields: string[]} $rule    One rule.
	 * @param string|null                                             $action  The admin-ajax action, if any.
	 * @param string|null                                             $route   The REST route, if any.
	 * @param mixed                                                   $request The request field map.
	 * @return bool
	 */
	public static function signature_matches( $rule, $action, $route, $request ) {
		if ( 'action' === $rule['kind'] ) {
			return is_string( $action ) && '' !== $action && $action === $rule['signature'];
		}
		if ( 'route' === $rule['kind'] ) {
			return is_string( $route ) && '' !== $route && RestRoute::matches( $route, $rule['signature'] );
		}
		return Pattern_Matcher::line_matches( $rule['signature'], $request );
	}

	/**
	 * Reduce a submission's field tree to the selected fields.
	 *
	 * Matching is case-insensitive and happens at EVERY nesting level, because form
	 * builders nest: WPForms posts `wpforms[fields][1]`, and an envelope-style builder
	 * ships the whole form inside one parameter (handbuch/envelopes.md). A name that
	 * matches takes its whole subtree — if the operator picked a field that turns out
	 * to be a group, he picked the group.
	 *
	 * Returns a FLAT list of the matched subtrees keyed by their path so the detector
	 * scores each exactly once; the detector's own recursion handles nested values.
	 *
	 * @param mixed    $fields Submitted fields.
	 * @param string[] $names  Selected field names.
	 * @return array<string, mixed> Matched name => value.
	 */
	public static function subset( $fields, $names ) {
		$wanted = array();
		foreach ( $names as $name ) {
			$wanted[ strtolower( $name ) ] = true;
		}
		$out = array();
		self::collect_subset( $fields, $wanted, $out, 0 );
		return $out;
	}

	/**
	 * Recursion behind subset().
	 *
	 * Depth-limited with the same 6 as Pattern_Matcher::WILDCARD_MAX_DEPTH and
	 * Echo_Values::MAX_DEPTH — a hostile or merely baroque payload must not be able to
	 * spend unbounded time here.
	 *
	 * @param mixed                $fields Current node.
	 * @param array<string, bool>  $wanted Lowercased selected names.
	 * @param array<string, mixed> $out    Collected matches, by reference.
	 * @param int                  $depth  Current depth.
	 * @return void
	 */
	private static function collect_subset( $fields, $wanted, &$out, $depth ) {
		if ( ! is_array( $fields ) || $depth > 6 ) {
			return;
		}
		foreach ( $fields as $name => $value ) {
			$key = strtolower( (string) $name );
			if ( isset( $wanted[ $key ] ) ) {
				// Path-unique key so two nested fields of the same name both survive
				// into the scan instead of overwriting each other.
				$out[ $key . '#' . count( $out ) ] = $value;
				continue;
			}
			if ( is_array( $value ) ) {
				self::collect_subset( $value, $wanted, $out, $depth + 1 );
			}
		}
	}

	/**
	 * Whether this field is already selected for this signature.
	 *
	 * @param array<int, array{kind: string, signature: string, fields: string[]}> $rules     Parsed rules.
	 * @param string                                                               $kind      Signature kind.
	 * @param string                                                               $signature Signature.
	 * @param string                                                               $field     Field name.
	 * @return bool
	 */
	public static function has_field( $rules, $kind, $signature, $field ) {
		foreach ( $rules as $rule ) {
			if ( $rule['kind'] === $kind && $rule['signature'] === $signature ) {
				foreach ( $rule['fields'] as $existing ) {
					if ( 0 === strcasecmp( $existing, $field ) ) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * Add one field to one signature's rule, creating the rule when it is the first.
	 *
	 * @param array<int, array{kind: string, signature: string, fields: string[]}> $rules     Parsed rules.
	 * @param string                                                               $kind      Signature kind.
	 * @param string                                                               $signature Signature.
	 * @param string                                                               $field     Field name.
	 * @return array<int, array{kind: string, signature: string, fields: string[]}>
	 */
	public static function add_field( $rules, $kind, $signature, $field ) {
		$field = trim( $field );
		if ( ! in_array( $kind, self::KINDS, true ) || '' === trim( $signature ) || '' === $field ) {
			return $rules;
		}
		if ( self::has_field( $rules, $kind, $signature, $field ) ) {
			return $rules;
		}
		foreach ( $rules as $index => $rule ) {
			if ( $rule['kind'] === $kind && $rule['signature'] === $signature ) {
				$rules[ $index ]['fields'][] = $field;
				return $rules;
			}
		}
		$rules[] = array(
			'kind'      => $kind,
			'signature' => $signature,
			'fields'    => array( $field ),
		);
		return $rules;
	}

	/**
	 * Remove one field. Removing the LAST field of a rule removes the rule — a
	 * signature with no fields would score nothing while still looking like a rule.
	 *
	 * @param array<int, array{kind: string, signature: string, fields: string[]}> $rules     Parsed rules.
	 * @param string                                                               $kind      Signature kind.
	 * @param string                                                               $signature Signature.
	 * @param string                                                               $field     Field name.
	 * @return array<int, array{kind: string, signature: string, fields: string[]}>
	 */
	public static function remove_field( $rules, $kind, $signature, $field ) {
		$out = array();
		foreach ( $rules as $rule ) {
			if ( $rule['kind'] === $kind && $rule['signature'] === $signature ) {
				$kept = array();
				foreach ( $rule['fields'] as $existing ) {
					if ( 0 !== strcasecmp( $existing, $field ) ) {
						$kept[] = $existing;
					}
				}
				if ( ! $kept ) {
					continue;
				}
				$rule['fields'] = $kept;
			}
			$out[] = $rule;
		}
		return $out;
	}
}
