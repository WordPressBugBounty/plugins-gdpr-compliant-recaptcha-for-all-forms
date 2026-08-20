<?php
/**
 * Pure, WordPress-independent UNPACKING of envelope fields: a single POST field whose
 * value is not a value at all but a whole form, serialized as JSON. See
 * handbuch/envelopes.md — that area file is this class's home; handbuch/gate.md holds the
 * gate it runs before, handbuch/detection.md the classification it feeds.
 *
 * WHY THIS EXISTS. Some form builders do not post their fields as fields. Ninja Forms
 * posts `action=nf_ajax_submit` plus ONE field `formData` carrying a JSON text with the
 * whole submission AND the form's settings object (verified in the wp.org zip:
 * `assets/js/min/front-end.js` builds `JSON.stringify({id,fields,settings,extra})`,
 * `includes/AJAX/Controllers/Submission.php` decodes it again). For this plugin such a
 * request has exactly one field, and everything the operator can address — a pattern,
 * a skip-field line, a field-bound block rule, the "block this sender" button in the
 * inbox — needs field names to address. There are none. The submission is one opaque
 * string.
 *
 * The plugin already unpacks JSON at the BODY level (Stamp::capture_request_data() when
 * Content-Type is application/json, and the client twins in
 * scripts/recaptcha-gdpr-pow.js / recaptcha-gdpr-analysis-model.js). It never unpacked
 * JSON one level deeper, inside a field VALUE — and a builder posting
 * form-urlencoded with a JSON-valued field falls exactly between the two. That gap is
 * what this class closes.
 *
 * THE FIELD DATUM behind it (wp.org support case vczp, 2026-08-19): every Ninja Forms
 * submission on every installation was classified "Gibberish content" since 5.1,
 * content-independently. NF's own settings keys `changeEmailErrorMsg`,
 * `changeDateErrorMsg` and `confirmFieldErrorMsg` ride along inside `formData` as TEXT
 * (Render.php merges Ninja_Forms::config('i18nFrontEnd') into every form's settings, so
 * they are there whether the operator touched them or not), each carries three
 * camelCase humps, and three of them clear MESSAGE_GIBBERISH_THRESHOLD on their own.
 * After unpacking they are KEYS, and Gibberish_Detector scores values — which is why
 * the unpacking fixes the misclassification without touching a single threshold.
 *
 * DELIBERATELY GENERIC, NOT A PER-BUILDER REGISTRY. An earlier draft bound the
 * unpacking to a curated (action, field) list. It was dropped on purpose: a registry
 * only ever helps builders we already know, while the operator can put ANY action into
 * the scope, and the field-level addressability above is exactly what is missing for
 * the builders we do NOT know. The narrowing that stayed is structural instead of
 * enumerated — see the five rules below.
 *
 * THE FIVE RULES, each one load-bearing:
 *   1. TOP LEVEL ONLY. Only the values of the field map's own top-level entries are
 *      examined. An attacker can therefore only ever restructure their OWN field.
 *   2. EXACTLY ONE LEVEL. What a decode produced is never scanned for JSON strings
 *      again. Unpacking is a single step, not a fixed point — otherwise the work done
 *      per request would depend on how deeply the sender nested their payload.
 *   3. OBJECTS AND ARRAYS ONLY, AND NON-EMPTY. `"123"`, `"null"`, `"true"`, `{}` and
 *      `[]` are valid JSON but carry no field structure; treating them as one would
 *      replace a value by nothing. They stay strings.
 *   4. CAPPED, AND THE CAP FAILS TOWARDS TODAY. Past MAX_BYTES, MAX_DEPTH or the call's
 *      MAX_ENTRIES budget the value stays the string it is. That fallback is NOT a safe
 *      state — it is the behaviour that produced the misclassification above. So the caps
 *      are set generously: a cap that trips on an ordinary large form would resurrect the
 *      bug it was meant to fix. MAX_ENTRIES is the one that is not about detection at all
 *      — it bounds what unpacking costs downstream, per REQUEST rather than per field,
 *      see its own docblock.
 *   5. IN PLACE, NEVER MERGED UPWARDS. The decoded structure replaces the value under
 *      its OWN key. Merging it into the top level would let a sender's `formData`
 *      overwrite our copy of `action`, `security` or `gdpr_pow_token`.
 *
 * THE RAW STRING SURVIVES AS A SIDE CHANNEL, and that is not tidiness but a
 * regression guard. Until 5.5.0 the blocklist extracted addresses and URLs from the RAW
 * value of every field (Echo_Values::extract_emails()/extract_urls() over the whole
 * string), so a blocked domain sitting inside the JSON — including in a KEY — was found.
 * After unpacking, keys are keys and nobody looks at them: the operator's explicit block
 * would silently stop working through our own update. unpack() therefore returns the
 * original strings, Stamp hands them to the blocklist check as additional content
 * strings, and exactly the bytes 5.5.0 matched on are matched on again. They are
 * request-local and never stored.
 *
 * They go to the BLOCKLIST ONLY — not to the gibberish scan (that would be the Ninja
 * Forms bug rebuilt) and not to the echo lock (the store SEEDS from what it is given, so
 * a constant text inside a form's configuration would seed a value that every later
 * submission of that form carries; see Echo_Values::build_echo_set()'s $no_text_roots).
 *
 * No WordPress dependencies (no options, no $wpdb, no translation functions) →
 * unit-testable in isolation, see tests/unit/FieldEnvelopesTest.php.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

class Field_Envelopes {

	/**
	 * Longest field value that is examined at all, in bytes.
	 *
	 * Deliberately generous (rule 4 above): the fallback of every cap is the RAW STRING,
	 * i.e. today's misclassification, so a tight cap would quietly re-break large forms.
	 * 2 MB is far above any real submission — a Ninja Forms envelope of a big form with
	 * all its settings measures in the low tens of kilobytes — and far below anything a
	 * PHP request could pass on without hitting post_max_size first. Cost is bounded by
	 * json_decode() over that many bytes, once per top-level string field, which is the
	 * same order as the gibberish scan already spends regexing every $_POST value.
	 */
	const MAX_BYTES = 2097152;

	/**
	 * Nesting depth handed to json_decode(). Past it the decode FAILS (returns null) and
	 * the value stays a string — the same fallback as every other rejection. Real form
	 * envelopes nest three or four levels; 32 is json_decode()'s own conventional depth
	 * and leaves the limit far away from honest payloads while still bounding a
	 * hand-built one.
	 */
	const MAX_DEPTH = 32;

	/**
	 * Entries (scalars AND nested containers) a single unpack() call may produce, across
	 * ALL fields of that call. Past the budget a value stays the string it is — same
	 * fallback as every other cap.
	 *
	 * NOT A DETECTION KNOB — this bounds what unpacking COSTS DOWNSTREAM. Every entry can
	 * become a row in Stamp::save_message(), and all of them go into ONE prepared INSERT.
	 * Before unpacking, a request's field count was bounded by PHP's own `max_input_vars`
	 * (default 1000), which counts $_POST entries and silently drops the rest. A JSON
	 * string is ONE entry, so decoding walks straight past that: measured 2026-08-20, a
	 * 1.9 MB payload of trivial `"kN":"v"` pairs decodes in 9 ms into 150 000 leaves —
	 * 150 000 rows from one unauthenticated POST. Spam submissions are the ones that get
	 * saved, so this is reachable by exactly the traffic the plugin invites.
	 *
	 * GLOBAL PER CALL, NOT PER FIELD, and that distinction is the whole point. A per-field
	 * cap is trivially defeated by splitting: 1000 trivial entries cost ~10 KB, and
	 * `post_max_size` (8 MB) then buys ~800 such fields, each passing a per-field check —
	 * ~800 000 entries with the cap fully respected. The budget therefore runs across the
	 * whole call; a field whose structure would exceed what is left stays a string, and
	 * earlier fields win (deterministic, insertion order).
	 *
	 * WHY 10 000 AND NOT PHP'S 1000. The two ceilings fail in opposite directions: PHP
	 * over its limit silently DROPS surplus fields, while this one over its limit
	 * REACTIVATES the 5.6.0 misclassification for that form, deterministically and
	 * without turning anything red (the value stays the string whose settings keys convict
	 * it). Rule 4 of the class docblock therefore applies with force — generous, not
	 * tight. Measured references: the captured Ninja Forms submission of a default form
	 * has ~200 entries, a synthetic 40-field form with 150 settings entries has 231, and a
	 * repeater-heavy or multi-step form plausibly reaches the low four digits. 10 000
	 * keeps ~40x headroom over the largest measured real envelope while being three orders
	 * of magnitude STRICTER than the shipped per-field version was against a split attack.
	 * The anchor is deliberately our own downstream cost, not `ini_get('max_input_vars')`:
	 * a pure class must not depend on the environment, and the host's parser limit says
	 * nothing about what our INSERT costs.
	 */
	const MAX_ENTRIES = 10000;

	/**
	 * Does this string even look like it could be a JSON object or array? A cheap
	 * pre-filter so the common case (an ordinary form value) never reaches json_decode().
	 *
	 * Leading whitespace is tolerated because JSON allows it; anything else that does not
	 * start with `{` or `[` cannot decode to the array/object rule 3 requires.
	 *
	 * @param string $value Raw field value.
	 * @return bool
	 */
	private static function looks_like_structure( $value ) {
		$trimmed = ltrim( $value );
		if ( '' === $trimmed ) {
			return false;
		}
		return '{' === $trimmed[0] || '[' === $trimmed[0];
	}

	/**
	 * Decode ONE candidate string, or return null when it is not an envelope or does not
	 * fit into what is left of the call's entry budget.
	 *
	 * Two attempts, in the same order and for the same reason Ninja Forms itself uses
	 * (Submission.php: `json_decode($_POST['formData'])`, then the same on
	 * `stripslashes()`): capture happens before wp_magic_quotes(), so the raw attempt is
	 * the normal one, and the stripslashes() fallback covers a stack that slashed the
	 * value earlier. Only a NON-EMPTY array is accepted (rule 3).
	 *
	 * @param string $value  Raw field value.
	 * @param int    $budget Entries still available; decremented by what this value costs.
	 * @return array<mixed>|null Decoded structure, or null.
	 */
	private static function decode( $value, &$budget ) {
		if ( $budget < 1 || strlen( $value ) > self::MAX_BYTES || ! self::looks_like_structure( $value ) ) {
			return null;
		}
		foreach ( array( $value, stripslashes( $value ) ) as $candidate ) {
			$decoded = json_decode( $candidate, true, self::MAX_DEPTH );
			if ( ! is_array( $decoded ) || array() === $decoded ) {
				continue;
			}
			$cost = self::count_entries( $decoded, $budget );
			if ( null === $cost ) {
				// Over the remaining budget. Do NOT try the stripslashes twin — it would
				// decode to the same size and cost the count a second time.
				return null;
			}
			$budget -= $cost;
			return $decoded;
		}
		return null;
	}

	/**
	 * How many entries does this structure hold, or null once it exceeds $limit?
	 *
	 * Counts EVERY entry, scalar or container — not just the leaves. A payload made of
	 * empty arrays (`[[],[],…]`) has no leaves at all, so a leaf-only count would wave
	 * through a structure that still costs a full walk in every consumer downstream.
	 *
	 * Stops at the limit, so a hostile payload costs the size of the budget, not its own.
	 *
	 * @param array<mixed> $decoded Decoded structure.
	 * @param int          $limit   Entries still available.
	 * @return int|null Entry count, or null when it exceeds $limit.
	 */
	private static function count_entries( array $decoded, $limit ) {
		$stack = array( $decoded );
		$seen  = 0;
		while ( $stack ) {
			$node = array_pop( $stack );
			foreach ( $node as $value ) {
				++$seen;
				if ( $seen > $limit ) {
					return null;
				}
				if ( is_array( $value ) ) {
					$stack[] = $value;
				}
			}
		}
		return $seen;
	}

	/**
	 * Decode a JSON REQUEST BODY under the same caps, TRUNCATED rather than refused.
	 *
	 * The sibling of unpack() for layer 2 (Stamp::capture_request_data(): a POST with
	 * `Content-Type: application/json`, read from php://input and merged into both field
	 * maps). That path has existed since 4.x and had NO limit of any kind — no byte cap,
	 * no entry cap, only PHP's default nesting depth.
	 *
	 * WHY IT IS CAPPED HERE AT ALL, although it is not a regression of the unpacking:
	 * without it MAX_ENTRIES is dead law. An attacker who notices the budget on field
	 * values simply sets a different Content-Type header and posts the identical payload
	 * as the body. A limit one header switch away from the hole it guards is not a limit.
	 *
	 * WHY TRUNCATION AND NOT REFUSAL — measured, not reasoned. Refusing an over-budget
	 * body leaves both field maps EMPTY, and every classification stage is guarded on a
	 * non-empty field map (`$gdpr_fields && …` in Stamp::classify_*()). So refusal does
	 * not merely blind the content checks: it removes the submission from judgement
	 * altogether, while WordPress's own REST dispatch still parses the same body and hands
	 * the complete submission to the target plugin. An attacker who solves the proof of
	 * work would pad their body and be delivered unjudged — a bypass this plugin did not
	 * have before, created by its own cap. Arm E of
	 * tests/integration/cases/ninja-forms-envelope.mjs is that measurement; it was red
	 * against the refusing version.
	 *
	 * Truncation keeps the submission judgeable and still bounds the cost: the first
	 * MAX_ENTRIES entries in document order survive, the rest is dropped. What falls off
	 * the end is invisible to the content checks — which is why Stamp keeps the RAW body
	 * for the blocklist (see its $body_raw), exactly as it keeps an envelope's raw string.
	 *
	 * A body over MAX_BYTES is still refused outright: there is nothing proportionate to
	 * do with it, and it is not a shape any form builder produces.
	 *
	 * @param mixed $body      Raw request body — file_get_contents() returns false on
	 *                         failure, so this is deliberately not typed as a string.
	 * @param bool  $incomplete Set by reference: true when the caller must keep the raw
	 *                         bytes for the blocklist, i.e. the body was truncated or
	 *                         refused outright. Reported here rather than recomputed by a
	 *                         second decode — every legitimate JSON body would pay for
	 *                         that.
	 * @return array<mixed>|null Decoded body (possibly truncated), or null when absent,
	 *                           unusable or over the byte cap.
	 */
	public static function decode_body( $body, &$incomplete = false ) {
		$incomplete = false;
		if ( ! is_string( $body ) || '' === $body ) {
			return null;
		}
		if ( strlen( $body ) > self::MAX_BYTES ) {
			$incomplete = true;
			return null;
		}
		$decoded = json_decode( $body, true, self::MAX_DEPTH );
		if ( ! is_array( $decoded ) || array() === $decoded ) {
			return null;
		}
		$budget     = self::MAX_ENTRIES;
		$truncated  = self::truncate( $decoded, $budget );
		$incomplete = 0 === $budget && $truncated !== $decoded;
		return $truncated;
	}

	/**
	 * Copy a structure until the budget is spent, in document order. Keys are preserved,
	 * so a truncated map is a PREFIX of the original rather than a renumbered one.
	 *
	 * @param array<mixed> $node   Structure to copy.
	 * @param int          $budget Entries still available; decremented as it copies.
	 * @return array<mixed>
	 */
	private static function truncate( array $node, &$budget ) {
		$out = array();
		foreach ( $node as $key => $value ) {
			if ( $budget < 1 ) {
				break;
			}
			--$budget;
			$out[ $key ] = is_array( $value ) ? self::truncate( $value, $budget ) : $value;
		}
		return $out;
	}

	/**
	 * Unpack every top-level field whose value is a JSON object/array, in place.
	 *
	 * Total by construction: never throws, whatever the input. A non-array input is
	 * returned unchanged with an empty side channel, so callers need no guard.
	 *
	 * @param mixed $fields The request's field map (request-derived, so not guaranteed
	 *                      to be an array).
	 * @return array{fields: mixed, raw: array<string,string>} The map with envelopes
	 *                      replaced by their structure, and the ORIGINAL string of each
	 *                      replaced field keyed by its field name (the side channel the
	 *                      blocklist check reads; empty when nothing was unpacked).
	 */
	public static function unpack( $fields ) {
		if ( ! is_array( $fields ) ) {
			return array(
				'fields' => $fields,
				'raw'    => array(),
			);
		}
		$raw    = array();
		$budget = self::MAX_ENTRIES;
		foreach ( $fields as $key => $value ) {
			if ( ! is_string( $value ) ) {
				continue;
			}
			$decoded = self::decode( $value, $budget );
			if ( null === $decoded ) {
				continue;
			}
			$fields[ $key ] = $decoded;
			$raw[ $key ]    = $value;
		}
		return array(
			'fields' => $fields,
			'raw'    => $raw,
		);
	}
}
