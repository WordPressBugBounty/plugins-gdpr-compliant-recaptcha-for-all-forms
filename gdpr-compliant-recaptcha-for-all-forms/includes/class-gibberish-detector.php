<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Pure, WordPress-independent gibberish detection (BACKLOG "Gibberish-Erkennung:
 * Binnen-Case-Wechsel-Regel").
 *
 * Motivation: a probing bot filled form fields with random mixed-case strings
 * (`vhIpaNIARAGVouiNF`, `mfYckaSlhNYNosFHemDmnLYc`) to test deliverability, not to
 * guess credentials. Entropy/vowel-ratio/bigram heuristics are unreliable across
 * the plugin's many locales (bigram tables need a language model and fail for
 * non-Latin scripts; consonant runs collide with German compounds like
 * "Angstschweiß"/"Borschtsch"). Inner upper/lower-case switching inside a single
 * word, however, is a convention humans never violate ("Wort"/"WORT"/"wort", never
 * "mfYckaSlh…") while still allowing the handful of genuine camelCase-ish outliers
 * (McDonald, iPhone, JavaScript) through.
 *
 * Rule (deterministic, language-neutral):
 * - Tokens >= MIN_TOKEN_LENGTH are scored on one of two paths (non-Latin scripts and
 *   punctuation are always neutral). PURE ASCII-Latin letters take the original path
 *   below. ALPHANUMERIC tokens (letters WITH interspersed digits) take a second path
 *   added 2026-08-03 after a bot switched to that shape to dodge the letters-only
 *   gate (a CF7 submission whose every field was a random string like "t9VO3ysAeW",
 *   "cyKmz0JLpD"): the letters-only compression is scored exactly like a pure-letter
 *   token but at the lower ALNUM_CASE_CHANGE_THRESHOLD, only when the compression is
 *   MIXED CASE and >= ALNUM_MIN_LETTERS long — a single-case+digits token (VAT id
 *   "DE123456789", serial "AB12CD34EF"), a pure-digit token (phone number, id) and a
 *   thin "a1B2c3D4" (4 compression letters) all stay neutral. See is_gibberish_token().
 *   The alphanumeric path contributes to the MESSAGE-LEVEL count only, never the
 *   single-token solo rule (a lone alphanumeric value — an order/reference number — is
 *   too often legitimate to convict on its own; the observed attack posts many).
 * - A token is gibberish at >= CASE_CHANGE_THRESHOLD "inner case changes": a new
 *   uppercase letter immediately following a lowercase letter, i.e. a camelCase
 *   hump NOT counting the token's own first character (see
 *   count_inner_case_changes()). This intentionally undercounts relative to a
 *   naive "every adjacent pair that differs" count — that naive count would flag
 *   McDonald (3 adjacent differences) as gibberish, which the spec explicitly
 *   requires to stay neutral.
 * - Legitimate camelCase COMPOUNDS with many humps (source code pasted into a
 *   support form: "updateFormTokenFields", "getUserAccountDataFromServer") are
 *   exempted via looks_like_camel_case_words(): every hump segment of a real
 *   compound carries a vowel, the random-case bot probes decompose into
 *   vowel-less junk segments.
 * - A message is flagged at >= MESSAGE_GIBBERISH_THRESHOLD gibberish tokens across
 *   all evaluated fields (a single token can be a legitimate product code) — OR,
 *   independently of that threshold, via the solo-token rule (field datum #3
 *   2026-07-17: a probe bot posted `MTAIPeUEidcjWAtXT` as the sole content of an
 *   otherwise empty form): a single gibberish token suffices when (a) it is the
 *   ENTIRE value of its field and (b) it is the only SCOREABLE token (>=
 *   MIN_TOKEN_LENGTH, pure ASCII letters — the same gate is_gibberish_token()
 *   applies) in the whole form. Condition (b) is the "form otherwise empty"
 *   guard, deliberately token-based rather than field-based: selects post their
 *   default label even on untouched forms ("-Thema auswählen-" — short and/or
 *   non-ASCII words, hence not scoreable, hence tolerated), while any real
 *   free-text content elsewhere (which almost always carries at least one
 *   scoreable word) suppresses the rule — protecting e.g. a support-form field
 *   that legitimately asks for a lone code-like identifier, as long as the rest
 *   of the form is actually filled in (user decision 2026-07-17).
 * - Exemptions: field names that look password-/code-like (is_exempt_field_name())
 *   are skipped entirely — real passwords and API keys ARE random strings, and
 *   this plugin also runs on login forms. URLs and email addresses are stripped
 *   from a field's value before tokenizing, so a domain segment such as
 *   "xKcDqWzP.com" never contributes a bare "xKcDqWzP" token.
 *
 * Known, deliberately accepted gap: strings with NO case signal at all slip
 * through — pure-lowercase ("xkcdqwzptv") and all-lowercase-plus-digits
 * ("ab3cd9ef"), since both the pure-letter and the alphanumeric path key on
 * lowercase->uppercase humps. See BACKLOG.md history. Conservative on purpose; a
 * consonant-run heuristic was considered and rejected (German compounds/
 * transliterations make it unreliable).
 *
 * No WordPress dependencies (no options, no $wpdb, no hooks) → deterministically
 * unit-testable, see tests/unit/GibberishDetectorTest.php. Stamp::check_submit()
 * is the only caller on the server side.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 *
 * Stateless gibberish-token/-message detection.
 */
final class Gibberish_Detector {

	/** Tokens shorter than this are never scored (too short to be conclusive). */
	const MIN_TOKEN_LENGTH = 8;

	/** Inner case-change count at/above which a single pure-letter token counts as gibberish. */
	const CASE_CHANGE_THRESHOLD = 3;

	/**
	 * Inner case-change count at/above which an ALPHANUMERIC token (letters with
	 * interspersed digits) counts as gibberish. Lower than the pure-letter threshold
	 * because interspersed digits are themselves an extra tell — legitimate free-text
	 * words do not carry them, so a random-case letter run mixed with digits needs
	 * fewer humps to be conclusive. Still guarded by the mixed-case requirement and
	 * the camelCase-compound exemption (see is_gibberish_token()).
	 */
	const ALNUM_CASE_CHANGE_THRESHOLD = 2;

	/**
	 * Minimum length of the letters-only compression for the alphanumeric path. The
	 * lower case-change threshold there (2) would otherwise convict on very thin
	 * evidence — "a1B2c3D4" compresses to just "aBcD" (4 letters, 2 humps). Requiring
	 * >= 6 compression letters keeps the two-hump verdict grounded; all observed spam
	 * tokens compress to 6–9 letters, so it costs nothing against the real probes.
	 */
	const ALNUM_MIN_LETTERS = 6;

	/** Gibberish-token count at/above which a whole message counts as suspicious. */
	const MESSAGE_GIBBERISH_THRESHOLD = 2;

	/**
	 * Case-insensitive substrings of a field name that exempt it from scoring
	 * entirely. Real passwords/API keys/tokens/coupon codes ARE random strings —
	 * scoring them would produce guaranteed false positives, and this plugin also
	 * protects login forms. Deliberately the exact list from the BACKLOG entry;
	 * kept short and specific rather than guessed-broad.
	 *
	 * @var string[]
	 */
	const EXEMPT_FIELD_NAME_SUBSTRINGS = array( 'pass', 'pwd', 'token', 'code', 'coupon' );

	/**
	 * Count "inner" case changes in a token: the number of positions (starting
	 * after the token's first character) where an uppercase letter immediately
	 * follows a lowercase letter — i.e. camelCase-style humps, not counting the
	 * token's own leading capital.
	 *
	 * Deliberately NOT "every adjacent pair whose case differs" (that naive count
	 * would give McDonald=3, misclassifying it as gibberish at the >=3 threshold).
	 * Counting only lowercase->uppercase transitions matches all of the spec's
	 * worked examples: McDonald/iPhone/JavaScript = 1 (their single hump), while
	 * random mixed-case strings accumulate several as case flips repeatedly.
	 *
	 * Operates byte-wise; callers are expected to have already established the
	 * token is pure ASCII (see is_gibberish_token()) — non-ASCII bytes are simply
	 * neither ctype_lower() nor ctype_upper() and never contribute a transition.
	 *
	 * @param string $token Token to inspect.
	 * @return int Number of inner lowercase->uppercase transitions.
	 */
	public static function count_inner_case_changes( $token ) {
		$token   = (string) $token;
		$length  = strlen( $token );
		$changes = 0;
		for ( $i = 1; $i < $length; $i++ ) {
			if ( ctype_lower( $token[ $i - 1 ] ) && ctype_upper( $token[ $i ] ) ) {
				++$changes;
			}
		}
		return $changes;
	}

	/**
	 * Whether a single token counts as gibberish: long enough, purely ASCII Latin
	 * letters, at/above the inner-case-change threshold, AND not a legitimate
	 * camelCase compound (see looks_like_camel_case_words()) — source code pasted
	 * into a support form is full of multi-word identifiers like
	 * "updateFormTokenFields" (3 humps) that would otherwise be flagged.
	 *
	 * @param string $token Token to inspect.
	 * @return bool
	 */
	public static function is_gibberish_token( $token ) {
		$token = (string) $token;
		if ( strlen( $token ) < self::MIN_TOKEN_LENGTH ) {
			return false;
		}
		// Pure ASCII-Latin-letter path (original rule, unchanged): non-Latin scripts
		// and punctuation fail the regex and are neutral.
		if ( 1 === preg_match( '/^[A-Za-z]+$/', $token ) ) {
			if ( self::count_inner_case_changes( $token ) < self::CASE_CHANGE_THRESHOLD ) {
				return false;
			}
			return ! self::looks_like_camel_case_words( $token );
		}
		// Alphanumeric path: letters WITH interspersed digits. Bots switched to this
		// shape once the letters-only rule shipped (field datum 2026-08-03: a CF7
		// submission whose every field was a random string like "t9VO3ysAeW"). The
		// discriminator is the letters-only compression (digits removed): it must be
		// mixed case (all-caps+digits is a VAT id / serial / order number → neutral),
		// carry >= ALNUM_CASE_CHANGE_THRESHOLD humps, and NOT decompose into
		// vowel-bearing camelCase words ("iPhone12Pro" → "iPhonePro" stays neutral).
		$letters = self::alnum_letters_only( $token );
		if ( null === $letters || strlen( $letters ) < self::ALNUM_MIN_LETTERS ) {
			return false;
		}
		if ( self::count_inner_case_changes( $letters ) < self::ALNUM_CASE_CHANGE_THRESHOLD ) {
			return false;
		}
		return ! self::looks_like_camel_case_words( $letters );
	}

	/**
	 * For an alphanumeric token (letters + digits), return its letters-only
	 * compression IFF the token is an eligible candidate for the alphanumeric
	 * gibberish path; otherwise null. Eligible means: purely [A-Za-z0-9], contains
	 * at least one digit AND at least one letter, and the letters include BOTH an
	 * uppercase and a lowercase one.
	 *
	 * Everything else returns null and stays neutral: pure-letter tokens (handled by
	 * the original path in is_gibberish_token()), pure-digit tokens (phone numbers,
	 * ids, dates split on '-'), and single-case + digits tokens — a VAT id like
	 * "DE123456789" or a serial "AB12CD34EF" carries only uppercase letters and must
	 * never be scored. The mixed-case requirement is the key false-positive guard:
	 * legitimate machine-readable codes are overwhelmingly single-case.
	 *
	 * @param string $token Token to inspect (caller has already checked length).
	 * @return string|null Letters-only compression, or null if not an eligible candidate.
	 */
	private static function alnum_letters_only( $token ) {
		$token = (string) $token;
		if ( 1 !== preg_match( '/^[A-Za-z0-9]+$/', $token ) ) {
			return null;
		}
		$letters = (string) preg_replace( '/[^A-Za-z]/', '', $token );
		// '' → the token is pure digits; $letters === $token → no digit at all (the
		// pure-letter path already handled it). Either way: not this path.
		if ( '' === $letters || $letters === $token ) {
			return null;
		}
		if ( 1 !== preg_match( '/[A-Z]/', $letters ) || 1 !== preg_match( '/[a-z]/', $letters ) ) {
			return null;
		}
		return $letters;
	}

	/**
	 * Whether a many-humped token is a legitimate camelCase COMPOUND rather than a
	 * random-case string: split at every lowercase->uppercase boundary, a real
	 * camelCase identifier ("updateFormTokenFields" → update|Form|Token|Fields)
	 * yields pronounceable word segments that each contain a vowel, while the
	 * random-case bot probes decompose into consonant junk
	 * ("vhIpaNIARAGVouiNF" → vh|Ipa|NIARAGVoui|NF — "vh" has no vowel;
	 * "mfYckaSlhNYNosFHemDmnLYc" → mf|Ycka|Slh|… — "mf"/"Slh"/"Dmn" have none).
	 * Rule: camelCase-like iff EVERY segment contains at least one vowel
	 * (a/e/i/o/u/y, either case — y covers "Sync"/"By"-style words).
	 *
	 * Deliberately accepted residual gap (same family as the pure-lowercase gap in
	 * the class docblock): a random string whose every hump segment happens to
	 * contain a vowel slips through — such strings are word-shaped, and the spec
	 * already concedes that word-shaped noise (LLM text) beats any deterministic
	 * heuristic. Only consulted for tokens already past the pure-ASCII-Latin gate.
	 *
	 * @param string $token Pure ASCII-letter token with >= CASE_CHANGE_THRESHOLD humps.
	 * @return bool
	 */
	public static function looks_like_camel_case_words( $token ) {
		$segments = preg_split( '/(?<=[a-z])(?=[A-Z])/', (string) $token );
		if ( false === $segments ) {
			return false;
		}
		foreach ( $segments as $segment ) {
			if ( 1 !== preg_match( '/[aeiouy]/i', $segment ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Whether a field name looks password-/code-/token-like and should therefore
	 * be exempted from gibberish scoring entirely (case-insensitive substring
	 * match against EXEMPT_FIELD_NAME_SUBSTRINGS).
	 *
	 * @param string $name Field name.
	 * @return bool
	 */
	public static function is_exempt_field_name( $name ) {
		$name = strtolower( (string) $name );
		foreach ( self::EXEMPT_FIELD_NAME_SUBSTRINGS as $needle ) {
			if ( false !== strpos( $name, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Split a field value into candidate letters/digits tokens, having first
	 * stripped URLs and email addresses so a domain segment (e.g. "xKcDqWzP.com")
	 * never leaves behind a bare gibberish-looking token. Multibyte-safe: bails
	 * out to "no tokens" instead of corrupting output on invalid UTF-8, since
	 * non-ASCII tokens are neutral anyway (see is_gibberish_token()).
	 *
	 * @param string $value Raw field value.
	 * @return string[] Candidate tokens (letters/digits runs; punctuation/whitespace
	 *                   already stripped as separators).
	 */
	private static function extract_candidate_tokens( $value ) {
		$value = (string) $value;
		if ( '' === $value || 1 !== preg_match( '//u', $value ) ) {
			// Empty, or not valid UTF-8 — the multibyte-aware regexes below require
			// valid UTF-8 input; bail out neutral rather than risk mangled output.
			return array();
		}

		// Drop URLs and email addresses BEFORE tokenizing: neither their scheme/
		// local part nor a bare "word.tld" domain segment should ever surface as a
		// standalone letters-only token.
		$value = (string) preg_replace( '/\S*(?:https?:\/\/|www\.)\S*/iu', ' ', $value );
		$value = (string) preg_replace( '/\S+@\S+/u', ' ', $value );
		$value = (string) preg_replace( '/[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+/u', ' ', $value );

		$tokens = preg_split( '/[^\p{L}\p{N}]+/u', $value, -1, PREG_SPLIT_NO_EMPTY );

		return false === $tokens ? array() : $tokens;
	}

	/**
	 * Whether a token is even ELIGIBLE for gibberish scoring: long enough and
	 * purely ASCII Latin letters — the exact gate is_gibberish_token() applies
	 * before looking at case changes. Used by the solo-token rule as its "form
	 * otherwise empty" measure: a scoreable token anywhere else in the form is
	 * evidence of substantial free-text content (short words like "Thema" and
	 * non-ASCII words like "auswählen" are deliberately NOT substantial — select
	 * defaults post exactly such labels on untouched forms).
	 *
	 * @param string $token Token to inspect.
	 * @return bool
	 */
	private static function is_scoreable_token( $token ) {
		$token = (string) $token;
		if ( strlen( $token ) < self::MIN_TOKEN_LENGTH ) {
			return false;
		}
		// A token is "substantial content" if it is either a pure-letter word or an
		// alphanumeric mixed-case+digit candidate (the same two shapes
		// is_gibberish_token() evaluates). Counting the alphanumeric shape here keeps
		// the solo-token rule consistent: a lone alphanumeric gibberish token as a
		// form's sole content can trigger it, and a legitimate alphanumeric value
		// elsewhere counts as substantial content that suppresses it.
		return 1 === preg_match( '/^[A-Za-z]+$/', $token ) || null !== self::alnum_letters_only( $token );
	}

	/**
	 * Scan a (possibly nested) field-name => value map for gibberish tokens,
	 * skipping exempt field names and recursing defensively into nested arrays
	 * (form builders occasionally post nested structures). The exemption check
	 * runs BEFORE the array recursion, so an exempt name shields its entire
	 * subtree (e.g. a `codes[]` multi-input posts as an array under one name).
	 *
	 * Besides the total gibberish count, reports the total number of SCOREABLE
	 * tokens (see is_scoreable_token()) and whether any scalar field value
	 * consisted of EXACTLY one candidate token that is gibberish — evaluated per
	 * scalar leaf, so one gibberish-only entry of a `text[]` multi-input counts
	 * too. is_gibberish_message() combines the three into the solo-token rule.
	 *
	 * @param array $fields     Field name => value (value may itself be an array).
	 * @param array $exempt_map Lowercased extra exempt field name => true.
	 * @return array{0: int, 1: bool, 2: int} Gibberish-token count, lone-in-its-field
	 *                                        gibberish hit, scoreable-token count.
	 */
	private static function scan_gibberish_tokens( $fields, $exempt_map ) {
		$count     = 0;
		$lone      = false;
		$scoreable = 0;
		foreach ( $fields as $name => $value ) {
			$name = (string) $name;
			if ( self::is_exempt_field_name( $name ) || isset( $exempt_map[ strtolower( $name ) ] ) ) {
				continue;
			}
			if ( is_array( $value ) ) {
				list( $child_count, $child_lone, $child_scoreable ) = self::scan_gibberish_tokens( $value, $exempt_map );
				$count     += $child_count;
				$lone       = $lone || $child_lone;
				$scoreable += $child_scoreable;
				continue;
			}
			if ( ! is_scalar( $value ) ) {
				continue;
			}
			$tokens          = self::extract_candidate_tokens( (string) $value );
			$field_gibberish = 0;
			foreach ( $tokens as $token ) {
				if ( self::is_scoreable_token( $token ) ) {
					++$scoreable;
				}
				if ( self::is_gibberish_token( $token ) ) {
					++$field_gibberish;
				}
			}
			$count += $field_gibberish;
			// Solo-token rule triggers ONLY on a pure-letter gibberish token. A lone
			// ALPHANUMERIC value as a form's sole content is far more often legitimate
			// (an order/reference number, a licence key in a field not named *code*),
			// so the alphanumeric path deliberately contributes to the message-level
			// count only, never the single-token trigger — while still counting as
			// scoreable content (see is_scoreable_token()) so a legitimate alphanumeric
			// value elsewhere suppresses the rule.
			if ( 1 === count( $tokens ) && 1 === $field_gibberish
				&& 1 === preg_match( '/^[A-Za-z]+$/', (string) $tokens[0] ) ) {
				$lone = true;
			}
		}
		return array( $count, $lone, $scoreable );
	}

	/**
	 * Whether a whole message (its field name => value map) is suspicious: at
	 * least MESSAGE_GIBBERISH_THRESHOLD gibberish tokens across all evaluated
	 * fields, or — solo-token rule, see class docblock — a lone gibberish token
	 * that is both the entire value of its field AND the only scoreable token in
	 * the whole form (i.e. the form carries no other substantial free text).
	 * Callers are responsible for having already stripped the plugin's own
	 * fields (see Stamp::strip_plugin_fields()) before calling this.
	 *
	 * @param mixed    $fields             Field name => value map (values may be nested
	 *                                     arrays). Accepts non-array input defensively
	 *                                     (treated as neutral) since callers pass
	 *                                     request-derived data.
	 * @param string[] $extra_exempt_names Additional field names to skip (matched
	 *                                     case-insensitively at any nesting level) —
	 *                                     e.g. the request's hashPWFields password
	 *                                     skip list and POW_SKIP_FIELDS entries, whose
	 *                                     values are legitimately random strings.
	 * @return bool
	 */
	public static function is_gibberish_message( $fields, $extra_exempt_names = array() ) {
		if ( ! is_array( $fields ) ) {
			return false;
		}
		$exempt_map = array();
		foreach ( $extra_exempt_names as $name ) {
			if ( '' !== $name ) {
				$exempt_map[ strtolower( $name ) ] = true;
			}
		}
		list( $count, $lone, $scoreable ) = self::scan_gibberish_tokens( $fields, $exempt_map );
		// Solo-token rule: the lone gibberish token is necessarily scoreable
		// itself, so "scoreable === 1" means NO other scoreable token exists
		// anywhere in the form — the "form otherwise empty" guard.
		if ( $lone && 1 === $scoreable ) {
			return true;
		}
		return $count >= self::MESSAGE_GIBBERISH_THRESHOLD;
	}
}
