<?php
/**
 * Pure, WordPress-independent matching of an admin-configured FIELD PATTERN against a
 * request's field map — the second signature class alongside admin-ajax actions
 * (Explicit mode) and REST routes (RestRoute). See handbuch/gate.md.
 *
 * WHY THIS CLASS EXISTS AT ALL — it holds no new logic. matches() is the former
 * Stamp::check_pattern() moved here VERBATIM, and Stamp::check_existing_patterns() now
 * calls line_matches() instead of interpreting a line itself. The move happened for the
 * save-time guard below (overbroad_lines()): a guard that warns about a pattern must
 * decide "does this line match?" EXACTLY as the live gate decides it. A second, similar
 * implementation would be worse than no guard at all — it would eventually stay silent
 * on a dangerous line and cry wolf on a harmless one, and nothing would notice, because
 * the two implementations are only ever exercised apart. So there is ONE implementation
 * and the guard is built out of it; divergence is not a discipline problem here, it is
 * constructively impossible. Pinned by tests/unit/PatternMatcherEquivalenceTest.php,
 * which asserts both halves: the source-level wiring AND the behaviour.
 *
 * THE MATCHING SEMANTICS, exactly as they have always been (each one is load-bearing —
 * a pattern is a monitoring rule, so widening it monitors more and narrowing it monitors
 * less, and both directions are security-relevant):
 *   - A line is JSON, decoded WITHOUT the assoc flag: nested objects arrive as stdClass,
 *     not arrays. matches() therefore has to handle both shapes.
 *   - `null` as a value means KEY EXISTENCE only ("the request carries this field").
 *   - Any other value is compared STRICTLY (`!==`) — every $_REQUEST value is a string,
 *     so `{"post_ID":12}` (a JSON number) never matches the string "12".
 *   - isset() is the existence test, so a field whose value IS null counts as absent.
 *   - Nested objects/arrays recurse.
 *   - An unparsable line decodes to null and is silently ignored (`! $pattern` below) —
 *     a typo in the textarea disables that one line, it never throws and never matches.
 *   - `{"*":"value"}` is the FIELD-NAME WILDCARD — the ONE named exception to the strict
 *     comparison, spelled out in the next paragraph.
 *
 * THE ONE NAMED EXCEPTION — the field-name wildcard `{"*":"value"}`. Strict comparison
 * (`!==`) REMAINS the rule; this is not a softening of it but a single, specified
 * carve-out, and it is deliberately narrow: ONLY a STRING value under the key `*` arms
 * it. It asks a different question from every other pattern key — not "does the field
 * called X hold this value?" but "does SOME field, at any depth of the subtree currently
 * being compared, hold this value?" — and it compares NORMALIZED: trim + lowercase on
 * BOTH sides. Everything else about the semantics above is untouched:
 *   - The type-strictness quirk survives intact, because a non-string value never arms
 *     the wildcard in the first place: `{"*":123}` keeps its literal, strictly compared
 *     meaning ("a field literally named `*` holding the integer 123" — which no
 *     $_REQUEST, whose values are all strings, ever satisfies), exactly as
 *     `{"post_ID":12}` still never matches the string "12". `{"*":null}` likewise keeps
 *     its literal key-existence meaning.
 *   - A field literally CALLED `*` that carries the value still matches — normalized
 *     equality is implied by strict equality. The wildcard therefore only ever ADDS
 *     matches; no request that a line matches today goes unmatched because of it.
 *   - Locality: the search covers the subtree being compared, not the whole request.
 *     `{"a":{"*":"x"}}` looks inside $request['a'] only — consistent with the recursion.
 *   - Several keys stay AND-ed: `{"_wpcf7":null,"*":"x"}` means "field _wpcf7 exists AND
 *     some field equals x".
 *   - A value that is empty after normalization does NOT arm the wildcard and stays
 *     literal. `{"*":""}` was never a live rule (Echo_Values::wildcard_values_from_lines()
 *     has always dropped an empty value), and arming it would mean "monitor every
 *     submission that has any empty field", i.e. nearly all of them — a widening nobody
 *     asked for.
 *   - The walk is depth-limited (WILDCARD_MAX_DEPTH, the same 6 as Echo_Values::MAX_DEPTH)
 *     and handles arrays AND stdClass, because both shapes reach this class.
 *
 * WHY trim + lowercase, of all comparisons: the normalization is INHERITED from the
 * blocked-value lines that used to share this textarea — Echo_Values::matches_wildcard_values()
 * has always compared those that way, and Echo_Values::normalize_wildcard() is reused
 * here verbatim so the plugin keeps exactly one definition of "normalized". The wildcard
 * is the MONITORING successor of that very line shape, so it inherits its comparison.
 *
 * No WordPress dependencies (no get_option(), no $_REQUEST, no translation) — the caller
 * supplies the option text and the field map. Unit-tested in isolation:
 * tests/unit/PatternMatcherTest.php, PatternGuardTest.php, PatternMatcherEquivalenceTest.php.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/gate.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Stateless field-pattern matching helpers.
 */
final class Pattern_Matcher {

	/**
	 * The pattern key that means "any field name", i.e. the field-name wildcard
	 * described in the class doc-comment. Only a STRING value under this key arms it.
	 *
	 * @var string
	 */
	const WILDCARD_KEY = '*';

	/**
	 * How deep the wildcard walk descends into a nested request before giving up.
	 *
	 * A pattern key names one level, so it cannot run away; the wildcard walks the whole
	 * subtree and therefore needs a bound of its own. Deliberately the same 6 as
	 * Echo_Values::MAX_DEPTH, which walks the same request maps for the same reason —
	 * two different limits on two walks over one structure would only ever confuse.
	 *
	 * @var int
	 */
	const WILDCARD_MAX_DEPTH = 6;

	/**
	 * Realistic $_REQUEST maps of the WordPress CORE backend POSTs, used by
	 * overbroad_lines() to answer one question at save time: would this pattern line
	 * also match a request wp-admin itself sends?
	 *
	 * WHY THIS IS NEEDED (handbuch/gate.md, "Der eine Fall, in dem es doch beisst"):
	 * the constructor gate does not distinguish frontend from backend traffic, so a
	 * pattern generic enough to match a core screen turns that screen's save into a spam
	 * verdict — and with POW_BLOCK on by default the save is discarded. The admin cannot
	 * work around it either, because wp-admin never receives the PoW script, so there is
	 * no challenge to solve. `{"email":null}` is the measured example (profile save
	 * blocked); it is pinned as a deliberate cost case in
	 * tests/integration/cases/backend-posts.mjs.
	 *
	 * VALUES, NOT ONLY KEYS, and all of them STRINGS: a pattern may pin a value
	 * (`{"action":"update"}`), and that comparison is strict, so a key-only catalog
	 * would silently miss exactly the patterns that name a core value. Every $_REQUEST
	 * value really is a string, and the catalog has to be shaped like the thing it
	 * stands in for.
	 *
	 * Field names verified against the WordPress core sources in the wp-env cache, not
	 * recalled: wp-admin/user-edit.php, wp-admin/options-general.php (+ settings_fields()
	 * in wp-admin/includes/plugin.php, which emits option_page/action), edit-form-advanced.php
	 * (+ the `save` submit button and the `excerpt` box in wp-admin/includes/meta-boxes.php),
	 * user-new.php and edit-form-comment.php. `_wpnonce`/`_wp_http_referer` come from
	 * wp_nonce_field()'s defaults; user-new names its nonce field explicitly.
	 *
	 * DELIBERATELY NOT IN THIS CATALOG: backend saves that travel over admin-ajax
	 * (Heartbeat, inline "quick edit", plugin updates, the block editor's autosave …).
	 * They cannot be reached by a field pattern at all — the ajax branch of the triage
	 * matches EXCLUSIVELY against the action list, it never calls
	 * check_existing_patterns() (handbuch/gate.md, "Welcher Zweig welche Klasse nutzt").
	 * Listing them would produce warnings about a danger that does not exist, which is
	 * the fastest way to teach an admin to click the warning away.
	 *
	 * Also not here: the block editor's REST save (`/wp/v2/posts/<id>`). It is a real
	 * lockout risk, but a route one — guarded at save time by
	 * RestRoute::reject_self_lockout_lines(), on the option where routes are configured.
	 *
	 * The keys are STABLE IDENTIFIERS, not display text: this class is WordPress-free and
	 * must not translate. The settings page turns them into a human, translated screen
	 * name when it renders the warning.
	 *
	 * @var array<string, array<string, string>>
	 */
	const CORE_BACKEND_SIGNATURES = array(
		// wp-admin/user-edit.php and profile.php — "Profile" / "Edit user".
		'profile'         => array(
			'action'           => 'update',
			'user_id'          => '1',
			'checkuser_id'     => '1',
			'user_login'       => 'admin',
			'role'             => 'administrator',
			'first_name'       => 'Jane',
			'last_name'        => 'Doe',
			'nickname'         => 'jane',
			'display_name'     => 'Jane Doe',
			'email'            => 'jane@example.com',
			'url'              => 'https://example.com',
			'description'      => 'Just another user.',
			'rich_editing'     => 'false',
			'admin_bar_front'  => '1',
			// A profile save posts both password fields; they are empty unless the
			// password is actually being changed.
			'pass1'            => '',
			'pass2'            => '',
			'_wpnonce'         => 'ffffffffff',
			'_wp_http_referer' => '/wp-admin/profile.php',
			'submit'           => 'Update Profile',
		),
		// wp-admin/options-general.php, submitted to options.php — "General settings".
		'options-general' => array(
			'option_page'        => 'general',
			'action'             => 'update',
			'blogname'           => 'Example site',
			'blogdescription'    => 'Just another WordPress site',
			'siteurl'            => 'https://example.com',
			'home'               => 'https://example.com',
			'new_admin_email'    => 'jane@example.com',
			'users_can_register' => '1',
			'default_role'       => 'subscriber',
			'timezone_string'    => 'Europe/Berlin',
			'date_format'        => 'F j, Y',
			'time_format'        => 'g:i a',
			'start_of_week'      => '1',
			'_wpnonce'           => 'ffffffffff',
			'_wp_http_referer'   => '/wp-admin/options-general.php',
			'submit'             => 'Save Changes',
		),
		// wp-admin/edit-form-advanced.php, submitted to post.php — the classic editor.
		'post-editor'     => array(
			'action'               => 'editpost',
			'originalaction'       => 'editpost',
			'post_type'            => 'post',
			'post_ID'              => '42',
			'post_author'          => '1',
			'user_ID'              => '1',
			'original_post_status' => 'draft',
			'post_title'           => 'Hello world',
			'content'              => 'The post body.',
			'excerpt'              => '',
			'referredby'           => 'https://example.com/wp-admin/edit.php',
			'save'                 => 'Update',
			'_wpnonce'             => 'ffffffffff',
			'_wp_http_referer'     => '/wp-admin/post.php',
		),
		// wp-admin/user-new.php — "Add new user".
		'user-new'        => array(
			'action'                 => 'createuser',
			'user_login'             => 'jane',
			'email'                  => 'jane@example.com',
			'first_name'             => 'Jane',
			'last_name'              => 'Doe',
			'url'                    => 'https://example.com',
			'pass1'                  => '',
			'pass2'                  => '',
			'role'                   => 'subscriber',
			'send_user_notification' => '1',
			'_wpnonce_create-user'   => 'ffffffffff',
			'_wp_http_referer'       => '/wp-admin/user-new.php',
			'createuser'             => 'Add User',
		),
		// wp-admin/edit-form-comment.php, submitted to comment.php — "Edit comment".
		'comment-edit'    => array(
			'action'                  => 'editedcomment',
			'comment_ID'              => '7',
			'comment_post_ID'         => '42',
			'newcomment_author'       => 'Jane Doe',
			'newcomment_author_email' => 'jane@example.com',
			'newcomment_author_url'   => 'https://example.com',
			'content'                 => 'A comment body.',
			'comment_status'          => '1',
			'c'                       => '7',
			'p'                       => '42',
			'referredby'              => 'https://example.com/wp-admin/edit-comments.php',
			'noredir'                 => '1',
			'save'                    => 'Update',
			'_wpnonce'                => 'ffffffffff',
			'_wp_http_referer'        => '/wp-admin/comment.php',
		),
	);

	/**
	 * Whether $request satisfies the decoded pattern $pattern — the plugin's ONE
	 * field-pattern comparison, moved here verbatim from Stamp::check_pattern().
	 *
	 * Semantics are documented in the file header; every one of them is behaviour the
	 * installed base depends on, so this body is deliberately unchanged rather than
	 * "cleaned up" (an empty JSON object still matches everything, a falsy pattern still
	 * matches nothing). The field-name wildcard is the one addition — a branch in FRONT
	 * of the untouched comparison chain, never a change to it.
	 *
	 * @param mixed $pattern Decoded pattern line — stdClass/array, or anything json_decode()
	 *                       returned for a line that was not a JSON object.
	 * @param mixed $request Field map to test (an array, or a nested stdClass/array while
	 *                       recursing).
	 * @return bool
	 */
	public static function matches( $pattern, $request ): bool {
		if ( ! $pattern || ! $request ) {
			return false;
		}
		if ( is_object( $request ) ) {
			$request = get_object_vars( $request );
		}
		if ( is_object( $pattern ) ) {
			$pattern = get_object_vars( $pattern );
		}
		foreach ( $pattern as $key => $value ) {
			// FIELD-NAME WILDCARD (class doc-comment, "the one named exception"): a
			// STRING under the key `*` asks whether SOME field of this subtree carries
			// the value, compared normalized. Anything else — including `*` with a
			// non-string value — falls through to the strict chain below unchanged.
			$wildcard = ( self::WILDCARD_KEY === (string) $key && is_string( $value ) )
				? Echo_Values::normalize_wildcard( $value )
				: '';
			if ( '' !== $wildcard ) {
				if ( ! self::value_exists_anywhere( $request, $wildcard ) ) {
					return false;
				}
				continue;
			}
			// A nested object/array in the pattern is matched recursively.
			if ( is_array( $value ) || is_object( $value ) ) {
				if ( ! isset( $request[ $key ] ) || ! self::matches( $value, $request[ $key ] ) ) {
					return false;
				}
			} elseif ( null !== $value ) {
				// Non-null value: the key must exist AND hold exactly this value.
				if ( ! isset( $request[ $key ] ) || $pattern[ $key ] !== $request[ $key ] ) {
					return false;
				}
				// Null value: the key only has to exist.
			} elseif ( ! isset( $request[ $key ] ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Whether ANY field of $request — at any depth, under any name — carries a value
	 * that normalizes to $needle. The engine behind the field-name wildcard.
	 *
	 * $needle arrives ALREADY normalized (the caller ran Echo_Values::normalize_wildcard()
	 * on the pattern side), so the normalization happens exactly once per side; passing a
	 * raw needle here would silently compare a trimmed value against an untrimmed one.
	 *
	 * Only scalar leaves are compared, and they are cast to string first — the rest of
	 * this class treats request values as strings for the same reason ($_REQUEST really
	 * only holds strings, but a decoded JSON body can hand us numbers and booleans). A
	 * leaf that IS null is skipped, which keeps the isset()-shaped "a null value counts
	 * as absent" reading of the strict branch.
	 *
	 * @param mixed  $request Field map (array or stdClass), or any leaf while recursing.
	 * @param string $needle  Already-normalized value to look for; never empty.
	 * @param int    $depth   Current recursion depth, bounded by WILDCARD_MAX_DEPTH.
	 * @return bool
	 */
	private static function value_exists_anywhere( $request, string $needle, int $depth = 0 ): bool {
		if ( is_object( $request ) ) {
			$request = get_object_vars( $request );
		}
		if ( ! is_array( $request ) ) {
			return false;
		}
		foreach ( $request as $value ) {
			if ( is_array( $value ) || is_object( $value ) ) {
				if ( $depth < self::WILDCARD_MAX_DEPTH
					&& self::value_exists_anywhere( $value, $needle, $depth + 1 ) ) {
					return true;
				}
			} elseif ( is_scalar( $value ) && Echo_Values::normalize_wildcard( $value ) === $needle ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether ONE raw line of the POW_PARAMETER_PATTERN textarea matches $request.
	 *
	 * This is the whole interpretation of a line — trim, decode WITHOUT the assoc flag
	 * (so nested objects stay stdClass, which matches() expects), compare. Callers must
	 * never do any of that themselves; that is the entire point of this class. An
	 * unparsable line decodes to null, which matches() rejects: the line is ignored, it
	 * never throws.
	 *
	 * @param string $raw_line One line as entered by the administrator.
	 * @param mixed  $request  Field map to test (typically $_REQUEST).
	 * @return bool
	 */
	public static function line_matches( string $raw_line, $request ): bool {
		$line = trim( $raw_line );
		// Deliberately no assoc flag — see the class doc-comment.
		$pattern = json_decode( $line );
		return self::matches( $pattern, $request );
	}

	/**
	 * SAVE-TIME GUARD for POW_PARAMETER_PATTERN: which of these lines would also match a
	 * WordPress core backend POST?
	 *
	 * Unlike RestRoute::reject_self_lockout_lines(), this one does NOT discard anything
	 * permanently. A generic pattern is a legitimate choice on a site whose forms need
	 * it, and the cost case is recoverable by editing the pattern — it is the SURPRISE
	 * that hurts, because the symptom (a profile save silently discarded) points nowhere
	 * near its cause. So a flagged line is HELD BACK ONCE and NAMED, and it is stored on
	 * the next save if the administrator confirms it: Settings_Menu::update_settings()
	 * skips update_option() for this one key (`continue`) while parking the submitted
	 * text so the textarea renders it back, and Overbroad_Pattern_Guard::confirmed()
	 * decides — via a checkbox bound by hash to exactly these lines — whether the second
	 * save goes through. The decision stays with the administrator; only the silence does
	 * not.
	 *
	 * Uses line_matches() for every comparison and contains no matching of its own — if
	 * a line is flagged here, the live gate matches it too, by construction.
	 *
	 * @param string $option_value The complete textarea value, exactly as submitted.
	 * @return array<string, string[]> Trimmed offending line => CORE_BACKEND_SIGNATURES
	 *                                 keys it matches, in catalog order. Empty array =
	 *                                 nothing to warn about.
	 */
	public static function overbroad_lines( string $option_value ): array {
		$lines = preg_split( "/\r\n|\n|\r/", $option_value );
		if ( false === $lines ) {
			return array();
		}

		$flagged = array();
		foreach ( $lines as $raw_line ) {
			$hits = array();
			foreach ( self::CORE_BACKEND_SIGNATURES as $screen => $fields ) {
				if ( self::line_matches( $raw_line, $fields ) ) {
					$hits[] = $screen;
				}
			}
			if ( ! empty( $hits ) ) {
				$flagged[ trim( $raw_line ) ] = $hits;
			}
		}
		return $flagged;
	}
}
