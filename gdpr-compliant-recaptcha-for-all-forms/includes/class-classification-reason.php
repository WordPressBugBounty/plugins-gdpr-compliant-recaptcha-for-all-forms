<?php
/**
 * Pure, WordPress-independent classification-reason taxonomy (T1 of the trust-
 * instrumentation plan, see loop/docs/impl-plan.md).
 *
 * A "reason" is a short, machine-readable string naming WHY a submission was
 * classified as spam. It is meant to be stored verbatim with the message (as the
 * technical field `_gdpr_reason`) so the site owner can see the cause in the UI,
 * and so an exported message corpus carries a stable label per entry.
 *
 * Format: `code` or `code:detail`, both lower-case ASCII. The full taxonomy:
 *
 *   no_pow:no_token        Submission carried no proof-of-work token at all.
 *   no_pow:invalid_token   A token was posted but failed StampToken verification (or had a
 *                          length this build no longer accepts).
 *   no_pow:token_no_row    Valid token, but no solved-PoW row landed within the poll window.
 *   no_pow:chain_no_row    HISTORIC (5.3.0-5.3.3): valid chain token, but its row never
 *                          landed. Nothing writes it since 5.3.4 — see HISTORIC_CODES.
 *   no_pow:token_ip_changed
 *                          Valid token, no row, and redeemed from a different address
 *                          than it was issued to (cache/proxy signature — diagnosis).
 *   simulation             POW_SIMULATE_SPAM is on — everything is "spam" by configuration.
 *   echo_lock              A core value matched an auto-recorded recent spam value.
 *   wildcard               A user-content field matched a value on the operator's blocklist
 *                          (POW_BLOCKED_VALUES). The CODE stays `wildcard`: it is stored in
 *                          live databases and used as a corpus label, so it is never
 *                          renamed — only its source option and its label moved.
 *   quarantine             Under-attack quarantine held an otherwise-clean submission.
 *   gibberish:letters=<n>,alnum=<n>,solo=<0|1>[,strong=1]
 *                          Gibberish detection fired; the detail carries the scoring
 *                          components from Gibberish_Detector::analyze_message().
 *                          `strong=1` is appended only when the strong-token rule
 *                          fired, so labels written before 2026-08-10 stay
 *                          byte-identical to what the builder produces today.
 *
 * There is deliberately NO reason for a clean message: absence of a reason means
 * clean. Callers must therefore store null/nothing rather than inventing an "ok"
 * code — a code for cleanliness would be indistinguishable from an unlabelled
 * legacy row in the corpus.
 *
 * The reasons are not all equally load-bearing downstream: three of the no_pow
 * sub-cases must NOT feed the auto-echo lock with the submission's content values,
 * because they describe a failed handshake rather than the content — see
 * NON_SEEDING_REASONS / seeds_echo_values().
 *
 * The one thing that invariant costs is the ability to explain a NON-block, so that
 * lives in a separate datum with its own grammar and its own storage field:
 *
 *   scoring:letters=<n>,alnum=<n>,solo=<0|1>,strong=<0|1>,scoreable=<n>
 *                          Written to `_gdpr_scoring` (never `_gdpr_reason`) for a
 *                          message that passed every check, and only when such a
 *                          message is saved at all. See scoring().
 *
 * These strings are CORPUS LABELS: they end up in stored message rows and in
 * exported training data, so their stability matters more than their elegance.
 * Add new codes rather than renaming existing ones.
 *
 * No WordPress dependencies (no options, no $wpdb, no translation functions) →
 * unit-testable in isolation, see tests/unit/ClassificationReasonTest.php.
 * label() therefore returns plain English; the plugin UI is English throughout, and
 * a caller that wants escaping/translation applies it at the render site.
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
 * Stateless classification-reason strings and their UI labels.
 */
final class Classification_Reason {

	// Codes. A code that carries no detail IS the complete reason string
	// (CODE_SIMULATION === 'simulation'); the two codes that do carry a detail have
	// their own constants/builder below (NO_POW_* and gibberish()).

	/** No usable proof of work — see the five NO_POW_* constants for the sub-cases. */
	const CODE_NO_POW = 'no_pow';

	/** Spam simulation mode (POW_SIMULATE_SPAM) classified the submission. */
	const CODE_SIMULATION = 'simulation';

	/** Auto-echo lock: a core value matched a recently recorded spam value. */
	const CODE_ECHO_LOCK = 'echo_lock';

	/** A user-content field matched an operator-configured blocked value. */
	const CODE_WILDCARD = 'wildcard';

	/** Under-attack quarantine held an otherwise-clean submission. */
	const CODE_QUARANTINE = 'quarantine';

	/** Gibberish detection fired — detail carries the scoring components. */
	const CODE_GIBBERISH = 'gibberish';

	/**
	 * NOT a reason. The code of the separate `_gdpr_scoring` datum written for messages
	 * that were NOT classified as spam — see scoring(). Kept in this class because it
	 * shares the `code:detail` grammar and the same pure-string discipline, but it must
	 * never appear in `_gdpr_reason`: absence of a reason means clean, and that
	 * invariant is what the whole taxonomy rests on.
	 */
	const CODE_SCORING = 'scoring';

	/** No proof-of-work token was posted at all (the protocol-blind mass). */
	const NO_POW_NO_TOKEN = 'no_pow:no_token';

	/** A token was posted but failed verification (forged, expired, malformed). */
	const NO_POW_INVALID_TOKEN = 'no_pow:invalid_token';

	/** Token verified, but no solved-PoW row was found within the poll window. */
	const NO_POW_TOKEN_NO_ROW = 'no_pow:token_no_row';

	/**
	 * DISPLAY-ONLY SINCE 5.3.4. No code path writes this any more — the chain-token
	 * branch that produced it went with the ChainToken class. It stays because stored
	 * `_gdpr_reason` rows on installations that ran 5.3.0-5.3.3 still carry the string,
	 * and a message detail that renders a raw reason code instead of a sentence is a
	 * worse regression than an unused constant. Remove it with a general cleanup pass
	 * over historic reason strings, not on its own.
	 */
	const NO_POW_CHAIN_NO_ROW = 'no_pow:chain_no_row';

	/**
	 * Reason codes that NO code path writes any more — kept only so stored rows from
	 * older versions still render as a sentence instead of a raw code.
	 *
	 * Exists so the integration suite's coverage printout can tell "never covered"
	 * apart from "cannot be covered any more" without a second, hand-maintained list
	 * living in the test harness (which would drift from this class the moment either
	 * side changed). The fact belongs here, next to the constants it describes.
	 *
	 * @var string[]
	 */
	const HISTORIC_CODES = array( self::NO_POW_CHAIN_NO_ROW );

	/**
	 * Token valid and unexpired, but redeemed from a different address than it was
	 * issued to AND no usable row was found — the caching/proxy signature. Purely a
	 * LABEL: the address difference itself never rejects anything (see StampToken).
	 */
	const NO_POW_TOKEN_IP_CHANGED = 'no_pow:token_ip_changed';

	/**
	 * Reasons whose submissions must NOT seed the auto-echo lock with their CONTENT
	 * values — see seeds_echo_values(), which is the only thing that reads this.
	 *
	 * THE FIRST THREE share one property: a token that VERIFIED was presented, and only
	 * the solved-PoW row was missing. That is an infrastructure symptom (cache in front
	 * of `get_stamp`, proxy, a database that cannot store the row, two clocks —
	 * HANDBUCH.md §12 causes 4/7/8), not a statement about the submitted content.
	 *
	 * CODE_ECHO_LOCK is here for a different reason, and it is the general form of the
	 * same idea: a verdict that the echo lock itself produced must not RE-SEED the very
	 * values that produced it. Until 5.6.0 it did — an echo hit is a spam verdict like
	 * any other, so it recorded again and pushed the entry's expiry to now + TTL_SECONDS.
	 * The 36h therefore ran from the last HIT rather than from the last real spam, and
	 * every further submission carrying the value renewed it. A lock could not expire
	 * while it was being tripped.
	 *
	 * That is harmless while the locked value really is spam — the sender is blocked
	 * either way — and unbounded when it is not. One case MEASURED, one that follows
	 * from the mechanism:
	 *
	 *   - Measured (Echo_Values::build_echo_set()'s $no_text_roots, and arm C of
	 *     tests/integration/cases/ninja-forms-envelope.mjs): a value that is CONSTANT per
	 *     form — a builder's configuration text, a dropdown option label — locked the whole
	 *     form once a single genuine spam submission had seeded it, kept alive entirely by
	 *     legitimate traffic.
	 *   - Not measured, but constructively certain from record()'s expiry refresh: a FORGED
	 *     sender address stays blocked for as long as its real owner keeps trying to write,
	 *     each attempt renewing their own lock. That is the exact scenario TTL_SECONDS names
	 *     in its own docblock ("short enough that a forged sender address does not stay
	 *     blocked"), which is why the refresh contradicted the stated design.
	 *
	 * With the entry here, every echo false positive — the two above and any not yet
	 * known — is bounded by TTL_SECONDS from the last NON-echo spam verdict. The price
	 * is narrow and named: a repeat sender whose original verdict was deterministic
	 * (gibberish, blocklist) re-earns that same verdict on every attempt and keeps
	 * seeding through it, so nothing changes for them; only a sender whose ONLY verdict
	 * ever was an echo hit, and who waits out the TTL, is released — which is what a TTL
	 * is for.
	 *
	 * @var string[]
	 */
	const NON_SEEDING_REASONS = array(
		self::NO_POW_TOKEN_NO_ROW,
		self::NO_POW_TOKEN_IP_CHANGED,
		self::NO_POW_CHAIN_NO_ROW,
		self::CODE_ECHO_LOCK,
	);

	/**
	 * Short English UI label per CODE, keyed by the code part of a reason string.
	 * Intentionally code-level (not detail-level): the detail is diagnostic data for
	 * the corpus, the label answers "what kind of block was this?" at a glance.
	 *
	 * @var array<string,string>
	 */
	const CODE_LABELS = array(
		self::CODE_NO_POW     => 'No proof of work',
		self::CODE_SIMULATION => 'Simulation mode',
		self::CODE_ECHO_LOCK  => 'Known spam value',
		self::CODE_WILDCARD   => 'Blocked value',
		self::CODE_QUARANTINE => 'Under-attack quarantine',
		self::CODE_GIBBERISH  => 'Gibberish content',
	);

	/** Fallback label for an unknown, empty or malformed reason string. */
	const UNKNOWN_LABEL = 'Unknown reason';

	/**
	 * Human-readable explanation per FULL reason string (code plus detail), for the
	 * one question CODE_LABELS deliberately does not answer: *why* did this block
	 * happen? Several different causes share the label "No proof of work", and until
	 * they were surfaced, a site owner reading the message view could not tell a
	 * blocked bot from a caching layer breaking the handshake for every real visitor.
	 *
	 * WHY THIS IS A SECOND MAP AND NOT A CHANGE TO CODE_LABELS. The code label is a
	 * CORPUS label: it is stored in message rows and exported as training data, so its
	 * stability matters more than its detail (see the file header). This map is a pure
	 * UI affordance — it is never stored, never exported, and may be reworded freely.
	 *
	 * @var array<string,string>
	 */
	const DETAIL_LABELS = array(
		self::NO_POW_NO_TOKEN         => 'No token was submitted at all. Either the plugin\'s JavaScript did not run on that page, or its hidden field never made it into the submitted data.',
		self::NO_POW_INVALID_TOKEN    => 'A token was submitted, but it was not valid. A token is signed by this site and expires after a short time window, so this usually means a cache handed out an expired one (a full-page cache, a hoster or CDN cache in front of the token request, or an optimisation layer) — or it was forged.',
		self::NO_POW_TOKEN_NO_ROW     => 'The token itself was valid, but the solved puzzle never arrived in time. The browser computes it and posts it back separately, so this points at that request being blocked, failing, or arriving too late.',
		self::NO_POW_CHAIN_NO_ROW     => 'A follow-up token from an older version of this plugin was valid, but no solved puzzle was found for it. Follow-up tokens are no longer issued; a visitor still holding one from before the update can hit this once. Same causes as above.',
		self::NO_POW_TOKEN_IP_CHANGED => 'The token was valid, but it was redeemed from a different address than the one it was issued to, and no solved puzzle was found for it. That combination points at a cache or proxy in front of the site: several visitors share one cached token, or the visitor\'s address changes between requests. Check the "Trusted proxies" setting.',
	);

	/**
	 * Build the gibberish reason string from the scoring components reported by
	 * Gibberish_Detector::analyze_message().
	 *
	 * Detail format (stable): `letters=<n>,alnum=<n>,solo=<0|1>[,strong=1]` — the number
	 * of gibberish tokens found on the pure-letter path, the number found on the
	 * alphanumeric path, whether the solo-token rule fired (a single gibberish token as
	 * a form's entire content), and — appended only when it fired — whether the
	 * STRONG-token rule did (a single token whose case-change signal is far above any
	 * legitimate camelCase identifier, which convicts even next to real content).
	 * Counts are clamped at 0 so a malformed caller value can never produce a negative
	 * label.
	 *
	 * `strong` is APPENDED rather than always present, on purpose: these strings are
	 * corpus labels living in stored rows and exported training data, and every
	 * `gibberish:` label written before 2026-08-10 lacks the component. Appending only
	 * on a hit keeps every previously written label byte-identical to what this builder
	 * produces today, so old and new rows stay directly comparable.
	 *
	 * @param int  $letters Gibberish tokens found on the pure-letter path.
	 * @param int  $alnum   Gibberish tokens found on the alphanumeric path.
	 * @param bool $solo    Whether the solo-token rule fired.
	 * @param bool     $strong  Whether the strong-token rule fired.
	 * @param string[] $fields  Field names that carried the gibberish (6.0.0).
	 * @return string Reason string, e.g. "gibberish:letters=2,alnum=0,solo=0,field=your-message".
	 */
	public static function gibberish( $letters, $alnum, $solo, $strong = false, $fields = array() ) {
		return self::CODE_GIBBERISH . ':letters=' . max( 0, (int) $letters )
			. ',alnum=' . max( 0, (int) $alnum )
			. ',solo=' . ( $solo ? '1' : '0' )
			. ( $strong ? ',strong=1' : '' )
			. self::field_component( $fields );
	}

	/**
	 * The `,field=<name>[+<name>…]` tail of a gibberish reason — which field actually
	 * carried the gibberish.
	 *
	 * ADDED IN 6.0.0 because the reason was unanswerable without it: it named counts
	 * ("letters=5,alnum=304") but not the field, so an operator looking at a wrongly
	 * refused submission could not tell what to change (wp.org, 2026-08-24). APPENDED,
	 * never inserted: every existing component keeps its position and its spelling, so
	 * stored rows and the corpus labels stay readable and comparable.
	 *
	 * Field NAMES only. A name is already stored with every message detail row and
	 * describes the form, not the person who filled it in — unlike a value, which is
	 * exactly what the credential path exists to keep out of the database.
	 *
	 * Names are sanitised to the characters real form fields use and each one capped,
	 * because this string goes into a database column, a log line and a Fail2Ban
	 * pattern: anything else is percent-encoded rather than dropped, so a surprising
	 * name still points somewhere instead of vanishing. At most three names — beyond
	 * that the answer is "most of the selection", not a pointer.
	 *
	 * @param string[] $fields Contributing field names.
	 * @return string Empty string when nothing was attributed.
	 */
	private static function field_component( $fields ) {
		if ( ! $fields ) {
			return '';
		}
		$clean = array();
		foreach ( array_slice( $fields, 0, 3 ) as $name ) {
			if ( '' === $name ) {
				continue;
			}
			$safe    = (string) preg_replace_callback(
				'/[^A-Za-z0-9_\-\[\]]/',
				static function ( $found ) {
					return rawurlencode( $found[0] );
				},
				$name
			);
			$clean[] = substr( $safe, 0, 60 );
		}
		return $clean ? ',field=' . implode( '+', $clean ) : '';
	}

	/**
	 * Build the SCORING string for a message that was NOT classified as spam.
	 *
	 * Deliberately not a reason: the file header's invariant is that absence of a
	 * reason means clean, and a code for cleanliness would be indistinguishable from an
	 * unlabelled legacy row. This is a separate datum, stored in its own technical field
	 * `_gdpr_scoring` and only when a clean message is saved at all — i.e. only under
	 * the "Save clean messages" / analysis opt-ins, never in normal operation. It
	 * answers the one question the reason taxonomy structurally cannot: why a message
	 * was NOT flagged.
	 *
	 * It carries the same components as gibberish() plus `scoreable`, the number of
	 * scoreable tokens across the form. That is the value which decides whether the
	 * solo-token rule was suppressed, and therefore the single datum that explains a
	 * near-miss ("one gibberish token found, but other scoreable tokens suppressed the
	 * single-token rule") instead of leaving the admin to guess.
	 *
	 * Format (stable): `scoring:letters=<n>,alnum=<n>,solo=<0|1>,strong=<0|1>,scoreable=<n>`.
	 * All components are always present — unlike gibberish() there is no legacy corpus
	 * to stay byte-compatible with.
	 *
	 * @param int  $letters   Gibberish tokens found on the pure-letter path.
	 * @param int  $alnum     Gibberish tokens found on the alphanumeric path.
	 * @param bool $solo      Whether the solo-token rule fired.
	 * @param bool $strong    Whether the strong-token rule fired.
	 * @param int  $scoreable Scoreable tokens counted across the whole form.
	 * @return string Scoring string, e.g. "scoring:letters=1,alnum=0,solo=0,strong=0,scoreable=3".
	 */
	public static function scoring( $letters, $alnum, $solo, $strong, $scoreable ) {
		return self::CODE_SCORING . ':letters=' . max( 0, (int) $letters )
			. ',alnum=' . max( 0, (int) $alnum )
			. ',solo=' . ( $solo ? '1' : '0' )
			. ',strong=' . ( $strong ? '1' : '0' )
			. ',scoreable=' . max( 0, (int) $scoreable );
	}

	/**
	 * Build the PoW PROBE string: what the server actually saw in `…_stamp_rgs` at the
	 * moment it decided a submission had no usable proof of work.
	 *
	 * Deliberately NOT part of the reason string, for the same reason scoring() is not:
	 * reason strings are corpus labels living in stored rows and exported training data,
	 * and appending measurements to `no_pow:token_no_row` would both break their
	 * comparability across releases and knock every such row out of DETAIL_LABELS (the
	 * human explanation the message view shows). This is a separate datum in its own
	 * technical field `_gdpr_pow_probe`.
	 *
	 * WHY IT EXISTS. "No proof of work" has several possible shapes, and until now the
	 * server threw away the one piece of evidence that tells them apart — whether a row
	 * for that token existed at all, whether one existed but was too old or spent, or
	 * whether the address had nothing either. Two support rounds were spent guessing
	 * between exactly those (HANDBUCH.md §12 cause 7). One line per blocked submission
	 * ends the guessing.
	 *
	 * Format (stable): `token_rows=<n>,token_age_s=<n|->,token_uses=<n|->,ip_rows=<n>,ip_age_s=<n|->,ip_uses=<n|->`
	 * - `token_*` describe the row keyed by the submitted token (unique, so 0 or 1).
	 * - `ip_rows` counts EVERY row for the submitting address; `ip_age_s` and `ip_uses`
	 *   both describe the NEWEST of them — ONE row, so the pair always describes a state
	 *   that actually existed. (Aggregating each value over all rows separately would
	 *   print a row that never existed, e.g. a fresh exhausted row's age next to an old
	 *   unused row's count, reading as "the fallback should have worked".)
	 * - `-` means "no such row", never 0: "no row" and "a fresh row with 0 uses" are
	 *   opposite findings and must not print the same.
	 *
	 * Ages are measured WITHOUT the time filter the consume queries apply, on purpose:
	 * a row that exists but sits outside the window is precisely one of the answers this
	 * is meant to distinguish, and a filtered query could never show it.
	 *
	 * @param int      $token_rows  Rows found for the token (0/1; 0 when no token was posted).
	 * @param int|null $token_age_s Age of that row in seconds, null when there is none.
	 * @param int|null $token_uses  Its consumed-use count, null when there is none.
	 * @param int      $ip_rows     Rows found for the submitting address.
	 * @param int|null $ip_age_s    Age of the newest of them, null when there are none.
	 * @param int|null $ip_uses     Lowest use count among them, null when there are none.
	 * @return string e.g. "token_rows=0,token_age_s=-,token_uses=-,ip_rows=1,ip_age_s=7,ip_uses=0".
	 */
	public static function pow_probe( $token_rows, $token_age_s, $token_uses, $ip_rows, $ip_age_s, $ip_uses ) {
		$number = static function ( $value ) {
			return null === $value ? '-' : (string) max( 0, (int) $value );
		};

		// The two counts are always a number (0 = "no such row"); only the ages and use
		// counts can be absent, and those are exactly the values where 0 would be a
		// misleading answer rather than a missing one.
		return 'token_rows=' . max( 0, (int) $token_rows )
			. ',token_age_s=' . $number( $token_age_s )
			. ',token_uses=' . $number( $token_uses )
			. ',ip_rows=' . max( 0, (int) $ip_rows )
			. ',ip_age_s=' . $number( $ip_age_s )
			. ',ip_uses=' . $number( $ip_uses );
	}

	/**
	 * Whether a submission classified with this reason may seed the auto-echo lock with
	 * its CONTENT values (Stamp::check_submit() → Echo_Store::record()).
	 *
	 * WHY THIS EXISTS. The echo lock remembers the core values of a spam submission —
	 * sender email, payload domain, phone number, long-text hash — for 36 hours, across
	 * every form and every address. That is the right response to "this content is spam"
	 * and the wrong response to "the handshake failed": a `no_pow` verdict says nothing
	 * whatsoever about what was submitted. The three NON_SEEDING_REASONS presented a
	 * token that VERIFIED and merely lacked its solved-PoW row, which is the signature of
	 * a broken infrastructure (cache, proxy, storage failure, clock skew) rather than of
	 * a bot. Letting those seed turns a mass false alarm into a content blocklist that
	 * outlives its own fix by up to 36h: the two-clocks bug fixed in 5.3.4 classified
	 * legitimate submissions as `no_pow:token_no_row` en masse, and after the update the
	 * very same senders kept being blocked — now as "Known spam value".
	 *
	 * Same reasoning the under-attack quarantine already carries as its exception #2
	 * ("grey-zone submissions are presumed innocent and must not seed echo values that
	 * would spam-classify legitimate senders after the wave ends"), applied to the
	 * handshake failure.
	 *
	 * ERROR DIRECTION IS DELIBERATE: anything not explicitly listed — including an
	 * unknown, empty, null or otherwise malformed value — SEEDS. A reason code added
	 * later would otherwise silently drop out of the echo lock, and a lock that quietly
	 * stops learning is far harder to notice than one that learns too much (the latter
	 * has a reset button, see the Diagnostics tab). Pinned in
	 * tests/unit/ClassificationReasonTest.php.
	 *
	 * TWO PRICES KNOWINGLY PAID, recorded here so the next session need not rediscover
	 * them:
	 *  1. A protocol-aware bot can provoke `no_pow:token_no_row` for free — fetch a token
	 *     via `get_stamp` (stateless, costs the server nothing), never solve it, post it
	 *     anyway — and thereby escape the echo lock permanently. Accepted: whoever can do
	 *     that can also just PAY the proof of work (field data: d=20 in ~2 s), and a
	 *     paying submission is classified clean and seeds nothing today either. The echo
	 *     lock was never the barrier against that class; the proof of work is.
	 *  2. `no_pow:invalid_token` keeps seeding although it, too, has a false-alarm shape
	 *     (a cache layer in front of `get_stamp` hands out expired tokens to real
	 *     visitors en masse). The cut is drawn at "a valid token was demonstrably
	 *     presented", which is the more conservative of the two available lines: it keeps
	 *     protocol-blind mass spam — the echo lock's main food source — feeding the
	 *     store.
	 *
	 * @param mixed $reason Reason string, or null for a clean submission (any input
	 *                      accepted defensively — stored values pass through the
	 *                      database and may be anything).
	 * @return bool True when the submission's values may be recorded.
	 */
	public static function seeds_echo_values( $reason ) {
		return ! in_array( $reason, self::NON_SEEDING_REASONS, true );
	}

	/**
	 * The code part of a reason string: everything before the first colon (the whole
	 * string for codes that carry no detail).
	 *
	 * @param mixed $reason Reason string (any input accepted defensively — stored
	 *                      values pass through the database and may be anything).
	 * @return string Code part, or '' for non-string/empty input.
	 */
	public static function code( $reason ) {
		if ( ! is_string( $reason ) || '' === $reason ) {
			return '';
		}
		$colon = strpos( $reason, ':' );
		// Cast: substr() is typed string|false below PHP 8 (it cannot fail here —
		// offset 0 — but the analyser must not have to know that).
		return false === $colon ? $reason : (string) substr( $reason, 0, $colon );
	}

	/**
	 * The detail part of a reason string: everything after the first colon, or '' when
	 * the reason carries no detail. Mirrors code() and is just as defensive.
	 *
	 * @param mixed $reason Reason string.
	 * @return string Detail part, or '' when there is none.
	 */
	public static function detail( $reason ) {
		if ( ! is_string( $reason ) || '' === $reason ) {
			return '';
		}
		$colon = strpos( $reason, ':' );
		return false === $colon ? '' : (string) substr( $reason, $colon + 1 );
	}

	/**
	 * The human-readable cause behind a reason string, or '' when there is nothing to
	 * add beyond the code label.
	 *
	 * FALLS BACK TO THE RAW DETAIL rather than to silence: a reason whose detail this
	 * version does not know yet (a newer code, a `gibberish:letters=…` scoring string)
	 * still tells the reader more than nothing, and hiding it would recreate exactly the
	 * gap this function exists to close. Never throws, for any input.
	 *
	 * @param mixed $reason Reason string.
	 * @return string Explanation, or '' when the reason carries no detail.
	 */
	public static function detail_label( $reason ) {
		if ( ! is_string( $reason ) || '' === $reason ) {
			return '';
		}
		if ( isset( self::DETAIL_LABELS[ $reason ] ) ) {
			return self::DETAIL_LABELS[ $reason ];
		}
		return self::detail( $reason );
	}

	/**
	 * Short English UI label for a reason string. Never throws and never returns an
	 * empty string: unknown codes, malformed strings and non-string input all yield
	 * UNKNOWN_LABEL. A stored reason may predate (or postdate) the code that reads
	 * it, so an unrecognised value must degrade to something printable rather than
	 * break the message view.
	 *
	 * @param mixed $reason Reason string.
	 * @return string Label.
	 */
	public static function label( $reason ) {
		$code = self::code( $reason );
		return isset( self::CODE_LABELS[ $code ] ) ? self::CODE_LABELS[ $code ] : self::UNKNOWN_LABEL;
	}
}
