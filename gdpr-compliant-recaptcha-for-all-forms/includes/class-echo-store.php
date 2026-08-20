<?php
/**
 * Thin WordPress integration layer for the auto-echo lock (BACKLOG "Wertbasierte
 * Spam-Pattern … Auto-Echo-Sperre mit TTL").
 *
 * All the non-trivial logic (which values to extract, own-domain exclusion,
 * hashing) lives in the pure Echo_Values class; this class only holds the WP glue:
 * the site's own domain (home_url()/site_url()), and the transient-backed TTL
 * store. It is therefore intentionally NOT unit-tested (no pure logic) — like the
 * WP-side of Stamp relative to ProofOfWork.
 *
 * Storage layout (chosen deliberately, see BACKLOG "Implementierungshinweis
 * Transients"): ONE transient holding a map `sha256-hash => expiry-unix-timestamp`,
 * NOT one transient per value. Rationale:
 * - The check runs on EVERY monitored POST and must be cheap: a single
 *   get_transient() plus in-memory hash lookups, never a DB query per field.
 * - Expired entries are pruned opportunistically on every load; the record path
 *   persists the pruned map, the (read-only) check path does not write.
 * - Size is capped at MAX_ENTRIES (newest-expiry-wins eviction) so a flood cannot
 *   grow the option row unbounded. Under a heavy flood the map churns (LRU-ish) —
 *   acceptable, because the PoW economy already handles the mass; the echo lock is
 *   a deterministic bonus layer for repeat senders, not the primary defense.
 * - get+modify+set is not atomic (same approximation as increment_spam_counter());
 *   a lost concurrent write only drops an echo value, which the next spam landing
 *   re-records — acceptable for a best-effort heuristic.
 *
 * GDPR: only SHA-256 hashes are stored (never the plaintext email/phone/text), and
 * the TTL is short — sender emails are forgeable, so a value must not stay blocked
 * for long.
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
 * Transient-backed, TTL'd hashed-value store for the auto-echo lock.
 */
final class Echo_Store {

	/** Single transient key holding the hash => expiry map. */
	const TRANSIENT_KEY = 'gdpr_pow_echo_values';

	/**
	 * Transient caching the SHA-256 hashes of every registered site user's email.
	 * These addresses are excluded from the echo lock (never recorded, never matched)
	 * so an attacker cannot echo-lock a real account by submitting spam that carries
	 * its address — the lock is consulted on login/password-reset too, so a match
	 * there would deny that user access. Cached (not queried per POST) and invalidated
	 * on user create/update/delete via register_cache_hooks(). GDPR: only hashes, like
	 * the echo map itself.
	 */
	const USER_EMAILS_TRANSIENT = 'gdpr_pow_user_email_hashes';

	/**
	 * Safety-net TTL for the user-email-hash cache. Invalidation is normally hook-
	 * driven (user_register/profile_update/deleted_user); the TTL only bounds staleness
	 * if a user row is changed outside those hooks (direct DB write, an un-hooked import).
	 */
	const USER_EMAILS_TTL = 12 * HOUR_IN_SECONDS;

	/**
	 * Time-to-live of a recorded echo value. 36h sits in the specified 24–48h band
	 * — long enough to catch a returning spam run, short enough that a forged
	 * sender address does not stay blocked. A class constant, not an option: the
	 * feature ships with no settings surface of its own (see BACKLOG entry).
	 */
	const TTL_SECONDS = 36 * HOUR_IN_SECONDS;

	/** Hard cap on stored entries; newest-expiry-wins eviction beyond it. */
	const MAX_ENTRIES = 1000;

	/**
	 * Whether the auto-echo lock is currently enabled (POW_ECHO_LOCK_ENABLED, default
	 * on). Gates BOTH the record path (nothing new is remembered) and the match path
	 * (nothing is matched) — the toggle is a single on/off for the whole bonus layer,
	 * leaving the proof-of-work economy untouched. Explicit `true` fallback so an
	 * existing install that predates the option (no DB row) stays protected; a saved
	 * '0' (checkbox off) reads falsy and disables it.
	 *
	 * @return bool
	 */
	public static function is_enabled() {
		return (bool) get_option( Option::POW_ECHO_LOCK_ENABLED, true );
	}

	/**
	 * The site's own registrable domain(s), used as the exclude list so an echo
	 * value is never seeded for the site's own domain (self-DoS guard, invariant 2).
	 *
	 * @return string[]
	 */
	public static function site_domains() {
		$domains = array();
		foreach ( array( home_url(), site_url() ) as $url ) {
			$domain = Echo_Values::registrable_domain( (string) $url, array() );
			if ( null !== $domain ) {
				$domains[ $domain ] = true;
			}
		}
		return array_keys( $domains );
	}

	/**
	 * SHA-256 hashes of all registered site users' email addresses, cached in a
	 * transient (rebuilt lazily on miss, invalidated by register_cache_hooks()). The
	 * query pulls only the user_email column, and the result never leaves as plaintext
	 * (Echo_Values::hash_emails() hashes each address). Passed to build_echo_set() as
	 * the exclude set in both record() and matches().
	 *
	 * @return string[] SHA-256 hashes of registered-user emails.
	 */
	public static function user_email_hashes() {
		$cached = get_transient( self::USER_EMAILS_TRANSIENT );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$emails = array();
		foreach ( get_users( array( 'fields' => array( 'user_email' ) ) ) as $user ) {
			if ( isset( $user->user_email ) ) {
				$emails[] = (string) $user->user_email;
			}
		}
		$hashes = Echo_Values::hash_emails( $emails );
		set_transient( self::USER_EMAILS_TRANSIENT, $hashes, self::USER_EMAILS_TTL );
		return $hashes;
	}

	/**
	 * Drop the cached user-email-hash set so the next lookup rebuilds it. Hooked to
	 * user_register/profile_update/deleted_user by register_cache_hooks().
	 *
	 * @return void
	 */
	public static function invalidate_user_email_cache() {
		delete_transient( self::USER_EMAILS_TRANSIENT );
	}

	/**
	 * Register the user-email-hash cache invalidation hooks. Called once from the
	 * plugin bootstrap. profile_update covers an email change on an existing account,
	 * user_register a new account, deleted_user a removed one.
	 *
	 * @return void
	 */
	public static function register_cache_hooks() {
		add_action( 'user_register', array( __CLASS__, 'invalidate_user_email_cache' ) );
		add_action( 'profile_update', array( __CLASS__, 'invalidate_user_email_cache' ) );
		add_action( 'deleted_user', array( __CLASS__, 'invalidate_user_email_cache' ) );
	}

	/**
	 * Record the core values of a (spam-classified) submission for TTL_SECONDS.
	 *
	 * @param mixed    $fields        The submission's field map.
	 * @param string[] $no_text_roots Top-level names whose subtree contributes no
	 *                                long-text hash — the unpacked envelopes of a form
	 *                                builder, see Echo_Values::build_echo_set().
	 * @return void
	 */
	public static function record( $fields, $no_text_roots = array() ) {
		if ( ! self::is_enabled() ) {
			return;
		}
		$hashes = Echo_Values::build_echo_set( $fields, self::site_domains(), self::user_email_hashes(), $no_text_roots );
		if ( empty( $hashes ) ) {
			return;
		}
		$now    = time();
		$map    = self::load_map( $now );
		$expiry = $now + self::TTL_SECONDS;
		foreach ( $hashes as $hash ) {
			$map[ $hash ] = $expiry;
		}
		if ( count( $map ) > self::MAX_ENTRIES ) {
			arsort( $map ); // Highest (latest) expiry first.
			$map = array_slice( $map, 0, self::MAX_ENTRIES, true );
		}
		set_transient( self::TRANSIENT_KEY, $map, self::TTL_SECONDS );
	}

	/**
	 * Whether the submission matches any currently-active echo value. Cheap: one
	 * get_transient() (short-circuited when the store is empty) plus hash lookups.
	 *
	 * @param mixed    $fields        The submission's field map.
	 * @param string[] $no_text_roots Top-level names whose subtree contributes no
	 *                                long-text hash — the SAME list record() was given,
	 *                                because a value that cannot be seeded must not be
	 *                                matchable either.
	 * @return bool
	 */
	public static function matches( $fields, $no_text_roots = array() ) {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$map = self::load_map( time() );
		if ( empty( $map ) ) {
			return false;
		}
		foreach ( Echo_Values::build_echo_set( $fields, self::site_domains(), self::user_email_hashes(), $no_text_roots ) as $hash ) {
			if ( isset( $map[ $hash ] ) ) { // load_map() already dropped expired entries.
				return true;
			}
		}
		return false;
	}

	/**
	 * Number of currently-active (non-expired) echo values held in the store. Used by
	 * the settings status strip to show the count and decide whether to offer a reset.
	 * Cheap and read-only: one get_transient() plus the opportunistic expiry prune of
	 * load_map() (the pruned map is intentionally not persisted here — the next record()
	 * writes it back).
	 *
	 * @return int
	 */
	public static function count() {
		return count( self::load_map( time() ) );
	}

	/**
	 * Drop the entire echo store, releasing every currently-held value at once. Admin-
	 * triggered from the settings status strip (nonce + manage_options gated there) so a
	 * legitimately caught address can be freed immediately. No data loss: the store is a
	 * transient TTL cache, not a record of anything — it rebuilds by itself as real spam
	 * lands again.
	 *
	 * @return void
	 */
	public static function clear() {
		delete_transient( self::TRANSIENT_KEY );
	}

	/**
	 * Load the map, dropping expired/malformed entries. Read-only — callers that
	 * want the pruned map persisted must set it back themselves (record() does).
	 *
	 * @param int $now Current unix timestamp.
	 * @return array<string,int> hash => expiry.
	 */
	private static function load_map( $now ) {
		$map = get_transient( self::TRANSIENT_KEY );
		if ( ! is_array( $map ) ) {
			return array();
		}
		foreach ( $map as $hash => $expiry ) {
			if ( ! is_int( $expiry ) || $expiry <= $now ) {
				unset( $map[ $hash ] );
			}
		}
		return $map;
	}
}
