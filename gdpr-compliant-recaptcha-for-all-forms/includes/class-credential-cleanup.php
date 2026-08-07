<?php
/**
 * One-off cleanup of credential values that older releases stored in cleartext.
 *
 * Until the redaction pre-pass in Stamp::save_message() landed, a password could
 * reach `wp_recaptcha_gdpr_details_rgd` whenever the client-side `hashPWFields`
 * marker was missing (no-JS logins, hand-built ajax bodies, minimal POSTs) — and
 * every admin can read that table. New rows are written redacted from now on;
 * this class removes what is already there.
 *
 * Why an option-backed ledger instead of the usual "run it inside the version
 * gate in RCM_Main::activate()": that gate only fires when RCM_Main::VERSION is
 * higher than the stored POW_VERSION, i.e. exactly once per release, in ONE
 * request. A migration that has to walk a table of unknown size cannot finish
 * there — it would either time out or, on installs where the gate has already
 * fired, never run at all. So maybe_run() is called on EVERY load, keeps its own
 * cursor, and does a bounded slice of work per request until it is done.
 *
 * The three properties that make that safe:
 *
 *  - TERMINATION: the cursor advances to the end of the scanned rgd_id window
 *    even when the window contained no hits, and the upper bound (max_id) is
 *    frozen when the ledger is created. Every request therefore strictly reduces
 *    the remaining range. Not visiting rows created after that point is correct
 *    for pass 1 — Stamp::save_message() writes those redacted already. For pass 2
 *    it rests on a different guarantee: `_gdpr_analysis_payload` rows are written
 *    only by Analysis::store_analysis_entry(), which is manage_options + nonce
 *    gated and receives what the admin's own (password-stripping) JS captured.
 *  - BOUNDED COST: each window is an ID range on the primary key (never a
 *    LIMIT over a full scan), and a run stops after TIME_BUDGET_S. Once both
 *    passes are done, maybe_run() costs exactly one get_option() on an
 *    autoloaded option — no query at all.
 *  - IDEMPOTENCE: every write moves a row into a state the SELECTs exclude
 *    (`rgd_value <> '[redacted]'` / `rgm_posted = 1`), and the title fix is a
 *    str_replace() that is a no-op on a second visit. A crashed run resumes at
 *    the last persisted cursor and at worst redoes one window.
 *
 * The exact decision stays in the pure Credential_Fields heuristic; SQL only
 * narrows the candidate set (a deliberately loose LIKE superset), because the
 * stored attribute is a `a->b->c` path that has to be matched per segment.
 *
 * RE-ARMABLE, not one-off. Since the admin can LEARN further credential field
 * names (Learned_Credential_Fields), a cleanup that only ever ran once would
 * repeat the very gap it was written for: every newly learned name would protect
 * future submissions while the existing rows keep their cleartext. The ledger
 * therefore also carries a hash of the name set it has already swept. Whenever
 * the stored list hashes differently — a confirmation from the notice, the
 * message inbox, or a manual edit on the settings page — a third pass is armed
 * for the NEW names only, with its own freshly frozen max_id and its own cursor.
 * All three properties above survive that: the pass ends against a bound frozen
 * when it was armed, it is budgeted by the same clock, and its write is the same
 * idempotent one. Arming happens at most once per changed list (the hash settles
 * even when the change was a REMOVAL, which arms nothing at all).
 *
 * This is WordPress glue (options, transients, $wpdb) and therefore not
 * unit-testable; the structural guarantees above are pinned by
 * tests/unit/CredentialCleanupSourceTest.php.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Resumable, budgeted redaction of pre-existing credential rows.
 */
final class Credential_Cleanup {

	/** Ledger layout version — a mismatch restarts the migration from scratch. */
	private const LEDGER_VERSION = 1;

	/** rgd_id range scanned per query. Bounded work, index-friendly (primary key). */
	private const ID_WINDOW = 5000;

	/**
	 * Wall-clock budget per request. Deliberately below a second: this runs on
	 * ordinary front-end loads, so it must be invisible; the ledger makes the
	 * remaining work someone else's problem (the next request's).
	 */
	private const TIME_BUDGET_S = 1.0;

	/**
	 * Best-effort concurrency guard. Two parallel runs would not corrupt anything
	 * (all writes are idempotent), they would only duplicate work — hence a plain
	 * transient rather than a DB lock. The TTL is the crash safety net: if a run
	 * dies mid-window the lock frees itself.
	 */
	private const LOCK_TRANSIENT = 'gdpr_pow_credential_cleanup_lock';

	/** Lock TTL in seconds. */
	private const LOCK_TTL = 60;

	/** Attribute name of the raw diagnostic capture written for analysis messages. */
	private const PAYLOAD_ATTRIBUTE = '_gdpr_analysis_payload';

	/**
	 * Learned names swept per armed run. Bounds the OR-chain of one query; a
	 * larger list is handled in consecutive chunks, since the hash keeps
	 * differing until every name has been seen.
	 */
	private const MAX_ARMED_NAMES = 25;

	/**
	 * Do the next slice of the cleanup, if there is one.
	 *
	 * Called unconditionally from RCM_Main::activate() (i.e. on every load) and
	 * designed to be free once finished: the completed ledger is an autoloaded
	 * option, and the learned list it is compared against is one too, so the early
	 * return below costs no query.
	 */
	public static function maybe_run(): void {
		$ledger = get_option( Option::POW_CREDENTIAL_CLEANUP );

		$learned      = Learned_Credential_Fields::parse_list( get_option( Option::POW_CREDENTIAL_FIELDS, '' ) );
		$learned_hash = Learned_Credential_Fields::list_hash( $learned );

		if ( self::is_finished( $ledger, $learned_hash ) ) {
			return;
		}

		if ( get_transient( self::LOCK_TRANSIENT ) ) {
			return;
		}
		set_transient( self::LOCK_TRANSIENT, 1, self::LOCK_TTL );

		$ledger = self::normalize_ledger( $ledger );
		self::maybe_arm_learned( $ledger, $learned );
		$started = microtime( true );

		do {
			if ( ! $ledger['posted_done'] ) {
				self::run_posted_pass( $ledger );
			} elseif ( ! $ledger['payload_done'] ) {
				self::run_payload_pass( $ledger );
			} elseif ( ! $ledger['learned_done'] ) {
				self::run_learned_pass( $ledger );
			} else {
				break;
			}
		} while ( microtime( true ) - $started < self::TIME_BUDGET_S );

		self::save_ledger( $ledger );
		delete_transient( self::LOCK_TRANSIENT );
	}

	/**
	 * Mark the cleanup as done without touching the database.
	 *
	 * Called for a fresh install: the tables were just created, so there is no
	 * legacy cleartext to remove and no reason to ever query for it.
	 */
	public static function mark_done_fresh_install(): void {
		self::save_ledger(
			array(
				'v'              => self::LEDGER_VERSION,
				'posted_done'    => true,
				'posted_cursor'  => 0,
				'payload_done'   => true,
				'payload_cursor' => 0,
				'max_id'         => 0,
				// The learned list starts out empty (hash ''), so nothing is armed.
				// A name learned later still re-arms normally — on a fresh install
				// that run finds nothing, which costs one bounded window.
				'learned_done'   => true,
				'learned_cursor' => 0,
				'learned_max_id' => 0,
				'learned_names'  => array(),
				'learned_seen'   => array(),
				'learned_hash'   => '',
			)
		);
	}

	/**
	 * Pass 1: detail rows whose attribute path names a credential.
	 *
	 * The SQL prefilter (`%pass%` OR `%pwd%`) is a strict superset of the
	 * heuristic — every term it recognises contains one of the two — so the exact
	 * decision can stay in Credential_Fields::is_password_path() while the query
	 * still stays selective. `rgm_posted = 1` limits the pass to rows that carry a
	 * posted value at all, which is also what makes the write idempotent.
	 *
	 * @param array $ledger Cleanup ledger, advanced in place.
	 */
	private static function run_posted_pass( array &$ledger ): void {
		global $wpdb;

		$details    = $wpdb->prefix . 'recaptcha_gdpr_details_rgd';
		$from       = (int) $ledger['posted_cursor'];
		$window_end = min( $from + self::ID_WINDOW, (int) $ledger['max_id'] );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders. Every value in this statement is a prepare() placeholder.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT rgd_id, rgm_id, rgd_attribute, rgd_value FROM ' . $details
				. ' WHERE rgd_id > %d AND rgd_id <= %d AND rgm_posted = 1'
				. ' AND ( rgd_attribute LIKE %s OR rgd_attribute LIKE %s )'
				. ' AND rgd_value <> %s',
				$from,
				$window_end,
				'%pass%',
				'%pwd%',
				Credential_Fields::REDACTED_VALUE
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		foreach ( (array) $rows as $row ) {
			if ( ! is_array( $row ) || ! Credential_Fields::is_password_path( (string) $row['rgd_attribute'] ) ) {
				continue;
			}
			self::redact_detail_row( $row );
		}

		// Unconditional: an empty window still consumed its range. Skipping this on
		// "no hits" would make the migration loop forever on large installs.
		$ledger['posted_cursor'] = $window_end;
		if ( $window_end >= (int) $ledger['max_id'] ) {
			$ledger['posted_done'] = true;
		}
	}

	/**
	 * Pass 2: raw `_gdpr_analysis_payload` captures.
	 *
	 * These predate the client-side password stripping (and survive any marker
	 * failure), so they can carry a credential under a cleartext key inside the
	 * JSON blob. The prefilter runs on the value here, not on the attribute, and
	 * the per-row decision is Credential_Fields::redact_payload_json() — including
	 * its fail-closed handling of unparseable JSON. rgm_posted is left as found:
	 * these rows are not value candidates in the UI to begin with.
	 *
	 * @param array $ledger Cleanup ledger, advanced in place.
	 */
	private static function run_payload_pass( array &$ledger ): void {
		global $wpdb;

		$details    = $wpdb->prefix . 'recaptcha_gdpr_details_rgd';
		$from       = (int) $ledger['payload_cursor'];
		$window_end = min( $from + self::ID_WINDOW, (int) $ledger['max_id'] );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders. Every value in this statement is a prepare() placeholder.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT rgd_id, rgd_value FROM ' . $details
				. ' WHERE rgd_id > %d AND rgd_id <= %d AND rgd_attribute = %s'
				. ' AND ( rgd_value LIKE %s OR rgd_value LIKE %s )',
				$from,
				$window_end,
				self::PAYLOAD_ATTRIBUTE,
				'%pass%',
				'%pwd%'
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		foreach ( (array) $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$new_value = Credential_Fields::redact_payload_json( (string) $row['rgd_value'] );
			if ( null === $new_value ) {
				continue;
			}

			$wpdb->query(
				$wpdb->prepare(
					'UPDATE ' . $details . ' SET rgd_value = %s WHERE rgd_id = %d', // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders. Both values are prepare() placeholders.
					$new_value,
					(int) $row['rgd_id']
				)
			);
		}

		// Unconditional, same reason as in run_posted_pass().
		$ledger['payload_cursor'] = $window_end;
		if ( $window_end >= (int) $ledger['max_id'] ) {
			$ledger['payload_done'] = true;
		}
	}

	/**
	 * Pass 3: rows whose attribute path carries a NEWLY LEARNED field name.
	 *
	 * Structurally pass 1 with two differences: the LIKE prefilter is built from
	 * the armed names instead of the fixed `%pass%`/`%pwd%` superset (a learned
	 * name shares no substring with them by definition — that is why it had to be
	 * learned), and the window is bounded by the max_id frozen when this run was
	 * armed, not by the migration's original one. The per-row decision stays in
	 * the pure Learned_Credential_Fields::is_learned_path(): the LIKE is a
	 * superset, exact segment matching is what decides.
	 *
	 * @param array $ledger Cleanup ledger, advanced in place.
	 */
	private static function run_learned_pass( array &$ledger ): void {
		global $wpdb;

		$names = array();
		foreach ( (array) $ledger['learned_names'] as $candidate ) {
			$name = Learned_Credential_Fields::normalize_name( $candidate );
			if ( null !== $name && ! in_array( $name, $names, true ) ) {
				$names[] = $name;
			}
		}
		if ( 0 === count( $names ) ) {
			// Nothing armed (or only unusable names): done without a single query.
			$ledger['learned_done'] = true;
			return;
		}

		$details    = $wpdb->prefix . 'recaptcha_gdpr_details_rgd';
		$from       = (int) $ledger['learned_cursor'];
		$window_end = min( $from + self::ID_WINDOW, (int) $ledger['learned_max_id'] );

		$likes = array();
		$args  = array( $from, $window_end, Credential_Fields::REDACTED_VALUE );
		foreach ( $names as $name ) {
			$likes[] = 'rgd_attribute LIKE %s';
			$args[]  = '%' . $wpdb->esc_like( $name ) . '%';
		}

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders. The OR-chain is built from a fixed literal per armed name, so the placeholder count varies with the armed set and cannot be counted statically; every value travels as a prepare() placeholder in the $args array, which is built alongside $likes right above and therefore always matches it 1:1.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT rgd_id, rgm_id, rgd_attribute, rgd_value FROM ' . $details
				. ' WHERE rgd_id > %d AND rgd_id <= %d AND rgm_posted = 1'
				. ' AND rgd_value <> %s'
				. ' AND ( ' . implode( ' OR ', $likes ) . ' )',
				$args
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber

		foreach ( (array) $rows as $row ) {
			if ( ! is_array( $row ) || ! Learned_Credential_Fields::is_learned_path( (string) $row['rgd_attribute'], $names ) ) {
				continue;
			}
			self::redact_detail_row( $row );
		}

		// Unconditional, same reason as in run_posted_pass().
		$ledger['learned_cursor'] = $window_end;
		if ( $window_end >= (int) $ledger['learned_max_id'] ) {
			$ledger['learned_done'] = true;
		}
	}

	/**
	 * Redact ONE message right now — the visible feedback of the message-inbox
	 * rescue button (Credential_Learning::ajax_treat_as_credential()).
	 *
	 * Bounded by construction (the rows of a single message) and idempotent by the
	 * same rules as the passes: already redacted rows are excluded by the SELECT.
	 * It is a courtesy, not the mechanism — every OTHER existing message is
	 * handled by the re-armed pass 3.
	 *
	 * @param int      $message_id rgm_id of the message.
	 * @param string[] $names      Learned names to apply.
	 * @return int Number of redacted rows.
	 */
	public static function redact_message_now( int $message_id, array $names ): int {
		if ( $message_id <= 0 || 0 === count( $names ) ) {
			return 0;
		}

		global $wpdb;
		$details = $wpdb->prefix . 'recaptcha_gdpr_details_rgd';

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT rgd_id, rgm_id, rgd_attribute, rgd_value FROM ' . $details // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders. Both values are prepare() placeholders.
				. ' WHERE rgm_id = %d AND rgm_posted = 1 AND rgd_value <> %s',
				$message_id,
				Credential_Fields::REDACTED_VALUE
			),
			ARRAY_A
		);

		$redacted = 0;
		foreach ( (array) $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! Learned_Credential_Fields::is_learned_path( (string) $row['rgd_attribute'], $names ) ) {
				continue;
			}
			self::redact_detail_row( $row );
			++$redacted;
		}

		return $redacted;
	}

	/**
	 * Redact one detail row: title first, then the value.
	 *
	 * Title first because it may embed the value verbatim (a credential field
	 * configured as a message head). Doing it before the row is rewritten keeps
	 * the needle available; doing it after would need the old value.
	 *
	 * @param array $row Row with rgd_id, rgm_id and rgd_value.
	 */
	private static function redact_detail_row( array $row ): void {
		global $wpdb;

		self::redact_title( (int) $row['rgm_id'], (string) $row['rgd_value'] );

		$wpdb->query(
			$wpdb->prepare(
				'UPDATE ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd SET rgd_value = %s, rgm_posted = 0 WHERE rgd_id = %d', // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders. Both values are prepare() placeholders.
				Credential_Fields::REDACTED_VALUE,
				(int) $row['rgd_id']
			)
		);
	}

	/**
	 * Replace a credential value inside a message title.
	 *
	 * Only touches the row when the value actually occurs in the title, so a
	 * second visit is a no-op (the needle is gone by then). Empty values are
	 * skipped — str_replace() on '' would be meaningless.
	 *
	 * @param int    $message_id rgm_id of the owning message.
	 * @param string $value      Cleartext value about to be redacted.
	 */
	private static function redact_title( int $message_id, string $value ): void {
		if ( '' === $value || $message_id <= 0 ) {
			return;
		}

		global $wpdb;
		$messages = $wpdb->prefix . 'recaptcha_gdpr_message_rgm';

		$title = $wpdb->get_var(
			$wpdb->prepare( 'SELECT rgm_title FROM ' . $messages . ' WHERE rgm_id = %d', $message_id ) // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders. The one value is a prepare() placeholder.
		);

		if ( ! is_string( $title ) || false === strpos( $title, $value ) ) {
			return;
		}

		$wpdb->query(
			$wpdb->prepare(
				'UPDATE ' . $messages . ' SET rgm_title = %s WHERE rgm_id = %d', // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders. Both values are prepare() placeholders.
				str_replace( $value, Credential_Fields::REDACTED_VALUE, $title ),
				$message_id
			)
		);
	}

	/**
	 * Arm a retroactive run for the names learned since the last one.
	 *
	 * No-op while a run is still in flight (it keeps the name set it started
	 * with), and no-op while the stored list hashes the way the swept set does.
	 * A change that only REMOVED names settles the hash without arming anything —
	 * there is nothing to redact for a name that is no longer a credential.
	 *
	 * @param array    $ledger  Cleanup ledger, updated in place.
	 * @param string[] $learned Current learned list.
	 */
	private static function maybe_arm_learned( array &$ledger, array $learned ): void {
		if ( ! $ledger['learned_done'] ) {
			return;
		}
		if ( Learned_Credential_Fields::list_hash( $learned ) === (string) $ledger['learned_hash'] ) {
			return;
		}

		list( $names, $seen ) = Learned_Credential_Fields::arm( $learned, $ledger['learned_seen'], self::MAX_ARMED_NAMES );

		$ledger['learned_seen'] = $seen;
		$ledger['learned_hash'] = Learned_Credential_Fields::list_hash( $seen );

		if ( 0 === count( $names ) ) {
			return;
		}

		$ledger['learned_names']  = $names;
		$ledger['learned_cursor'] = 0;
		$ledger['learned_max_id'] = self::max_detail_id();
		$ledger['learned_done']   = false;
	}

	/**
	 * Is the stored ledger a completed one of the current layout, for the current
	 * learned list?
	 *
	 * Kept deliberately total (any shape of stored value is accepted as input) so
	 * the hot path — "already done, do nothing" — never depends on the option
	 * holding what we expect. A ledger written before the learned list existed
	 * carries no learned keys at all; it counts as done, and its absent hash
	 * equals the '' an empty list hashes to.
	 *
	 * @param mixed  $ledger       Raw option value.
	 * @param string $learned_hash Hash of the current learned list.
	 * @return bool
	 */
	private static function is_finished( $ledger, string $learned_hash ): bool {
		if ( ! is_array( $ledger ) ) {
			return false;
		}
		$learned_done = ! array_key_exists( 'learned_done', $ledger ) || ! empty( $ledger['learned_done'] );
		$stored_hash  = isset( $ledger['learned_hash'] ) && is_scalar( $ledger['learned_hash'] )
			? (string) $ledger['learned_hash']
			: '';

		return isset( $ledger['v'] ) && self::LEDGER_VERSION === (int) $ledger['v']
			&& ! empty( $ledger['posted_done'] )
			&& ! empty( $ledger['payload_done'] )
			&& $learned_done
			&& $stored_hash === $learned_hash;
	}

	/**
	 * Turn whatever is stored into a usable ledger, creating one on first run.
	 *
	 * The upper bound is frozen here: MAX(rgd_id) at start. Rows added later are
	 * written redacted by Stamp::save_message() already, so not visiting them is
	 * correct — and it is what guarantees the migration ends on a busy site.
	 *
	 * @param mixed $stored Raw option value.
	 * @return array{v:int,posted_done:bool,posted_cursor:int,payload_done:bool,payload_cursor:int,max_id:int,learned_done:bool,learned_cursor:int,learned_max_id:int,learned_names:string[],learned_seen:string[],learned_hash:string}
	 */
	private static function normalize_ledger( $stored ): array {
		if ( is_array( $stored ) && isset( $stored['v'] ) && self::LEDGER_VERSION === (int) $stored['v'] ) {
			return array(
				'v'              => self::LEDGER_VERSION,
				'posted_done'    => ! empty( $stored['posted_done'] ),
				'posted_cursor'  => isset( $stored['posted_cursor'] ) ? (int) $stored['posted_cursor'] : 0,
				'payload_done'   => ! empty( $stored['payload_done'] ),
				'payload_cursor' => isset( $stored['payload_cursor'] ) ? (int) $stored['payload_cursor'] : 0,
				'max_id'         => isset( $stored['max_id'] ) ? (int) $stored['max_id'] : 0,
				// Absent keys = a ledger from before the learned list existed. It
				// counts as done, so nothing is re-scanned until a name is learned.
				'learned_done'   => ! array_key_exists( 'learned_done', $stored ) || ! empty( $stored['learned_done'] ),
				'learned_cursor' => isset( $stored['learned_cursor'] ) ? (int) $stored['learned_cursor'] : 0,
				'learned_max_id' => isset( $stored['learned_max_id'] ) ? (int) $stored['learned_max_id'] : 0,
				'learned_names'  => isset( $stored['learned_names'] ) && is_array( $stored['learned_names'] )
					? Learned_Credential_Fields::parse_list( Learned_Credential_Fields::to_lines( $stored['learned_names'] ) )
					: array(),
				'learned_seen'   => isset( $stored['learned_seen'] ) && is_array( $stored['learned_seen'] )
					? Learned_Credential_Fields::parse_list( Learned_Credential_Fields::to_lines( $stored['learned_seen'] ) )
					: array(),
				'learned_hash'   => isset( $stored['learned_hash'] ) && is_scalar( $stored['learned_hash'] )
					? (string) $stored['learned_hash']
					: '',
			);
		}

		return array(
			'v'              => self::LEDGER_VERSION,
			// An empty (or missing) table has nothing to scan: max_id 0 makes the
			// first window end at 0 and both passes report done immediately.
			'posted_done'    => false,
			'posted_cursor'  => 0,
			'payload_done'   => false,
			'payload_cursor' => 0,
			'max_id'         => self::max_detail_id(),
			// Fresh ledger: nothing swept yet, hash '' — an already non-empty
			// learned list therefore arms pass 3 on this very run.
			'learned_done'   => true,
			'learned_cursor' => 0,
			'learned_max_id' => 0,
			'learned_names'  => array(),
			'learned_seen'   => array(),
			'learned_hash'   => '',
		);
	}

	/**
	 * Current upper bound of the detail table — the value a run freezes when it
	 * starts. The one place MAX() is read, so "every pass ends against a frozen
	 * bound" stays a property of the code, not of a habit.
	 *
	 * @return int
	 */
	private static function max_detail_id(): int {
		global $wpdb;
		return (int) $wpdb->get_var( 'SELECT MAX(rgd_id) FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input; identifiers cannot be placeholders. The statement carries no values at all, so there is nothing to prepare.
	}

	/**
	 * Persist the ledger, autoloaded so the finished-check stays query-free.
	 *
	 * @param array $ledger Ledger to store.
	 */
	private static function save_ledger( array $ledger ): void {
		update_option( Option::POW_CREDENTIAL_CLEANUP, $ledger, true );
	}
}
