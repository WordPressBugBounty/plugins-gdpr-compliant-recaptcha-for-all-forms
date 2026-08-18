<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Class Option: Each instance of that class is intended to hold an option for the plugin
 *
 */
class Option {

	/**
	 * The message/health COUNTERS that grew up on this class: the folder queries and the
	 * path helpers they need, the storage-independent no-stamp bucket counter, and the two
	 * pure status decisions built on those figures.
	 *
	 * SCHNITTLINIE (Welle 4, PLAN-DATEIGROESSE.md): class-option.php was 920 lines, and
	 * the assumption in that plan — "essentially an option registry that legitimately
	 * grows one line per option" — held for only half of it. Roughly 400 lines were not
	 * registry at all but counting logic that had accumulated next to the keys. It now
	 * lives in trait-option-counters.php; what stayed is the option MODEL (every key as a
	 * const, the instance and its accessors) plus fp_mismatch_share(), which sits with the
	 * two POW_FP_* constants it reads.
	 *
	 * A trait, not a second class: every caller writes Option::… (Message_Page,
	 * Settings_Menu, Dashboard_Widget, Abilities, Stamp) and several source-level pins
	 * name those constants in THIS file. A trait is compiled in, so nothing about the
	 * public surface, the visibilities or those pins changes.
	 */
	use Option_Counters;

	/** @var string */
	const PREFIX = 'gdpr_pow_';

	/** @var int */
	const INT = 1;

	/** @var int */
	const STRING = 2;

	/** @var int */
	const BOOL = 3;

	/** @var int */
	const TEXT = 4;

	/** @var int */
	const ROLE_DROPDOWN = 5;

	/** @var string */
	const PAGE_QUERY = '?page=' . self::PREFIX . 'options';

	/** @var string */
	const PAGE_QUERY_MESSAGES = '?page=' . self::PREFIX . 'messages';

	/** @var string */
	const PAGE_QUERY_SPAM = '?page=' . self::PREFIX . 'spam';

	/** @var string */
	const PAGE_QUERY_TRASH = '?page=' . self::PREFIX . 'trash';

	/** @var string */
	const PAGE_QUERY_ANALYSIS = '?page=' . self::PREFIX . 'analyse';

	/** @var boolean */
	const POW_OPTIONS = self::PREFIX . 'pow_options';

	/** @var boolean */
	const POW_INSTALLED = self::PREFIX . 'pow_installed';

	/** @var String */
	const POW_VERSION = self::PREFIX . 'pow_version';

	/** @var string */
	const POW_SALT = self::PREFIX . 'pow_salt';

	/** @var string */
	const POW_DIFFICULTY = self::PREFIX . 'pow_difficulty';

	/** @var string */
	const POW_TIME_WINDOW = self::PREFIX . 'pow_time_window';

	/** @var string */
	const POW_MAX_USES = self::PREFIX . 'pow_max_uses';

	/** @var string */
	const POW_UNDER_ATTACK_MODE = self::PREFIX . 'pow_under_attack_mode';

	/** @var string */
	const POW_UNDER_ATTACK_QUARANTINE = self::PREFIX . 'pow_under_attack_quarantine';

	/** @var string */
	const POW_ECHO_LOCK_ENABLED = self::PREFIX . 'pow_echo_lock_enabled';

	/**
	 * Stage 2 of the Abilities API surface: let an AI agent EXTEND the monitored
	 * scope. Off by default and deliberately its own switch — a write path into the
	 * security boundary must never appear through an update.
	 *
	 * @var string
	 */
	const POW_ABILITIES_WRITE = self::PREFIX . 'pow_abilities_write';

	/**
	 * Stage 3: let an AI agent read stored submissions and change protection
	 * settings. Off by default, does NOT follow from POW_ABILITIES_WRITE, and
	 * carries a permanent admin notice while on.
	 *
	 * @var string
	 */
	const POW_ABILITIES_UNSAFE = self::PREFIX . 'pow_abilities_unsafe';

	/**
	 * Stage 3, READ half: an agent may list and read stored submissions.
	 *
	 * Named "..._READ_SUBMISSIONS", not "..._READ", on purpose. Option names become
	 * API once published, and a bare "READ" next to the existing "WRITE" (which is
	 * stage 2, scope additions) would read as the harmless one — while it actually
	 * grants access to stored submissions including personal data. The name has to
	 * say what is being read.
	 *
	 * @var string
	 */
	const POW_ABILITIES_READ_SUBMISSIONS = self::PREFIX . 'pow_abilities_read_submissions';

	/**
	 * Audit trail of scope changes made through an ability. Bookkeeping, not a
	 * setting: not in prepare_options(), autoload=no. A short-lived transient (the
	 * Scope_Sync notice pattern) would be useless here — an agent writes while the
	 * admin is by definition not at the screen.
	 *
	 * @var string
	 */
	const POW_ABILITIES_LOG = self::PREFIX . 'pow_abilities_log';

	/** @var bool */
	const POW_BLOCK_LOGIN = self::PREFIX . 'pow_block_login';

	/** @var bool */
	const POW_BLOCK = self::PREFIX . 'pow_block';

	/** @var bool */
	const POW_SAVE_SPAM = self::PREFIX . 'pow_save_spam';

	/** @var bool */
	const POW_SAVE_CLEAN = self::PREFIX . 'pow_save_clean';

	/** @var bool */
	const POW_FLAG_SPAM = self::PREFIX . 'pow_flag_spam';

	/** @var bool */
	const POW_FLAG_SAVE = self::PREFIX . 'pow_flag_save';

	/** @var string */
	const POW_FLAG_SUFFIXES = self::PREFIX . 'pow_flag_suffixes';

	/** @var string */
	const POW_FLAG_TAGS = self::PREFIX . 'pow_flag_tags';

	/** @var bool */
	const POW_SIMULATE_SPAM = self::PREFIX . 'pow_simulate_spam';

	/** @var string */
	const POW_MESSAGE_HEADS = self::PREFIX . 'pow_message_heads';

	/** @var int */
	const POW_MENU_POSITION = self::PREFIX . 'pow_menu_position';

	/** @var bool */
	const POW_DASHBOARD = self::PREFIX . 'pow_dashboard';

	/** @var string */
	const POW_IP_WHITELIST = self::PREFIX . 'pow_ip_whitelist';

	/** @var string */
	const POW_SITE_WHITELIST = self::PREFIX . 'pow_site_whitelist';

	/** @var string */
	const POW_TRUSTED_PROXIES = self::PREFIX . 'pow_trusted_proxies';

	/**
	 * Opt-in: treat a private/loopback peer as a reverse proxy while POW_TRUSTED_PROXIES
	 * is empty. Default false — see ClientIp::is_private() for what it heals and what it
	 * costs.
	 *
	 * @var string
	 */
	const POW_TRUST_PRIVATE_PROXY = self::PREFIX . 'pow_trust_private_proxy';

	/**
	 * Confirmation ledger of the SUGGESTED trusted-proxy address (see
	 * class-proxy-candidate-ledger.php). Bookkeeping, not a setting: absent from
	 * prepare_options()/activate() seeding, written with autoload=no, read on the settings
	 * screen only, and deleted the moment POW_TRUSTED_PROXIES is non-empty.
	 *
	 * Holds one candidate — always the private/loopback REMOTE_ADDR the server itself
	 * observed, never an address out of a forwarding header — plus first/last sighting, a
	 * counter and the NAME of the header that indicated the hop. Nothing ever moves from
	 * here into POW_TRUSTED_PROXIES without an explicit admin click (capability + nonce).
	 *
	 * @var string
	 */
	const POW_PROXY_CANDIDATE = self::PREFIX . 'pow_proxy_candidate';

	/** @var bool */
	const POW_SAVE_CART = self::PREFIX . 'pow_save_cart';

	/** @var string */
	const POW_EXPLICIT_ACTION = self::PREFIX . 'pow_explicit_action';

	/** @var int */
	const POW_CRON_DELETE_INBOX = self::PREFIX . 'pow_cron_delete_inbox';

	/** @var int */
	const POW_CRON_DELETE_SPAM = self::PREFIX . 'pow_cron_delete_spam';

	/** @var int */
	const POW_CRON_DELETE_TRASH = self::PREFIX . 'pow_cron_delete_trash';

	/** @var Text */
	const POW_ERROR_MESSAGE = self::PREFIX . 'pow_error_message';

	/** @var Bool */
	const POW_ANALYSIS_MODE = self::PREFIX . 'pow_analysis_mode';

	/** @var Bool */
	const POW_DIRECT_ANALYSIS_MODE = self::PREFIX . 'pow_direct_analysis_mode';

	/** @var Text */
	const POW_PARAMETER_PATTERN = self::PREFIX . 'pow_parameter_pattern';

	/**
	 * Standalone blocklist option (PLAN-BLOCKLIST-TRENNUNG.md AP2/§2): plain-text
	 * lines, one value per line — sender address, "@sender-domain", link domain,
	 * or exact field text. Splits the value-based spam judgment out of
	 * POW_PARAMETER_PATTERN, which now carries only field/value MONITORING
	 * patterns. A real settings option (Settings_Menu group "Spam Processing"),
	 * populated going forward via Message_Page::block_value_callback() and, once,
	 * by Blocked_Values_Migration migrating the old {"*":"value"}/{"*":"@domain"}
	 * lines out of POW_PARAMETER_PATTERN. Read via
	 * Echo_Values::values_from_plaintext_lines().
	 *
	 * @var string
	 */
	const POW_BLOCKED_VALUES = self::PREFIX . 'pow_blocked_values';

	/**
	 * Ledger of the one-off migration that moves legacy {"*":"value"}/
	 * {"*":"@domain"} lines out of POW_PARAMETER_PATTERN into POW_BLOCKED_VALUES
	 * (see class-blocked-values-migration.php, PLAN-BLOCKLIST-TRENNUNG.md §3.3).
	 * NOT an option in the settings sense: deliberately absent from
	 * prepare_options()/activate() seeding, same category as POW_CREDENTIAL_CLEANUP
	 * — nothing here is a user decision, it is migration bookkeeping (a one-off
	 * done flag).
	 *
	 * @var string
	 */
	const POW_BLOCKED_VALUES_MIGRATED = self::PREFIX . 'pow_blocked_values_migrated';

	/**
	 * Third signature class alongside actions/patterns (REST_ROUTES_PLAN.md AP3):
	 * one REST route/namespace per line, matched against the route
	 * `RestRoute::extract()` reads off a POST (see Stamp::check_rest_routes()).
	 * Segment wildcard `*` and namespace-suffix wildcard `/*` supported, see
	 * class-rest-route.php.
	 *
	 * @var string
	 */
	const POW_REST_ROUTES = self::PREFIX . 'pow_rest_routes';

	/**
	 * Ledger of default explicit-actions/patterns already OFFERED to the scope
	 * (Scope_Sync). Not user-facing; tracks which builder defaults have been seen so
	 * a newly-activated builder's action is added once, while an admin-removed entry
	 * is never re-added. See class-scope-sync.php.
	 *
	 * @var string
	 */
	const POW_SEEDED_ACTIONS = self::PREFIX . 'pow_seeded_actions';

	/** @var string */
	const POW_SEEDED_PATTERNS = self::PREFIX . 'pow_seeded_patterns';

	/**
	 * Ledger of default REST routes already OFFERED to POW_REST_ROUTES
	 * (Scope_Sync's third domain, REST_ROUTES_PLAN.md AP4). Same semantics as
	 * POW_SEEDED_ACTIONS/POW_SEEDED_PATTERNS above.
	 *
	 * @var string
	 */
	const POW_SEEDED_ROUTES = self::PREFIX . 'pow_seeded_routes';

	/**
	 * Set once the admin has dismissed (or acted on) the one-time "unmonitored form
	 * builders detected" notice for the pre-existing-install backfill. @var string
	 */
	const POW_SCOPE_NOTICE_DISMISSED = self::PREFIX . 'pow_scope_notice_dismissed';

	/** @var Text */
	const POW_HIDE_ACTION = self::PREFIX . 'pow_hide_action';

	/** @var Text */
	const POW_HIDE_PATTERN = self::PREFIX . 'pow_hide_pattern';

	/** @var Bool */
	const POW_SAVE_IP = self::PREFIX . 'pow_save_ip';

	/** @var Bool */
	const POW_SAVE_LOGIN = self::PREFIX . 'pow_save_login';

	/** @var Text */
	const POW_SKIP_FIELDS = self::PREFIX . 'pow_skip_fields';

	/** @var Text */
	const POW_FAIL_2_BAN_PATH = self::PREFIX . 'pow_fail_2_ban_path';

	/** @var string */
	const HASH = self::PREFIX . 'hash';

	/**
	 * Ledger of the one-off cleanup that redacts credential values older releases
	 * stored in cleartext (see class-credential-cleanup.php). NOT an option in the
	 * settings sense: deliberately absent from prepare_options()/activate() seeding
	 * — nothing here is a user decision, it is migration bookkeeping (layout
	 * version, per-pass cursor and done flag, frozen rgd_id upper bound), same
	 * category as the HEALTH_* constants below. Autoloaded on purpose: once both
	 * passes are done, Credential_Cleanup::maybe_run() must cost a cached
	 * get_option() and nothing else.
	 *
	 * @var string
	 */
	const POW_CREDENTIAL_CLEANUP = self::PREFIX . 'pow_credential_cleanup';

	/**
	 * Admin-maintained list of LEARNED credential field names, one per line (see
	 * class-learned-credential-fields.php). A real setting — rendered on the
	 * settings page as the transparency/correction surface — but NOT the main
	 * entrance: entries normally arrive via the one-click confirmations (admin
	 * notice / message inbox). Deliberately a separate option from
	 * POW_SKIP_FIELDS: skip means "the row never exists" and is site-scoped,
	 * credential means "the row stays, the value reads [redacted]".
	 *
	 * @var string
	 */
	const POW_CREDENTIAL_FIELDS = self::PREFIX . 'pow_credential_fields';

	/**
	 * Ledger of PROPOSED credential field names (see
	 * class-credential-suggestion-ledger.php). Bookkeeping, not a setting:
	 * absent from prepare_options()/activate() seeding, same category as
	 * POW_CREDENTIAL_CLEANUP. Fed from unauthenticated request data, therefore
	 * capped in every direction; nothing ever moves from here to
	 * POW_CREDENTIAL_FIELDS without an explicit admin click.
	 *
	 * @var string
	 */
	const POW_CREDENTIAL_SUGGESTIONS = self::PREFIX . 'pow_credential_suggestions';

	/**
	 * Fingerprint diagnosis counters (see Stamp::record_fp_status()): how many accepted
	 * solves came back from the SAME address the token was issued to, how many from a
	 * different one, and when the last mismatch was seen (unix timestamp).
	 *
	 * Bookkeeping, not settings: absent from prepare_options()/activate() seeding, same
	 * category as POW_CREDENTIAL_CLEANUP, and written with autoload=no — they are read
	 * on two admin screens, never on a front-end request. Monotonic totals on purpose
	 * (no rolling window): the ratio answers a STRUCTURAL question — "is a cache/proxy
	 * in front of this site?" — where inertia is harmless and a window would only add
	 * moving parts. Resettable from the settings status strip.
	 *
	 * @var string
	 */
	const POW_FP_MATCHED_TOTAL = self::PREFIX . 'pow_fp_matched_total';

	/** @var string */
	const POW_FP_MISMATCHED_TOTAL = self::PREFIX . 'pow_fp_mismatched_total';

	/** @var string */
	const POW_FP_LAST_MISMATCH_AT = self::PREFIX . 'pow_fp_last_mismatch_at';

	/**
	 * Storage-failure diagnosis (see Stamp::record_store_failure()): how often an
	 * ACCEPTED solve could not be persisted into `…_stamp_rgs`, when that last happened
	 * (unix timestamp), and the database error that came with it.
	 *
	 * Why this exists at all: `INSERT IGNORE` (check_stamp()) downgrades a real failure
	 * — missing table, half-applied migration, read-only or full database — to a warning
	 * and returns the same 0 a legitimate duplicate returns. Before this counter, such a
	 * site answered every handshake with {accepted:true} while never writing a single
	 * row, so EVERY submission was classified no_pow:token_no_row and the site owner had
	 * nothing to look at (HANDBUCH.md §12 cause 7).
	 *
	 * Bookkeeping, not settings: absent from prepare_options()/activate() seeding,
	 * written with autoload=no, read on the settings screen only.
	 *
	 * @var string
	 */
	const POW_STORE_FAILED_TOTAL = self::PREFIX . 'pow_store_failed_total';

	/** @var string */
	const POW_STORE_LAST_FAILED_AT = self::PREFIX . 'pow_store_last_failed_at';

	/** @var string */
	const POW_STORE_LAST_ERROR = self::PREFIX . 'pow_store_last_error';

	/**
	 * Lookback window (hours) of the "submissions without a stamp row" health counter.
	 *
	 * @var int
	 */
	const HEALTH_NO_POW_WINDOW_HOURS = 24;

	/**
	 * At how many no-stamp submissions within HEALTH_NO_POW_WINDOW_HOURS the health
	 * counter turns amber. NOT an option: plain internal constant, deliberately not in
	 * prepare_options()/activate() (making it user-configurable is a follow-up, not this
	 * change). 10/day is a deliberately low bar — a healthy site sees the occasional
	 * scripted no-stamp POST, but a broken client-PoW pipeline produces this for
	 * *every* human submission, so double-digit counts mean "look at the console".
	 *
	 * @var int
	 */
	const HEALTH_NO_POW_WARN_THRESHOLD = 10;

	/**
	 * Bucket size (minutes) of the storage-independent no-stamp health counter.
	 *
	 * One hour per bucket, so HEALTH_NO_POW_WINDOW_HOURS buckets cover the window.
	 * Coarser than the 5-minute buckets of the under-attack counter on purpose: that
	 * one drives a live decision and needs to react within minutes, this one answers
	 * "is something wrong with this site today".
	 *
	 * @var int
	 */
	const HEALTH_BUCKET_MINUTES = 60;

	/** @var string */
	private $name;

	/** @var int */
	private $type;

	/** @var int */
	private $default;

	/** @var int */
	private $hint;

	/** @var string|int */
	private $value = '';

	/** @var string|int */
	private $symbol = '';

	/** @var string|int */
	private $group = '';

	/** @var string One-sentence short description, always visible (see Settings_Menu). */
	private $short = '';

	/**
	 * @param string $name
	 * @param int $type
	 * @param string $short One-sentence short description, always visible under the label.
	 */
	public function __construct( $name, $type, $default_value, $hint, $group, $symbol = '', $short = '' ) {
		$this->name    = $name;
		$this->type    = $type;
		$this->default = $default_value;
		$this->value   = $default_value;
		$this->hint    = $hint;
		$this->group   = $group;
		$this->symbol  = $symbol;
		$this->short   = $short;
	}

	/**
	 * @return string
	 */
	public function get_name() {
		return $this->name;
	}

	/**
	 * @return int
	 */
	public function get_type() {
		return $this->type;
	}

	/**
	 * @return string|int
	 */
	public function get_default() {
		return $this->default;
	}

	/**
	 * @return string|int
	 */
	public function get_hint() {
		return $this->hint;
	}

	/**
	 * @return int|string
	 */
	public function get_value() {
		return $this->value;
	}

	/**
	 * @return int|string
	 */
	public function get_symbol() {
		return $this->symbol;
	}

	/**
	 * @return int|string
	 */
	public function get_group() {
		return $this->group;
	}

	/**
	 * @return string
	 */
	public function get_short() {
		return $this->short;
	}

	/**
	 * @param $value
	 * @return void
	 */
	public function set_value( $value ) {
		$this->value = $value;
	}

	/**
	 * Share of accepted solves that came back from a different address than the token
	 * was issued to, in whole percent. Pure arithmetic over the two fingerprint
	 * counters (POW_FP_*_TOTAL), so the display can be unit-tested — see
	 * tests/unit/OptionHealthCounterTest.php.
	 *
	 * Returns 0 when nothing has been measured yet: with no data, "0 %" is the honest
	 * reading of the question ("do solves arrive from elsewhere?" — none did), and the
	 * callers hide the whole item at total 0 anyway. Negative/garbage inputs are
	 * floored at 0 rather than producing a nonsensical percentage.
	 *
	 * @param int $matched    POW_FP_MATCHED_TOTAL.
	 * @param int $mismatched POW_FP_MISMATCHED_TOTAL.
	 * @return array{total:int,percent:int} Measured solves and the mismatch share.
	 */
	public static function fp_mismatch_share( $matched, $mismatched ) {
		$matched    = max( 0, (int) $matched );
		$mismatched = max( 0, (int) $mismatched );
		$total      = $matched + $mismatched;

		return array(
			'total'   => $total,
			'percent' => $total > 0 ? (int) round( ( $mismatched * 100 ) / $total ) : 0,
		);
	}
}
