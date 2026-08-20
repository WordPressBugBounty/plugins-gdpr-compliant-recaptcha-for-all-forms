<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Class Support_Report: the "Support report" button on the Diagnostics tab — one
 * copyable, plain-text status block a site owner can post into the PUBLIC wp.org
 * support forum without exposing anything sensitive.
 *
 * ONE STEP, ONE BLOCK (BACKLOG.md "Support-Report-Knopf auf dem Diagnostics-Reiter",
 * Fable-decided 2026-08-18). The whole feature is: FIELD_KEYS (the whitelist),
 * collect() (the WP-dependent reader) and render() (the pure formatter). No upload,
 * no mail, no new option — copy-paste is the entire delivery mechanism.
 *
 * FIELD_KEYS is the closed, ordered set of everything the report may ever contain.
 * A field that is not in this list cannot appear, no matter what collect() puts into
 * $values — that is what "closed whitelist" means here, and it is why render()
 * accepts an arbitrary array rather than reading options itself.
 *
 * THE SECURITY LINE, drawn from the forum-safety analysis in BACKLOG.md:
 *   - full VALUES: versions, base/effective difficulty, time window, max uses,
 *     under-attack mode + quarantine, echo lock, every operational on/off switch
 *     (an attacker probing a single target can already feel these out with two or
 *     three test submissions — a report that hid them would just be a worse report),
 *     cron retention, the health/store-failure/address-change counters, and proxy
 *     status as yes/no only.
 *   - COUNTS ONLY, never content: every list option (whitelists, trusted proxies,
 *     blocked values, the three scope lists, learned credential fields) and the
 *     repeat-sender lock's held-value count — a value dump would hand a spammer the
 *     exact blocklist to avoid, and the scope lists would reveal which forms are NOT
 *     watched. Routed exclusively through line_count() (see there) so this rule is
 *     enforced at one place instead of trusted by convention.
 *   - NEVER: the four AI-agent write/unsafe/read-submissions/audit-log toggles (a
 *     public "agent write access is on" is a machine-greppable target list), the
 *     stamp-token signing secret, any IP/hostname/site URL, header VALUES, message
 *     content, field values of any kind. A source-level test (SupportReportTest)
 *     pins that none of those option identifiers occurs anywhere in this file —
 *     comments included, case-insensitively — not just "unused by collect()".
 *
 * No second stage: an operator who wants those four toggles checked asks the
 * maintainer directly, in one sentence — see BACKLOG.md for why that does not
 * justify a second report tier.
 *
 * Deliberately excludes two options the initial field list named that turned out not
 * to fit the "value" grammar at all (see plugin session notes / handbuch/admin.md):
 * POW_EXPLICIT_ACTION is a scope LIST (the "apply on actions" textarea, same category
 * as the pattern/route lists) and is reported as a count via scope_actions_lines
 * instead — listing its actual value would be exactly the scope leak the "counts
 * only" rule exists to prevent. POW_CREDENTIAL_CLEANUP is a migration ledger
 * (cursor/done flags per pass), not a user-facing on/off setting, so it has no
 * meaningful "value" to report at all.
 *
 * Also deliberately excludes the "clock delta, database NOW() vs. PHP UTC" field the
 * initial field list asked for (HANDBUCH.md §12 cause 8, "two clocks"): the only way to
 * answer it is a query that lets MySQL evaluate its own clock, which is exactly the
 * plugin-wide anti-pattern tests/unit/OneClockTest.php exists to forbid across all of
 * plugin/ — the very defect class that bug report was about. This class is not an
 * exception to that invariant, so the field was dropped rather than adding a loophole
 * (e.g. an unlisted function name) that would satisfy the letter of the guard while
 * repeating the mistake it guards against.
 */
class Support_Report {

	/**
	 * The complete, closed list of field keys, in output order. THIS is the
	 * whitelist — render() never emits a key outside this list, however many keys
	 * $values carries.
	 *
	 * @var string[]
	 */
	const FIELD_KEYS = array(
		'plugin_version',
		'wordpress_version',
		'php_version',
		'difficulty_base',
		'difficulty_effective',
		'time_window_minutes',
		'max_uses',
		'under_attack_mode',
		'under_attack_quarantine',
		'echo_lock_enabled',
		'block_enabled',
		'block_login_enabled',
		'flag_spam_enabled',
		'flag_save_enabled',
		'save_spam_enabled',
		'save_clean_enabled',
		'save_ip_enabled',
		'save_login_enabled',
		'save_cart_enabled',
		'simulate_spam_enabled',
		'analysis_mode_enabled',
		'direct_analysis_mode_enabled',
		'cron_delete_inbox_days',
		'cron_delete_spam_days',
		'cron_delete_trash_days',
		'health_no_pow_count',
		'store_failed_total',
		'fp_mismatch_percent',
		'fp_mismatch_total',
		'reason_distribution_24h',
		'trusted_proxies_configured',
		'trust_private_proxy_enabled',
		'forwarding_header_present',
		'ip_whitelist_lines',
		'site_whitelist_lines',
		'trusted_proxies_lines',
		'blocked_values_lines',
		'scope_actions_lines',
		'scope_patterns_lines',
		'scope_routes_lines',
		'credential_fields_lines',
		'skip_fields_lines',
		'echo_store_count',
	);

	/**
	 * Literal first line of every report — states its own purpose, because nothing
	 * controls where a copied block ends up once it is on the clipboard.
	 *
	 * @var string
	 */
	const SAFETY_LINE = 'GDPR ReCaptcha support report — safe to post publicly (no addresses, list contents or secrets)';

	/**
	 * English label for each FIELD_KEYS entry. Plain hardcoded strings, not __() —
	 * render() is WordPress-free on purpose (see there), and the plugin UI is English
	 * throughout anyway (same reasoning as Classification_Reason::label()).
	 *
	 * @return array<string, string>
	 */
	private static function labels() {
		return array(
			'plugin_version'               => 'Plugin version',
			'wordpress_version'            => 'WordPress version',
			'php_version'                  => 'PHP version',
			'difficulty_base'              => 'Difficulty (base)',
			'difficulty_effective'         => 'Difficulty (effective)',
			'time_window_minutes'          => 'Time window (minutes)',
			'max_uses'                     => 'Max uses per solved stamp',
			'under_attack_mode'            => 'Under-attack mode',
			'under_attack_quarantine'      => 'Under-attack quarantine',
			'echo_lock_enabled'            => 'Repeat-sender lock (echo lock)',
			'block_enabled'                => 'Block',
			'block_login_enabled'          => 'Block on login',
			'flag_spam_enabled'            => 'Flag instead of block',
			'flag_save_enabled'            => 'Save flagged messages',
			'save_spam_enabled'            => 'Save spam messages',
			'save_clean_enabled'           => 'Save clean messages',
			'save_ip_enabled'              => 'Save sender IP',
			'save_login_enabled'           => 'Save login/password-reset submissions',
			'save_cart_enabled'            => 'Save cart/checkout activity',
			'simulate_spam_enabled'        => 'Simulation mode',
			'analysis_mode_enabled'        => 'Analysis mode',
			'direct_analysis_mode_enabled' => 'Direct analysis mode',
			'cron_delete_inbox_days'       => 'Auto-delete inbox after (days, 0 = off)',
			'cron_delete_spam_days'        => 'Auto-delete spam after (days, 0 = off)',
			'cron_delete_trash_days'       => 'Auto-delete trash after (days, 0 = off)',
			'health_no_pow_count'          => 'Submissions without a stamp (24h)',
			'store_failed_total'           => 'Failed stamp stores (total)',
			'fp_mismatch_percent'          => 'Address-change rate (%)',
			'fp_mismatch_total'            => 'Address-change measurements (total)',
			'reason_distribution_24h'      => 'Reason-code distribution, 24h (0 everywhere means "not saved", not "no spam")',
			'trusted_proxies_configured'   => 'Trusted proxies configured',
			'trust_private_proxy_enabled'  => 'Trust private-network proxy',
			'forwarding_header_present'    => 'Forwarding header present on this request',
			'ip_whitelist_lines'           => 'IP whitelist entries',
			'site_whitelist_lines'         => 'Site whitelist entries',
			'trusted_proxies_lines'        => 'Trusted proxy entries',
			'blocked_values_lines'         => 'Blocked-value rules',
			'scope_actions_lines'          => 'Scope: actions',
			'scope_patterns_lines'         => 'Scope: patterns',
			'scope_routes_lines'           => 'Scope: REST routes',
			'credential_fields_lines'      => 'Learned credential fields',
			'skip_fields_lines'            => 'Skip fields configured',
			'echo_store_count'             => 'Repeat-sender lock: values held',
		);
	}

	/**
	 * Format $values into the plain-text report. PURE: no get_option(), no WordPress
	 * function of any kind, nothing but string handling — the whole reason collect()
	 * and render() are two different methods.
	 *
	 * Unknown keys in $values (anything outside FIELD_KEYS) are ignored; a FIELD_KEYS
	 * entry missing from $values prints as "unknown" rather than being skipped, so
	 * the line count of a report is always the same regardless of what collect()
	 * managed to read. render() therefore never emits more lines than FIELD_KEYS has
	 * entries, plus the one safety line.
	 *
	 * @param array<string, mixed> $values Field key => value, as produced by collect().
	 * @return string
	 */
	public static function render( array $values ) {
		$labels = self::labels();
		$lines  = array( self::SAFETY_LINE );

		foreach ( self::FIELD_KEYS as $key ) {
			$value   = array_key_exists( $key, $values ) ? $values[ $key ] : 'unknown';
			$label   = isset( $labels[ $key ] ) ? $labels[ $key ] : $key;
			$lines[] = $label . ': ' . self::stringify( $value );
		}

		return implode( "\n", $lines );
	}

	/**
	 * @param mixed $value
	 * @return string
	 */
	private static function stringify( $value ) {
		if ( is_bool( $value ) ) {
			return $value ? 'on' : 'off';
		}
		return (string) $value;
	}

	/**
	 * The WP-dependent half: reads options and counters, returns exactly the keys
	 * FIELD_KEYS names. Nothing here decides what gets PRINTED — that is render()'s
	 * job — this method only decides what gets READ.
	 *
	 * @return array<string, mixed>
	 */
	public static function collect() {
		$base_difficulty = (int) get_option( Option::POW_DIFFICULTY );
		$under_attack_on = (bool) get_option( Option::POW_UNDER_ATTACK_MODE, true );
		// Same gate as Stamp::issue_difficulty()/Settings_Menu::render_status_strip():
		// the boost only applies while the option is enabled.
		$under_attack_now = $under_attack_on && Stamp::is_under_attack();

		$fp_share = Option::fp_mismatch_share(
			get_option( Option::POW_FP_MATCHED_TOTAL, 0 ),
			get_option( Option::POW_FP_MISMATCHED_TOTAL, 0 )
		);

		$trusted_proxy_lines = self::line_count( Option::POW_TRUSTED_PROXIES );

		return array(
			'plugin_version'               => RCM_Main::VERSION,
			'wordpress_version'            => get_bloginfo( 'version' ),
			'php_version'                  => PHP_VERSION,
			'difficulty_base'              => $base_difficulty,
			'difficulty_effective'         => ProofOfWork::effective_difficulty( $base_difficulty, $under_attack_now, Stamp::UNDER_ATTACK_BONUS ),
			'time_window_minutes'          => (int) get_option( Option::POW_TIME_WINDOW, 10 ),
			'max_uses'                     => (int) get_option( Option::POW_MAX_USES, 10 ),
			'under_attack_mode'            => $under_attack_on,
			'under_attack_quarantine'      => (bool) get_option( Option::POW_UNDER_ATTACK_QUARANTINE ),
			'echo_lock_enabled'            => Echo_Store::is_enabled(),
			'block_enabled'                => (bool) get_option( Option::POW_BLOCK ),
			'block_login_enabled'          => (bool) get_option( Option::POW_BLOCK_LOGIN ),
			'flag_spam_enabled'            => (bool) get_option( Option::POW_FLAG_SPAM ),
			'flag_save_enabled'            => (bool) get_option( Option::POW_FLAG_SAVE ),
			'save_spam_enabled'            => (bool) get_option( Option::POW_SAVE_SPAM ),
			'save_clean_enabled'           => (bool) get_option( Option::POW_SAVE_CLEAN ),
			'save_ip_enabled'              => (bool) get_option( Option::POW_SAVE_IP ),
			'save_login_enabled'           => (bool) get_option( Option::POW_SAVE_LOGIN, true ),
			'save_cart_enabled'            => (bool) get_option( Option::POW_SAVE_CART ),
			'simulate_spam_enabled'        => (bool) get_option( Option::POW_SIMULATE_SPAM ),
			'analysis_mode_enabled'        => (bool) get_option( Option::POW_ANALYSIS_MODE ),
			'direct_analysis_mode_enabled' => (bool) get_option( Option::POW_DIRECT_ANALYSIS_MODE ),
			'cron_delete_inbox_days'       => (int) get_option( Option::POW_CRON_DELETE_INBOX, 0 ),
			'cron_delete_spam_days'        => (int) get_option( Option::POW_CRON_DELETE_SPAM, 0 ),
			'cron_delete_trash_days'       => (int) get_option( Option::POW_CRON_DELETE_TRASH, 0 ),
			'health_no_pow_count'          => Option::no_pow_health_count(),
			'store_failed_total'           => (int) get_option( Option::POW_STORE_FAILED_TOTAL, 0 ),
			'fp_mismatch_percent'          => $fp_share['percent'],
			'fp_mismatch_total'            => $fp_share['total'],
			'reason_distribution_24h'      => self::reason_distribution_24h(),
			'trusted_proxies_configured'   => $trusted_proxy_lines > 0 ? 'yes' : 'no',
			'trust_private_proxy_enabled'  => (bool) get_option( Option::POW_TRUST_PRIVATE_PROXY ),
			'forwarding_header_present'    => self::forwarding_header_present() ? 'yes' : 'no',
			'ip_whitelist_lines'           => self::line_count( Option::POW_IP_WHITELIST ),
			'site_whitelist_lines'         => self::line_count( Option::POW_SITE_WHITELIST ),
			'trusted_proxies_lines'        => $trusted_proxy_lines,
			'blocked_values_lines'         => self::line_count( Option::POW_BLOCKED_VALUES ),
			'scope_actions_lines'          => self::line_count( Option::POW_EXPLICIT_ACTION ),
			'scope_patterns_lines'         => self::line_count( Option::POW_PARAMETER_PATTERN ),
			'scope_routes_lines'           => self::line_count( Option::POW_REST_ROUTES ),
			'credential_fields_lines'      => self::line_count( Option::POW_CREDENTIAL_FIELDS ),
			'skip_fields_lines'            => self::line_count( Option::POW_SKIP_FIELDS ),
			'echo_store_count'             => Echo_Store::count(),
		);
	}

	/**
	 * The ONLY access path to a list-shaped option in this file — deliberately, so
	 * "counts only, never content" is a source-level invariant instead of a
	 * convention (see Support_ReportTest.php, the source-pinning test). Same
	 * trim/split/filter shape as Settings_Menu::maybe_adopt_proxy_candidate().
	 *
	 * @param string $option_name One of the Option::POW_*_WHITELIST/…_VALUES/…_ROUTES
	 *                            constants — never resolved or printed, only counted.
	 * @return int
	 */
	private static function line_count( $option_name ) {
		$raw = (string) get_option( $option_name, '' );
		if ( '' === trim( $raw ) ) {
			return 0;
		}
		$lines = preg_split( '/\r\n|\n|\r/', $raw );
		$lines = array_filter(
			array_map( 'trim', is_array( $lines ) ? $lines : array() ),
			static function ( $line ) {
				return '' !== $line;
			}
		);
		return count( $lines );
	}

	/**
	 * Whether THIS request carries any forwarding header at all — presence only, the
	 * value is never read or stored. Same header list and the same "never resolve"
	 * discipline as Settings_Menu::forwarding_header_with_public_address(), but
	 * without that method's "carries a PUBLIC address" narrowing: a support report
	 * just needs the yes/no a site owner can act on ("is anything even sending a
	 * proxy header"), not the proxy-candidate-ledger's stricter bar.
	 *
	 * @return bool
	 */
	private static function forwarding_header_present() {
		foreach ( ClientIp::DIAGNOSTIC_HEADERS as $header_name ) {
			if ( ! empty( $_SERVER[ $header_name ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The exact `_gdpr_reason` values the 24h distribution counts, in report order —
	 * always Classification_Reason enum strings, never whatever a stored row happens
	 * to contain (Fable pre-release review, 2026-08-18: "die Codes sind Enum-Strings
	 * … keine freien Texte"). NO_POW_CHAIN_NO_ROW is deliberately absent:
	 * Classification_Reason::HISTORIC_CODES marks it as a code no path writes any
	 * more, so counting it would answer a question about pre-5.3.4 rows, not about a
	 * fix that could apply today.
	 *
	 * @return string[]
	 */
	private static function reason_distribution_codes() {
		return array(
			Classification_Reason::NO_POW_NO_TOKEN,
			Classification_Reason::NO_POW_INVALID_TOKEN,
			Classification_Reason::NO_POW_TOKEN_NO_ROW,
			Classification_Reason::NO_POW_TOKEN_IP_CHANGED,
			Classification_Reason::CODE_SIMULATION,
			Classification_Reason::CODE_ECHO_LOCK,
			Classification_Reason::CODE_WILDCARD,
			Classification_Reason::CODE_QUARANTINE,
		);
	}

	/**
	 * Pure aggregation: turn raw `{reason, total}` rows (shaped like MySQL's GROUP BY
	 * would return them) into the "code=count" breakdown string, restricted to
	 * reason_distribution_codes() plus one bucket for CODE_GIBBERISH. Any row whose
	 * value is neither an exact whitelisted code nor a `gibberish:`-prefixed detail is
	 * silently dropped rather than echoed — the whitelist IS the "enum strings, never
	 * free text" rule, not a convention layered on top of it. No WordPress dependency,
	 * so this half is directly unit-testable (SupportReportTest).
	 *
	 * @param array<int, array{reason: mixed, total: mixed}> $rows
	 * @return string
	 */
	private static function format_reason_distribution( array $rows ) {
		$counts                    = array_fill_keys( self::reason_distribution_codes(), 0 );
		$gibberish_code            = Classification_Reason::CODE_GIBBERISH;
		$counts[ $gibberish_code ] = 0;

		foreach ( $rows as $row ) {
			$reason = isset( $row['reason'] ) ? (string) $row['reason'] : '';
			$total  = isset( $row['total'] ) ? (int) $row['total'] : 0;

			if ( array_key_exists( $reason, $counts ) ) {
				$counts[ $reason ] += $total;
				continue;
			}
			if ( 0 === strpos( $reason, $gibberish_code . ':' ) ) {
				$counts[ $gibberish_code ] += $total;
			}
			// Anything else (legacy code, or a corrupted/foreign rgd_value) is silently
			// dropped: it is not a recognised enum string, so it is never echoed.
		}

		$parts = array();
		foreach ( $counts as $code => $count ) {
			$parts[] = $code . '=' . $count;
		}
		return implode( ', ', $parts );
	}

	/**
	 * `_gdpr_reason` counts per code over the last 24h.
	 *
	 * ONE CLOCK: reads with the SAME clock `rgm_date` was WRITTEN with —
	 * current_time('mysql'), i.e. WordPress's configured local time — exactly like
	 * Option::count_no_pow_reasons_since_hours(). Never MySQL's own NOW()/CURDATE()/
	 * etc, which tests/unit/OneClockTest.php forbids across all of plugin/ (the exact
	 * "two clocks" defect class, HANDBUCH.md §12 cause 8): the threshold is computed
	 * in PHP and bound as a %s literal, so MySQL never evaluates "now" itself.
	 *
	 * These rows exist only when Stamp::save_message() actually ran for a classified
	 * submission — gated behind POW_SAVE_SPAM for spam. An all-zero result therefore
	 * means "nothing was SAVED in the window", not "nothing happened"; the field's
	 * label carries that caveat, since a blank-looking value is the one most likely to
	 * be misread.
	 *
	 * @return string
	 */
	private static function reason_distribution_24h() {
		global $wpdb;
		// phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested -- intentional: matches the current_time('mysql')-written rgm_date, same technique as Option::count_no_pow_reasons_since_hours().
		$threshold = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - 24 * HOUR_IN_SECONDS );
		$rows      = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT rgd.rgd_value AS reason, COUNT(*) AS total FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd rgd'
				. ' INNER JOIN ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm rgm ON rgm.rgm_id = rgd.rgm_id'
				. ' WHERE rgd.rgd_attribute = %s AND rgm.rgm_date >= %s'
				. ' GROUP BY rgd.rgd_value',
				'_gdpr_reason',
				$threshold
			),
			ARRAY_A
		);

		return self::format_reason_distribution( is_array( $rows ) ? $rows : array() );
	}
}
