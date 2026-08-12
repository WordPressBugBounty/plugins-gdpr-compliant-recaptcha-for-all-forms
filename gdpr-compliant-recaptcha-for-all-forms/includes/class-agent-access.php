<?php
/**
 * Stage 3 of the Abilities surface: reading submissions, and changing protection.
 *
 * Area doc: handbuch/abilities.md.
 *
 * @package VENDOR\RECAPTCHA_GDPR_COMPLIANT
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/abilities.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * What an AI agent may read and change beyond diagnostics.
 *
 * Split in two halves behind two separate switches, because they are two different
 * decisions and one switch would force the operator to grant both to get either:
 *
 *   POW_ABILITIES_READ_SUBMISSIONS  list and read stored submissions
 *   POW_ABILITIES_UNSAFE            delete a submission, change protection settings
 *
 * THE THREAT MODEL IS THE PROMPT-INJECTED AGENT, not the curious admin — the same
 * one Scope_Add is built against, only sharper here: an agent with the read half
 * literally reads attacker-authored text (this plugin stores spam), and then acts.
 * Every guard below is written for a caller that already holds `manage_options` and
 * is fully hostile.
 *
 * Three consequences, each of which is the reason for a specific rule further down:
 *
 *   1. No ability takes an option NAME from its input without checking it against a
 *      closed allow-list. In particular the agent must not be able to widen its own
 *      rights — POW_ABILITIES_* is not on that list, and neither is POW_SALT.
 *   2. Values are validated, not just names. An allowed setting with an absurd value
 *      is still a denial of service (see PROTECTION_SETTINGS).
 *   3. The analysis folder is NOT readable. See list_folders().
 */
final class Agent_Access {

	/** Folder id for the inbox (rgm_type 1). */
	const FOLDER_INBOX = 'inbox';

	/** Folder id for the spam folder (rgm_type 2). */
	const FOLDER_SPAM = 'spam';

	/** Largest page of submissions one call will return. */
	const MAX_LIMIT = 50;

	/**
	 * The ONLY settings a stage-3 agent may change, each with the bounds its value
	 * must respect.
	 *
	 * A CLOSED LIST, and deliberately a short one. What is on it is the operational
	 * core — "make the protection stricter or turn it on" — and each of them is
	 * visible on the settings screen, so a change is noticeable.
	 *
	 * What is NOT on it, and why, since that is the more important half:
	 *
	 *   POW_ABILITIES_*     an agent must not be able to widen its own rights. This
	 *                       is the single most important line in this class.
	 *   POW_SALT            rotating it invalidates every token in flight; there is
	 *                       no agent task that needs it.
	 *   POW_IP_WHITELIST    all four are the address-trust configuration. An agent
	 *   POW_SITE_WHITELIST  that can write them can exempt itself, or make the
	 *   POW_TRUSTED_PROXIES resolved visitor address freely choosable.
	 *   POW_TRUST_PRIVATE_PROXY
	 *   the three scope options  they belong to stage 2, which has its own guards
	 *                       (Scope_Add::plan()) that this path would bypass.
	 *   POW_SIMULATE_SPAM   the quietest kill switch on the whole option surface:
	 *                       protection effectively off, spam delivered, and the only
	 *                       sign is one word in the status strip. No plausible agent
	 *                       task needs it — it is a human-at-the-screen workflow.
	 *   POW_SAVE_SPAM       "stop storing the evidence from now on", which together
	 *                       with delete-submission below is complete cleanup in two
	 *                       calls. The storage-saving argument does not pay for that.
	 *
	 * @var array<string,array{type:string,min?:int,max?:int}>
	 */
	const PROTECTION_SETTINGS = array(
		Option::POW_DIFFICULTY        => array(
			// CLAMPED, and the clamp is not cosmetic. Difficulty is exponential work:
			// a value like 60 locks out every real visitor (no browser solves 2^60)
			// while looking like a perfectly ordinary setting — a full denial of
			// service through an "allowed" option. A 0 at the other end makes the
			// proof of work free. The bounds mirror what the settings screen offers.
			'type' => 'int',
			'min'  => 8,
			'max'  => 25,
		),
		Option::POW_BLOCK             => array( 'type' => 'bool' ),
		Option::POW_UNDER_ATTACK_MODE => array( 'type' => 'bool' ),
	);

	/**
	 * Whether the read half is switched on.
	 *
	 * @return bool
	 */
	public static function read_enabled() {
		return (bool) get_option( Option::POW_ABILITIES_READ_SUBMISSIONS );
	}

	/**
	 * Whether the write/delete half is switched on.
	 *
	 * @return bool
	 */
	public static function write_enabled() {
		return (bool) get_option( Option::POW_ABILITIES_UNSAFE );
	}

	/**
	 * The folders an agent may read, mapped to their `rgm_type`.
	 *
	 * THE ANALYSIS FOLDER (type 4) IS ABSENT ON PURPOSE. Analysis-mode rows are
	 * created from EVERY POST while the mode is on — including wp-admin saves of
	 * other plugins, i.e. API keys and secrets an admin typed into some settings
	 * form. The credential redaction only catches password-NAMED fields, so those
	 * values sit there in the clear. An agent reading that folder would be reading
	 * far more than "stored spam", and a prompt-injected one would be exfiltrating
	 * it. Inbox and spam cover what this surface is actually for.
	 *
	 * @return array<string,int>
	 */
	public static function list_folders() {
		return array(
			self::FOLDER_INBOX => 1,
			self::FOLDER_SPAM  => 2,
		);
	}

	/**
	 * Decide whether a protection change is allowed, and with which value.
	 *
	 * PURE — no options, no WordPress, no side effects — so every rejection is
	 * directly unit-testable (tests/unit/AgentAccessPlanTest.php), the same split
	 * Scope_Add::plan() uses and for the same reason.
	 *
	 * @param mixed $setting Requested setting key (untrusted, any type).
	 * @param mixed $value   Requested value (untrusted, any type).
	 * @return array{ok:bool,setting?:string,value?:mixed,reason?:string}
	 */
	public static function plan_protection_change( $setting, $value ) {
		if ( ! is_string( $setting ) || '' === $setting ) {
			return array(
				'ok'     => false,
				'reason' => 'setting_not_a_name',
			);
		}

		if ( ! array_key_exists( $setting, self::PROTECTION_SETTINGS ) ) {
			return array(
				'ok'     => false,
				'reason' => 'setting_not_allowed',
			);
		}

		$spec = self::PROTECTION_SETTINGS[ $setting ];

		if ( 'bool' === $spec['type'] ) {
			// Strict: a string like "maybe" must be a rejection, not a truthy cast.
			// Silently reading garbage as "on" is how a protection setting ends up in
			// a state nobody chose.
			if ( is_bool( $value ) ) {
				return array(
					'ok'      => true,
					'setting' => $setting,
					'value'   => $value,
				);
			}
			if ( in_array( $value, array( 1, 0, '1', '0', 'true', 'false' ), true ) ) {
				return array(
					'ok'      => true,
					'setting' => $setting,
					'value'   => in_array( $value, array( 1, '1', 'true' ), true ),
				);
			}
			return array(
				'ok'     => false,
				'reason' => 'value_not_a_boolean',
			);
		}

		if ( ! is_int( $value ) && ! ( is_string( $value ) && ctype_digit( $value ) ) ) {
			return array(
				'ok'     => false,
				'reason' => 'value_not_an_integer',
			);
		}

		$number = (int) $value;
		if ( $number < $spec['min'] || $number > $spec['max'] ) {
			// REJECTED, not clamped into range. Clamping would answer "done" to a
			// request that was not carried out, and an agent acting on that answer
			// believes the site is in a state it is not in.
			return array(
				'ok'     => false,
				'reason' => 'value_out_of_range',
			);
		}

		return array(
			'ok'      => true,
			'setting' => $setting,
			'value'   => $number,
		);
	}

	/**
	 * Plain-English text for a rejection reason. Every refusal is NAMED, never
	 * silently swallowed — the same stance as Scope_Add::explain() and the
	 * add_settings_error() guard on the settings screen.
	 *
	 * @param string $reason Reason code from plan_protection_change().
	 * @return string
	 */
	public static function explain( $reason ) {
		$texts = array(
			'setting_not_a_name'   => __( 'The setting name must be a non-empty string.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'setting_not_allowed'  => __( 'This setting cannot be changed through an ability. Only the puzzle difficulty, spam blocking and under-attack mode can. Address trust, the monitored scope, spam simulation, spam storage, the token secret and the agent permissions themselves are deliberately excluded.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'value_not_a_boolean'  => __( 'This setting is a switch; pass true or false.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'value_not_an_integer' => __( 'This setting is a number; pass an integer.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'value_out_of_range'   => __( 'The value is outside the range this setting accepts. The difficulty in particular is exponential work: a value above the range locks out real visitors, one below it makes the puzzle free.', 'gdpr-compliant-recaptcha-for-all-forms' ),
		);

		return isset( $texts[ $reason ] ) ? $texts[ $reason ] : __( 'Refused.', 'gdpr-compliant-recaptcha-for-all-forms' );
	}

	/**
	 * Normalise a requested page size into the allowed range. Pure.
	 *
	 * @param mixed $limit Requested limit.
	 * @return int
	 */
	public static function clamp_limit( $limit ) {
		if ( ! is_int( $limit ) && ! ( is_string( $limit ) && ctype_digit( $limit ) ) ) {
			return 20;
		}

		return max( 1, min( self::MAX_LIMIT, (int) $limit ) );
	}

	/* ---------------------------------------------------------------------
	 * Database access — everything above this line is pure.
	 * ------------------------------------------------------------------ */

	/**
	 * One page of submission summaries from a folder. No field contents — that is
	 * what get_submission() is for, one submission at a time.
	 *
	 * @param string $folder One of the list_folders() keys.
	 * @param int    $limit  Page size (already clamped).
	 * @param int    $offset Rows to skip.
	 * @return array<int,array<string,mixed>>
	 */
	public static function list_submissions( $folder, $limit, $offset ) {
		global $wpdb;

		$folders = self::list_folders();
		if ( ! isset( $folders[ $folder ] ) ) {
			return array();
		}

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT rgm_id, rgm_date, rgm_type, rgm_action FROM ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm'
				. ' WHERE rgm_type = %d ORDER BY rgm_id DESC LIMIT %d OFFSET %d',
				$folders[ $folder ],
				(int) $limit,
				max( 0, (int) $offset )
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return array();
		}

		$out = array();
		foreach ( $rows as $row ) {
			$id    = (int) $row['rgm_id'];
			$out[] = array(
				'id'      => $id,
				'date'    => (string) $row['rgm_date'],
				'folder'  => $folder,
				'action'  => (string) $row['rgm_action'],
				'reason'  => self::technical_field( $id, '_gdpr_reason' ),
				'scoring' => self::technical_field( $id, '_gdpr_scoring' ),
			);
		}

		return $out;
	}

	/**
	 * The stored fields of one submission.
	 *
	 * REDACTION, AND WHY IT IS A SECOND LINE AND NOT THE FIRST. Password values are
	 * redacted once, at save time (Stamp::save_message()), so what sits in the table
	 * is already redacted for every field the plugin recognised as a credential. The
	 * message screen renders those stored values as they are — including, via its
	 * "treat as credential field" rescue path, rows that were stored UNREDACTED
	 * because the field was not recognised at the time. Those are exactly the rows an
	 * agent must not receive, so the attribute path is checked again here with
	 * Credential_Fields::is_password_path(). Cheap (a pure function that already
	 * exists), and it fails in the safe direction.
	 *
	 * @param int $id Message id.
	 * @return array<string,mixed>|null Null when there is no such submission.
	 */
	public static function get_submission( $id ) {
		global $wpdb;

		$id  = (int) $id;
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT rgm_id, rgm_date, rgm_type, rgm_action FROM ' . $wpdb->prefix . 'recaptcha_gdpr_message_rgm WHERE rgm_id = %d',
				$id
			),
			ARRAY_A
		);

		if ( ! $row ) {
			return null;
		}

		$folders = array_flip( self::list_folders() );
		if ( ! isset( $folders[ (int) $row['rgm_type'] ] ) ) {
			// Analysis rows (type 4) are not readable here — see list_folders().
			return null;
		}

		$details = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT rgd_attribute, rgd_value FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd WHERE rgm_id = %d',
				$id
			),
			ARRAY_A
		);

		$fields = array();
		if ( is_array( $details ) ) {
			foreach ( $details as $detail ) {
				$attribute = (string) $detail['rgd_attribute'];
				if ( Credential_Fields::is_password_path( $attribute ) ) {
					$fields[ $attribute ] = '[redacted]';
					continue;
				}
				$fields[ $attribute ] = (string) $detail['rgd_value'];
			}
		}

		return array(
			'id'     => $id,
			'date'   => (string) $row['rgm_date'],
			'folder' => $folders[ (int) $row['rgm_type'] ],
			'action' => (string) $row['rgm_action'],
			'fields' => $fields,
		);
	}

	/**
	 * Delete one submission and its detail rows.
	 *
	 * @param int $id Message id.
	 * @return bool Whether a row was deleted.
	 */
	public static function delete_submission( $id ) {
		global $wpdb;

		$id = (int) $id;
		if ( $id <= 0 || null === self::get_submission( $id ) ) {
			return false;
		}

		$wpdb->delete( $wpdb->prefix . 'recaptcha_gdpr_details_rgd', array( 'rgm_id' => $id ), array( '%d' ) );
		$deleted = $wpdb->delete( $wpdb->prefix . 'recaptcha_gdpr_message_rgm', array( 'rgm_id' => $id ), array( '%d' ) );

		return (bool) $deleted;
	}

	/**
	 * Read one technical detail row (`_gdpr_reason`, `_gdpr_scoring`).
	 *
	 * @param int    $id        Message id.
	 * @param string $attribute Technical attribute name.
	 * @return string|null
	 */
	private static function technical_field( $id, $attribute ) {
		global $wpdb;

		$value = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT rgd_value FROM ' . $wpdb->prefix . 'recaptcha_gdpr_details_rgd WHERE rgm_id = %d AND rgd_attribute = %s LIMIT 1',
				(int) $id,
				$attribute
			)
		);

		return null === $value ? null : (string) $value;
	}

	/**
	 * Append an entry to the shared audit trail (Option::POW_ABILITIES_LOG).
	 *
	 * Records the OLD value alongside the new one for a protection change. "Was set"
	 * alone does not let an admin undo anything, and undoing is the first thing they
	 * will want when they find a change they did not make.
	 *
	 * @param string $ability Full ability id.
	 * @param string $action  Short action label.
	 * @param array  $detail  Arbitrary detail payload.
	 * @return void
	 */
	public static function record( $ability, $action, array $detail ) {
		$log = get_option( Option::POW_ABILITIES_LOG, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		$log[] = array(
			'at'      => time(),
			'ability' => (string) $ability,
			'domain'  => (string) $action,
			'user'    => get_current_user_id(),
			'detail'  => $detail,
		);

		if ( count( $log ) > 100 ) {
			$log = array_slice( $log, -100 );
		}

		update_option( Option::POW_ABILITIES_LOG, $log, false );
	}
}
