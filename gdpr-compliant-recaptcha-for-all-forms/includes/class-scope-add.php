<?php
/**
 * Additive, guarded extension of the monitored scope.
 *
 * Area doc: handbuch/abilities.md (this class), handbuch/gate.md (what the three
 * scope options mean and why a wrong entry is dangerous).
 *
 * @package VENDOR\RECAPTCHA_GDPR_COMPLIANT
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Plans and applies additions to the monitored scope on behalf of a caller that is
 * NOT a human at the settings screen — today an AI agent through the Abilities API.
 *
 * The whole class exists because the settings textarea and this path have different
 * threat models even though they write the same three options. A human typing
 * `{"email":null}` into the textarea causes the documented, self-inflicted cost case
 * in handbuch/gate.md: backend forms start matching, POW_BLOCK discards the save, and
 * wp-admin never gets a proof-of-work script, so the admin cannot type their way out
 * again. That is a bad afternoon, and it is theirs.
 *
 * The same line arriving through an ability is a different animal. An agent reads
 * text it did not write — including, once stage 3 exists, spam this very plugin
 * stored — so a prompt-injected agent is the realistic caller, not the hypothetical
 * one. `plan()` therefore has to hold against a fully hostile caller that already
 * holds `manage_options`, and its job is narrow on purpose:
 *
 *   - it only ever ADDS (there is no removal path here, by construction),
 *   - it refuses entries that would match wp-admin's own traffic,
 *   - it refuses entries that classify rather than monitor, and
 *   - it names every rejection instead of silently dropping it.
 *
 * Everything in plan() is pure: no options, no WordPress, no side effects. Only
 * apply() touches the database. That split is what makes the guards unit-testable
 * (tests/unit/ScopeAddPlanTest.php).
 */
final class Scope_Add {

	/** Domain key for POW_EXPLICIT_ACTION (admin-ajax action names). */
	const DOMAIN_ACTIONS = 'actions';

	/** Domain key for POW_PARAMETER_PATTERN (field-shape patterns). */
	const DOMAIN_PATTERNS = 'patterns';

	/** Domain key for POW_REST_ROUTES (REST route identifiers). */
	const DOMAIN_ROUTES = 'routes';

	/**
	 * Most entries accepted in a single call. Not a security boundary on its own —
	 * a caller can call again — but it keeps one confused request from rewriting the
	 * whole scope, and it makes the returned report readable by a human.
	 */
	const MAX_PER_CALL = 10;

	/**
	 * Hard ceiling per domain, counting entries that are already there. All three
	 * options are autoloaded, so unbounded growth is paid for on every single
	 * request of the site, not just on the settings screen.
	 */
	const MAX_TOTAL_LINES = 400;

	/** Longest single entry we accept, in characters. */
	const MAX_LINE_LENGTH = 500;

	/**
	 * Field names wp-admin itself posts. A pattern mentioning any of these matches
	 * administrative traffic rather than a public form — including, for `_wpnonce`
	 * and `option_page`, the save of this plugin's own settings page, which is the
	 * one door the admin would need in order to undo the damage.
	 *
	 * @var string[]
	 */
	const ADMIN_FIELD_KEYS = array(
		'_wpnonce',
		'_wp_http_referer',
		'_wp_original_http_referer',
		'option_page',
		'action',
		'screen-options-apply',
		'wp_screen_options',
		'save',
		'submit',
		'post_ID',
		'post_type',
		'user_id',
	);

	/**
	 * Field names so common that a pattern built only from them matches almost any
	 * form on the site, backend forms included. A real form-builder signature always
	 * carries at least one product-specific key (`_wpcf7`, `input_values`,
	 * `forminator_nonce`, `frm_action`, …), so requiring one specific key costs
	 * legitimate entries nothing.
	 *
	 * @var string[]
	 */
	const GENERIC_FIELD_KEYS = array(
		'email',
		'e-mail',
		'mail',
		'name',
		'first_name',
		'last_name',
		'fname',
		'lname',
		'subject',
		'message',
		'comment',
		'text',
		'url',
		'website',
		'phone',
		'tel',
		'address',
		'company',
		'user_email',
		'your-name',
		'your-email',
	);

	/**
	 * admin-ajax actions wp-admin drives itself with. The ajax branch of the
	 * constructor triage recognises requests EXCLUSIVELY through the action list
	 * (handbuch/gate.md), and wp-admin carries no proof-of-work script, so any of
	 * these in the scope means the corresponding admin feature stops working with no
	 * way to recover from inside wp-admin.
	 *
	 * @var string[]
	 */
	const ADMIN_AJAX_ACTIONS = array(
		'heartbeat',
		'inline-save',
		'inline-save-tax',
		'save-widget',
		'widgets-order',
		'customize_save',
		'closed-postboxes',
		'meta-box-order',
		'hidden-columns',
		'update-plugin',
		'update-theme',
		'install-plugin',
		'search-install-plugins',
		'health-check-site-status-result',
		'wp-remove-post-lock',
		'wp-refresh-post-lock',
		'sample-permalink',
		'add-menu-item',
		'menu-quick-search',
		'query-attachments',
		'upload-attachment',
		'get-post-thumbnail-html',
		'send-attachment-to-editor',
		'get_stamp',
		'check_stamp',
	);

	/**
	 * Plan an addition without touching anything.
	 *
	 * @param string        $domain  One of the DOMAIN_* constants.
	 * @param array<int,mixed> $entries Raw entries as supplied by the caller. Typed
	 *                                  loosely on purpose: these arrive from an
	 *                                  ability input, so a caller that ignores the
	 *                                  schema must be rejected, not fatal.
	 * @param string[]      $current Entries already in the scope option, parsed to lines.
	 * @return array{accepted:string[],rejected:array<int,array{entry:string,reason:string}>}
	 */
	public static function plan( $domain, array $entries, array $current ) {
		$accepted = array();
		$rejected = array();

		$known = array();
		foreach ( $current as $line ) {
			$known[ self::dedup_key( $domain, (string) $line ) ] = true;
		}
		$total = count( $current );

		foreach ( $entries as $raw ) {
			$entry = is_string( $raw ) ? trim( $raw ) : '';

			if ( '' === $entry ) {
				$rejected[] = self::rejection( (string) ( is_string( $raw ) ? $raw : '' ), 'empty' );
				continue;
			}
			if ( strlen( $entry ) > self::MAX_LINE_LENGTH ) {
				$rejected[] = self::rejection( $entry, 'too_long' );
				continue;
			}
			if ( count( $accepted ) >= self::MAX_PER_CALL ) {
				$rejected[] = self::rejection( $entry, 'per_call_limit' );
				continue;
			}
			if ( $total >= self::MAX_TOTAL_LINES ) {
				$rejected[] = self::rejection( $entry, 'scope_full' );
				continue;
			}

			$key = self::dedup_key( $domain, $entry );
			if ( isset( $known[ $key ] ) ) {
				$rejected[] = self::rejection( $entry, 'already_monitored' );
				continue;
			}

			$reason = self::reject_reason( $domain, $entry );
			if ( null !== $reason ) {
				$rejected[] = self::rejection( $entry, $reason );
				continue;
			}

			$accepted[]    = $entry;
			$known[ $key ] = true;
			++$total;
		}

		return array(
			'accepted' => $accepted,
			'rejected' => $rejected,
		);
	}

	/**
	 * Why this entry may not be added, or null if it may.
	 *
	 * @param string $domain One of the DOMAIN_* constants.
	 * @param string $entry  Trimmed, length-checked entry.
	 * @return string|null Rejection reason code.
	 */
	private static function reject_reason( $domain, $entry ) {
		if ( self::DOMAIN_ROUTES === $domain ) {
			list( , $locked_out ) = RestRoute::reject_self_lockout_lines( $entry );
			return empty( $locked_out ) ? null : 'would_lock_out_admin';
		}

		if ( self::DOMAIN_ACTIONS === $domain ) {
			if ( ! preg_match( '/^[A-Za-z0-9_-]+$/', $entry ) ) {
				return 'not_an_action_name';
			}
			return in_array( strtolower( $entry ), self::ADMIN_AJAX_ACTIONS, true )
				? 'would_lock_out_admin'
				: null;
		}

		if ( self::DOMAIN_PATTERNS === $domain ) {
			return self::reject_pattern_reason( $entry );
		}

		return 'unknown_domain';
	}

	/**
	 * Pattern-specific rules.
	 *
	 * Three separate refusals, in order of how badly they end:
	 *
	 * 1. A `*` key is the FIELD-NAME WILDCARD: `{"*":"value"}` matches on the value
	 *    regardless of which field carries it, at any depth, on any form. That is a
	 *    legitimate monitoring pattern for an admin who knows their site, but it is far
	 *    too broad for an agent-driven scope addition — it would put nearly every form
	 *    on the site under evaluation from one line. Same family of refusal as
	 *    `too_generic` below; it keeps its own reason code because reason codes are
	 *    stable identifiers in the agent's answer, and renaming one is itself an API
	 *    change. Blocking a VALUE is a different setting entirely (POW_BLOCKED_VALUES)
	 *    and has no agent path at all.
	 * 2. A pattern naming a wp-admin field matches administrative traffic.
	 * 3. A pattern built only from generic field names matches nearly every form,
	 *    which is the documented cost case, just not self-inflicted this time.
	 *
	 * @param string $entry Trimmed pattern line.
	 * @return string|null Rejection reason code.
	 */
	private static function reject_pattern_reason( $entry ) {
		$decoded = json_decode( $entry, true );
		if ( ! is_array( $decoded ) || array() === $decoded ) {
			return 'not_a_json_object';
		}
		// A JSON array decodes to a list; a pattern must be an object of field names.
		if ( array_keys( $decoded ) === range( 0, count( $decoded ) - 1 ) ) {
			return 'not_a_json_object';
		}

		$keys = array();
		foreach ( array_keys( $decoded ) as $key ) {
			$keys[] = strtolower( trim( (string) $key ) );
		}

		if ( in_array( '*', $keys, true ) ) {
			return 'wildcard_value_pattern';
		}

		foreach ( $keys as $key ) {
			if ( in_array( $key, self::ADMIN_FIELD_KEYS, true ) ) {
				return 'matches_admin_fields';
			}
		}

		foreach ( $keys as $key ) {
			if ( ! in_array( $key, self::GENERIC_FIELD_KEYS, true ) ) {
				// At least one product-specific key — this is a real signature.
				return null;
			}
		}

		return 'too_generic';
	}

	/**
	 * Comparison key for de-duplication. Routes match case-insensitively
	 * (RestRoute::matches()), so they de-duplicate that way too; the other two are
	 * compared verbatim after trimming, exactly as their read paths compare them.
	 *
	 * @param string $domain One of the DOMAIN_* constants.
	 * @param string $line   Raw line.
	 * @return string
	 */
	private static function dedup_key( $domain, $line ) {
		$line = trim( $line );
		return self::DOMAIN_ROUTES === $domain ? strtolower( $line ) : $line;
	}

	/**
	 * @param string $entry  The rejected entry.
	 * @param string $reason Reason code.
	 * @return array{entry:string,reason:string}
	 */
	private static function rejection( $entry, $reason ) {
		return array(
			'entry'  => $entry,
			'reason' => $reason,
		);
	}

	/**
	 * Human-readable text for a reason code, for the report an agent gets back.
	 *
	 * @param string $reason Reason code from plan().
	 * @return string
	 */
	public static function explain( $reason ) {
		$map = array(
			'empty'                  => __( 'Empty entry.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'too_long'               => __( 'Entry is too long.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'per_call_limit'         => __( 'Too many entries in one call; add them in smaller batches.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'scope_full'             => __( 'This part of the monitored scope is already at its maximum size.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'already_monitored'      => __( 'Already monitored.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'would_lock_out_admin'   => __( 'Refused: this would make the plugin evaluate WordPress\' own administration traffic, which would lock the administrator out of wp-admin.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'not_an_action_name'     => __( 'Not a valid admin-ajax action name.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'not_a_json_object'      => __( 'A recognition pattern must be a JSON object of field names.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'wildcard_value_pattern' => __( 'Refused: a "*" wildcard matches on a value regardless of field name and would monitor almost every form. Name the form\'s own fields instead. Blocking a value is a site-owner decision and has no agent path.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'matches_admin_fields'   => __( 'Refused: this pattern names fields that WordPress\' own admin screens post.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'too_generic'            => __( 'Refused: this pattern is built only from generic field names and would match almost every form on the site. Include at least one field name specific to the form builder.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'unknown_domain'         => __( 'Unknown scope domain.', 'gdpr-compliant-recaptcha-for-all-forms' ),
		);

		return isset( $map[ $reason ] ) ? $map[ $reason ] : $reason;
	}

	/**
	 * The scope option behind a domain key.
	 *
	 * Deliberately its own mapping rather than a reach into Scope_Sync::domains():
	 * that one is private, and it carries a third element (the defaults callable)
	 * this path has no business with — Scope_Add extends the LIVE scope, never the
	 * shipped defaults.
	 *
	 * @param string $domain One of the DOMAIN_* constants.
	 * @return string|null Option name.
	 */
	public static function option_for( $domain ) {
		$map = array(
			self::DOMAIN_ACTIONS  => Option::POW_EXPLICIT_ACTION,
			self::DOMAIN_PATTERNS => Option::POW_PARAMETER_PATTERN,
			self::DOMAIN_ROUTES   => Option::POW_REST_ROUTES,
		);

		return isset( $map[ $domain ] ) ? $map[ $domain ] : null;
	}

	/**
	 * Apply a plan. The only method here that touches the database.
	 *
	 * @param string   $domain   One of the DOMAIN_* constants.
	 * @param string[] $accepted Entries from plan()['accepted'].
	 * @return int New total number of lines in the domain, or -1 on an unknown domain.
	 */
	public static function apply( $domain, array $accepted ) {
		$option = self::option_for( $domain );
		if ( null === $option ) {
			return -1;
		}

		$current = Scope_Sync::parse_lines( get_option( $option, '' ) );
		if ( empty( $accepted ) ) {
			return count( $current );
		}

		$merged = array_merge( $current, $accepted );
		update_option( $option, implode( "\n", $merged ) );

		return count( $merged );
	}

	/**
	 * Append to the persistent audit trail.
	 *
	 * Persistent on purpose. Scope_Sync's notice transient lives for a minute, which
	 * is fine for something that happens inside the admin's own request — but an
	 * agent writes precisely when nobody is at the screen, and "the scope changed and
	 * no one ever saw it" is most of the damage for a security plugin.
	 *
	 * @param string   $ability Ability id that made the change.
	 * @param string   $domain  One of the DOMAIN_* constants.
	 * @param string[] $added   Entries actually added.
	 * @return void
	 */
	public static function record( $ability, $domain, array $added ) {
		if ( empty( $added ) ) {
			return;
		}

		$log = get_option( Option::POW_ABILITIES_LOG, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		$log[] = array(
			'at'      => time(),
			'ability' => (string) $ability,
			'domain'  => (string) $domain,
			'user'    => get_current_user_id(),
			'added'   => array_values( $added ),
		);

		// Keep the tail: the newest entries are the ones an admin needs to react to,
		// and this option must never grow without a bound.
		if ( count( $log ) > 100 ) {
			$log = array_slice( $log, -100 );
		}

		update_option( Option::POW_ABILITIES_LOG, $log, false );
	}
}
