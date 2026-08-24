<?php
/**
 * What this plugin's abilities DO — the execute callbacks behind the catalogue in
 * class-abilities.php.
 *
 * SCHNITTLINIE (Welle 4, PLAN-DATEIGROESSE.md): the seam, why it is a trait and what
 * deliberately stayed behind are documented once, at the `use Ability_Actions;` statement
 * in class-abilities.php. Read that first.
 *
 * The properties this half has to keep, unchanged by the move:
 * - NOTHING HERE PERSISTS OR COUNTS on the read-only stage. classify-text scores supplied
 *   text and returns; it never increments the wave counter, never seeds the echo store and
 *   never saves a message, because repeated "just checking" calls must not move the live
 *   spam decision for real visitors.
 * - NOTHING HERE TOUCHES $wpdb. Stage 3's database access lives in Agent_Access, so this
 *   file stays callbacks and the guards stay in one place.
 * - NOTHING HERE REACHES INTO PROOF-OF-WORK VERIFICATION. The self-test hands off to
 *   Ability_Probe, which drives the real handshake over HTTP; a diagnostic shortcut
 *   through check_stamp() would be a bypass with a friendly name.
 * - THE STAGE-2 DOMAIN IS BOUND AT REGISTRATION, never read from the input — scope_callback()
 *   closes over it, so an ability cannot be aimed at a scope option it was not registered
 *   for.
 *
 * PHP 7.1 floor applies here exactly as in class-abilities.php: no arrow functions, no
 * typed properties. The bootstrap requires both files unconditionally, so a parse error
 * takes the whole site down.
 *
 * Area doc: handbuch/abilities.md.
 *
 * @package VENDOR\RECAPTCHA_GDPR_COMPLIANT
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/abilities.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse (Traits
// bekommen keine eigene Indexzeile; sie sind Teil ihrer Klasse).

/**
 * The execute callbacks of the abilities surface. Composed into Abilities.
 */
trait Ability_Actions {

	/**
	 * Build the execute callback for one scope domain.
	 *
	 * @param string $domain  One of the Scope_Add::DOMAIN_* constants.
	 * @param string $ability Full ability id, for the audit trail.
	 * @return callable
	 */
	private function scope_callback( $domain, $ability ) {
		$self = $this;

		return function ( $input ) use ( $self, $domain, $ability ) {
			return $self->add_to_scope( $domain, $ability, $input );
		};
	}

	/**
	 * Stage 3: one page of submission summaries.
	 *
	 * @param array<string,mixed> $input Ability input.
	 * @return array<string,mixed>
	 */
	public function list_submissions( $input = array() ) {
		$folder = isset( $input['folder'] ) && is_string( $input['folder'] ) ? $input['folder'] : '';
		if ( ! isset( Agent_Access::list_folders()[ $folder ] ) ) {
			return array(
				'ok'      => false,
				'reason'  => 'unknown_folder',
				'message' => __( 'Unknown folder. Readable folders are the inbox and the spam folder; the analysis folder is deliberately not readable, because analysis mode records every POST on the site, including admin screens of other plugins.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		$limit  = Agent_Access::clamp_limit( isset( $input['limit'] ) ? $input['limit'] : null );
		$offset = isset( $input['offset'] ) && is_numeric( $input['offset'] ) ? (int) $input['offset'] : 0;

		return array(
			'ok'          => true,
			'folder'      => $folder,
			'limit'       => $limit,
			'offset'      => max( 0, $offset ),
			'submissions' => Agent_Access::list_submissions( $folder, $limit, $offset ),
		);
	}

	/**
	 * Stage 3: the stored fields of one submission.
	 *
	 * @param array<string,mixed> $input Ability input.
	 * @return array<string,mixed>
	 */
	public function get_submission( $input = array() ) {
		$id = isset( $input['id'] ) && is_numeric( $input['id'] ) ? (int) $input['id'] : 0;

		$submission = $id > 0 ? Agent_Access::get_submission( $id ) : null;
		if ( null === $submission ) {
			return array(
				'ok'      => false,
				'reason'  => 'not_found',
				'message' => __( 'No readable submission with that id. Note that analysis-mode entries are not readable through this ability.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		return array(
			'ok'         => true,
			'submission' => $submission,
		);
	}

	/**
	 * Stage 3: delete one submission.
	 *
	 * @param array<string,mixed> $input Ability input.
	 * @return array<string,mixed>
	 */
	public function delete_submission( $input = array() ) {
		$id = isset( $input['id'] ) && is_numeric( $input['id'] ) ? (int) $input['id'] : 0;

		if ( $id <= 0 || ! Agent_Access::delete_submission( $id ) ) {
			return array(
				'ok'      => false,
				'reason'  => 'not_found',
				'message' => __( 'No deletable submission with that id.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		Agent_Access::record( self::ABILITY_NAMESPACE . '/delete-submission', 'delete', array( 'id' => $id ) );

		return array(
			'ok'      => true,
			'deleted' => $id,
		);
	}

	/**
	 * Stage 3: change one protection setting.
	 *
	 * @param array<string,mixed> $input Ability input.
	 * @return array<string,mixed>
	 */
	public function set_protection( $input = array() ) {
		$plan = Agent_Access::plan_protection_change(
			isset( $input['setting'] ) ? $input['setting'] : null,
			isset( $input['value'] ) ? $input['value'] : null
		);

		if ( ! $plan['ok'] ) {
			return array(
				'ok'      => false,
				'reason'  => $plan['reason'],
				'message' => Agent_Access::explain( $plan['reason'] ),
			);
		}

		// Read the old value BEFORE writing: the audit trail records old -> new, because
		// "was set" alone does not let an admin undo anything, and undoing is the first
		// thing they want when they find a change they did not make.
		$previous = get_option( $plan['setting'] );
		update_option( $plan['setting'], $plan['value'] );

		Agent_Access::record(
			self::ABILITY_NAMESPACE . '/set-protection',
			'set-protection',
			array(
				'setting' => $plan['setting'],
				'from'    => $previous,
				'to'      => $plan['value'],
			)
		);

		return array(
			'ok'      => true,
			'setting' => $plan['setting'],
			'from'    => $previous,
			'to'      => $plan['value'],
		);
	}

	/**
	 * @param array<string,mixed> $input Ability input (unused).
	 * @return array<string,mixed>
	 */
	public function run_self_test( $input = array() ) {
		unset( $input );

		return Ability_Probe::run();
	}

	/**
	 * The live monitored scope, and optionally a coverage answer.
	 *
	 * Blocked values are counted but never listed. They carry values an admin blocked by
	 * hand — real senders' email addresses and domains (handbuch/detection.md). That is
	 * personal data about third parties, and an MCP client is typically an external
	 * service, so listing them would quietly turn a "what do you monitor" question into a
	 * data transfer.
	 *
	 * The count is the line count of POW_BLOCKED_VALUES, the option the blocklist lives in
	 * since PLAN-BLOCKLIST-TRENNUNG.md. It used to be derived by filtering `{"*":…}` rows
	 * out of the pattern option, which is why `patterns` needed a filter at all; now the
	 * pattern option holds nothing but monitoring patterns and every line of it is
	 * listable.
	 *
	 * @param array<string,mixed> $input Ability input.
	 * @return array<string,mixed>
	 */
	public function read_scope( $input = array() ) {
		$actions  = Scope_Sync::parse_lines( get_option( Option::POW_EXPLICIT_ACTION, '' ) );
		$patterns = Scope_Sync::parse_lines( get_option( Option::POW_PARAMETER_PATTERN, '' ) );
		$routes   = Scope_Sync::parse_lines( get_option( Option::POW_REST_ROUTES, '' ) );
		$blocked  = Scope_Sync::parse_lines( get_option( Option::POW_BLOCKED_VALUES, '' ) );

		$result = array(
			'actions'                  => $actions,
			'patterns'                 => $patterns,
			'routes'                   => $routes,
			'blocked_values_count'     => count( $blocked ),
			'blocked_values_withheld'  => __( 'Blocked sender values are counted but not listed: they are third parties\' email addresses and domains.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'how_requests_are_matched' => __( 'admin-ajax requests are matched by action name only. Classic form posts and REST requests are matched by field pattern or by REST route.', 'gdpr-compliant-recaptcha-for-all-forms' ),
		);

		$action = isset( $input['action'] ) && is_string( $input['action'] ) ? trim( $input['action'] ) : '';
		if ( '' !== $action ) {
			$result['action_covered'] = in_array( $action, $actions, true );
		}

		$route = isset( $input['route'] ) && is_string( $input['route'] ) ? trim( $input['route'] ) : '';
		if ( '' !== $route ) {
			$result['route_covered'] = RestRoute::matches( $route, implode( "\n", $routes ) );
		}

		return $result;
	}

	/**
	 * Score supplied field values with the plugin's content rules.
	 *
	 * Two honest limits, both stated in the result rather than buried here:
	 *
	 * 1. The live decision starts with proof-of-work (check_request()). Supplied text
	 *    has no token and no solved puzzle, so that stage cannot be evaluated at all.
	 *    A submission this call calls clean can still be spam live, for the most
	 *    common reason of all.
	 * 2. Under-attack quarantine turns otherwise-clean submissions into spam while a
	 *    wave is running. Whether that applies is reported separately instead of
	 *    being folded into the verdict, because it depends on the moment, not the
	 *    text.
	 *
	 * Side effects are deliberately absent: no counter is incremented, nothing is
	 * recorded in the echo store, nothing is saved. (Echo_Store::matches() may warm a
	 * transient cache of registered users' email hashes on a miss — a cache fill, not
	 * a record of this call.) Supplied values are never echoed back; only verdicts and
	 * counts are returned.
	 *
	 * @param array<string,mixed> $input Ability input.
	 * @return array<string,mixed>
	 */
	public function classify_text( $input = array() ) {
		$fields = isset( $input['fields'] ) && is_array( $input['fields'] ) ? $input['fields'] : array();

		if ( empty( $fields ) ) {
			return array(
				'error' => __( 'No fields supplied.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}
		if ( count( $fields ) > self::MAX_CLASSIFY_FIELDS ) {
			return array(
				'error' => __( 'Too many fields supplied.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		$total = 0;
		foreach ( $fields as $value ) {
			$total += strlen( is_scalar( $value ) ? (string) $value : wp_json_encode( $value ) );
		}
		if ( $total > self::MAX_CLASSIFY_CHARS ) {
			return array(
				'error' => __( 'Supplied fields are too large.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		// Scores exactly the fields the caller supplied. Since 6.0.0 that IS the live
		// semantics rather than a deviation from it: the live path scores the fields the
		// operator selected and nothing else, and an agent handing a field map here is
		// making the same explicit choice. There is no exemption list on either side any
		// more — see Gibberish_Fields.
		$analysis = Gibberish_Detector::analyze_message( $fields );

		$echo_hit     = Echo_Store::matches( $fields );
		$wildcard_hit = $this->wildcard_hit( $fields );
		$is_spam      = $echo_hit || $wildcard_hit || $analysis['gibberish'];

		$reason = null;
		if ( $echo_hit ) {
			$reason = Classification_Reason::CODE_ECHO_LOCK;
		} elseif ( $wildcard_hit ) {
			$reason = Classification_Reason::CODE_WILDCARD;
		} elseif ( $analysis['gibberish'] ) {
			$reason = Classification_Reason::gibberish(
				$analysis['letters'],
				$analysis['alnum'],
				$analysis['solo'],
				$analysis['strong']
			);
		}

		$under_attack = Stamp::is_under_attack();

		return array(
			'verdict'                 => $is_spam ? 'spam' : 'clean',
			'reason'                  => $reason,
			'signals'                 => array(
				'echo_lock'        => $echo_hit,
				'blocked_value'    => $wildcard_hit,
				'gibberish'        => $analysis['gibberish'],
				'gibberish_tokens' => $analysis['letters'],
			),
			'proof_of_work_evaluated' => false,
			'under_attack'            => $under_attack,
			'quarantine_would_apply'  => $under_attack
				&& ! $is_spam
				&& (bool) get_option( Option::POW_UNDER_ATTACK_QUARANTINE ),
			'limits'                  => array(
				__( 'The proof-of-work stage was not evaluated: supplied text carries no solved puzzle. Live, that stage runs first and is by far the most common reason a submission is treated as spam.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Every supplied field was scored for gibberish. Live, only fields the site owner selected for that form are scored, and sites that selected none are never scored at all.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Nothing was stored, counted or remembered by this call.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
		);
	}

	/**
	 * Stage 2 execute callback.
	 *
	 * @param string              $domain  One of the Scope_Add::DOMAIN_* constants.
	 * @param string              $ability Full ability id.
	 * @param array<string,mixed> $input   Ability input.
	 * @return array<string,mixed>
	 */
	public function add_to_scope( $domain, $ability, $input = array() ) {
		$entries = isset( $input['entries'] ) && is_array( $input['entries'] ) ? $input['entries'] : array();
		if ( empty( $entries ) ) {
			return array( 'error' => __( 'No entries supplied.', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		$option = Scope_Add::option_for( $domain );
		if ( null === $option ) {
			return array( 'error' => __( 'Unknown scope domain.', 'gdpr-compliant-recaptcha-for-all-forms' ) );
		}

		$current = Scope_Sync::parse_lines( get_option( $option, '' ) );
		$plan    = Scope_Add::plan( $domain, $entries, $current );

		$total = Scope_Add::apply( $domain, $plan['accepted'] );
		Scope_Add::record( $ability, $domain, $plan['accepted'] );

		$rejected = array();
		foreach ( $plan['rejected'] as $item ) {
			$rejected[] = array(
				'entry'       => $item['entry'],
				'reason'      => $item['reason'],
				'explanation' => Scope_Add::explain( $item['reason'] ),
			);
		}

		return array(
			'added'           => $plan['accepted'],
			'rejected'        => $rejected,
			'total_monitored' => $total,
			'note'            => __( 'Entries are only ever added, never removed. Review them under Recognition on the plugin\'s settings screen.', 'gdpr-compliant-recaptcha-for-all-forms' ),
		);
	}
}
