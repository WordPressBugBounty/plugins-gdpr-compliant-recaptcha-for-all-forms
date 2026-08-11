<?php
/**
 * WordPress Abilities API surface — what an AI agent may ask this plugin to do.
 *
 * Area doc: handbuch/abilities.md.
 *
 * @package VENDOR\RECAPTCHA_GDPR_COMPLIANT
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

/**
 * Registers this plugin's abilities (core Abilities API, WordPress 6.9+) and its
 * connector card (Connectors API, WordPress 7.0+).
 *
 * The Abilities API is core's registry of callable plugin capabilities. The separate
 * WordPress/mcp-adapter plugin republishes every ability carrying
 * `meta.mcp.public` as an MCP tool, so an AI agent can call it. We do not implement
 * MCP; we describe what we can do and let the operator decide whether anything is
 * listening.
 *
 * Everything on this surface is guarded by function_exists()/class_exists(), so the
 * plugin's declared floor (WordPress 4.8, PHP 7.1) is untouched. Note the PHP floor
 * in particular: no arrow functions, no typed properties, no spread in constant
 * expressions anywhere in this file.
 *
 * ## The three stages, and why they are not one switch
 *
 * Stage 1 (self-test, health, scope, classify-text) is registered unconditionally.
 * It reads, it computes, it changes nothing. Every callback requires
 * `manage_options`, which is the same bar as seeing those numbers in the settings
 * screen, and registering an ability opens no port on its own.
 *
 * Stage 2 (extending the monitored scope) writes into the security boundary. It is
 * NOT registered at all unless POW_ABILITIES_WRITE is on — deliberately not merely
 * flag-hidden, because an ability that exists is an ability some other code path may
 * reach. Its guards live in Scope_Add, which assumes a hostile caller.
 *
 * Stage 3 (reading stored submissions, changing protection settings) has its switch
 * and its warnings here, but no catalogue yet. The switch ships first on purpose:
 * the operator decision it represents is the hard part, and it is the same decision
 * whether the catalogue has one entry or ten.
 *
 * ## What this class must never become
 *
 * No ability touches proof-of-work verification. The self-test drives the real
 * handshake over HTTP and reads the outcome; there is no test flag inside
 * Stamp::check_stamp(), no privileged path, no relaxed branch. A diagnostic that
 * verifies differently from production verifies nothing, and a bypass built for
 * diagnostics is still a bypass. tests/unit/AbilityRegistrationTest.php pins this.
 */
final class Abilities {

	/** Ability id namespace. Stable once published — agents and docs refer to it. */
	const ABILITY_NAMESPACE = 'gdpr-recaptcha';

	/** Connector id on the WordPress 7.0 Connectors screen. */
	const CONNECTOR_ID = 'gdpr-invisible-anti-spam';

	/** Most fields classify-text will look at in one call. */
	const MAX_CLASSIFY_FIELDS = 50;

	/** Most characters classify-text will look at in one call, across all fields. */
	const MAX_CLASSIFY_CHARS = 20000;

	/**
	 * Hook registration. Nothing here assumes the APIs exist.
	 */
	public function __construct() {
		add_action( 'wp_abilities_api_categories_init', array( $this, 'register_categories' ) );
		add_action( 'wp_abilities_api_init', array( $this, 'register_abilities' ) );
		add_action( 'wp_connectors_init', array( $this, 'register_connector' ) );
		add_action( 'admin_notices', array( $this, 'render_unsafe_notice' ) );
	}

	/**
	 * Whether stage 2 (scope writes) is switched on.
	 *
	 * @return bool
	 */
	public static function write_enabled() {
		return (bool) get_option( Option::POW_ABILITIES_WRITE );
	}

	/**
	 * Whether stage 3 (submissions, protection settings) is switched on.
	 *
	 * @return bool
	 */
	public static function unsafe_enabled() {
		return (bool) get_option( Option::POW_ABILITIES_UNSAFE );
	}

	/**
	 * Category registration. Fires before ability registration.
	 *
	 * @return void
	 */
	public function register_categories() {
		if ( ! function_exists( 'wp_register_ability_category' ) ) {
			return;
		}

		wp_register_ability_category(
			self::ABILITY_NAMESPACE,
			array(
				'label'       => __( 'Invisible Anti-Spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'description' => __( 'Diagnose and configure the invisible proof-of-work spam protection.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			)
		);
	}

	/**
	 * Ability registration.
	 *
	 * @return void
	 */
	public function register_abilities() {
		if ( ! function_exists( 'wp_register_ability' ) ) {
			return;
		}

		$this->register_stage_one();

		if ( self::write_enabled() ) {
			$this->register_stage_two();
		}
	}

	/**
	 * Read-only diagnostics. Always registered.
	 *
	 * @return void
	 */
	private function register_stage_one() {
		wp_register_ability(
			self::ABILITY_NAMESPACE . '/self-test',
			array(
				'label'               => __( 'Test the spam protection', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'description'         => __( 'Runs the real proof-of-work handshake against this site and reports in plain language whether it works, and if not, what is wrong. This is the first thing to run when submissions are wrongly treated as spam.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'category'            => self::ABILITY_NAMESPACE,
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(),
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'verdict' => array( 'type' => 'string' ),
						'code'    => array( 'type' => 'string' ),
						'message' => array( 'type' => 'string' ),
						'details' => array( 'type' => 'object' ),
					),
				),
				'execute_callback'    => array( $this, 'run_self_test' ),
				'permission_callback' => array( $this, 'can_read' ),
				'meta'                => array( 'mcp' => array( 'public' => true ) ),
			)
		);

		wp_register_ability(
			self::ABILITY_NAMESPACE . '/health',
			array(
				'label'               => __( 'Read spam protection health figures', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'description'         => __( 'Returns the counters this plugin keeps: spam caught, submissions that arrived without a solved puzzle, current puzzle difficulty, whether a spam wave is in progress. Numbers only — no submission content.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'category'            => self::ABILITY_NAMESPACE,
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'execute_callback'    => array( $this, 'read_health' ),
				'permission_callback' => array( $this, 'can_read' ),
				'meta'                => array( 'mcp' => array( 'public' => true ) ),
			)
		);

		wp_register_ability(
			self::ABILITY_NAMESPACE . '/scope',
			array(
				'label'               => __( 'Read what is being monitored', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'description'         => __( 'Lists the form actions, field patterns and REST routes this plugin evaluates, and answers whether a given action or route is covered. Use it to find out why a particular form is not protected.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'category'            => self::ABILITY_NAMESPACE,
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'action' => array(
							'type'        => 'string',
							'description' => __( 'An admin-ajax action name to check for coverage.', 'gdpr-compliant-recaptcha-for-all-forms' ),
						),
						'route'  => array(
							'type'        => 'string',
							'description' => __( 'A REST route to check for coverage, e.g. "my-plugin/v1/submit".', 'gdpr-compliant-recaptcha-for-all-forms' ),
						),
					),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'execute_callback'    => array( $this, 'read_scope' ),
				'permission_callback' => array( $this, 'can_read' ),
				'meta'                => array( 'mcp' => array( 'public' => true ) ),
			)
		);

		wp_register_ability(
			self::ABILITY_NAMESPACE . '/classify-text',
			array(
				'label'               => __( 'Check supplied text for spam signals', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'description'         => __( 'Scores field values you supply against this plugin\'s content rules and returns the verdict it would reach, without storing anything. Everything runs on this site; nothing is sent anywhere.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'category'            => self::ABILITY_NAMESPACE,
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'fields' => array(
							'type'        => 'object',
							'description' => __( 'Field name to value map, as a form would post it.', 'gdpr-compliant-recaptcha-for-all-forms' ),
						),
					),
					'required'   => array( 'fields' ),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'execute_callback'    => array( $this, 'classify_text' ),
				'permission_callback' => array( $this, 'can_read' ),
				'meta'                => array( 'mcp' => array( 'public' => true ) ),
			)
		);
	}

	/**
	 * Scope writes. Registered only while POW_ABILITIES_WRITE is on.
	 *
	 * @return void
	 */
	private function register_stage_two() {
		$domains = array(
			Scope_Add::DOMAIN_ACTIONS  => array(
				'id'    => 'add-monitored-action',
				'label' => __( 'Monitor an additional form action', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'desc'  => __( 'Adds an admin-ajax action name to the monitored scope, so submissions sent through it are checked for a solved puzzle. Only ever adds; entries that would make the plugin evaluate WordPress\' own admin traffic are refused.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
			Scope_Add::DOMAIN_PATTERNS => array(
				'id'    => 'add-recognition-pattern',
				'label' => __( 'Monitor an additional form field pattern', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'desc'  => __( 'Adds a JSON field-shape pattern to the monitored scope. Only ever adds; patterns that would match admin screens, that are built only from generic field names, or that classify rather than monitor are refused.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
			Scope_Add::DOMAIN_ROUTES   => array(
				'id'    => 'add-rest-route',
				'label' => __( 'Monitor an additional REST route', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'desc'  => __( 'Adds a REST route to the monitored scope. Only ever adds; routes overlapping WordPress core namespaces or the channel an agent itself arrives through are refused.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
		);

		foreach ( $domains as $domain => $meta ) {
			wp_register_ability(
				self::ABILITY_NAMESPACE . '/' . $meta['id'],
				array(
					'label'               => $meta['label'],
					'description'         => $meta['desc'],
					'category'            => self::ABILITY_NAMESPACE,
					'input_schema'        => array(
						'type'       => 'object',
						'properties' => array(
							'entries' => array(
								'type'        => 'array',
								'items'       => array( 'type' => 'string' ),
								'description' => __( 'Entries to add, one per array item.', 'gdpr-compliant-recaptcha-for-all-forms' ),
							),
						),
						'required'   => array( 'entries' ),
					),
					'output_schema'       => array( 'type' => 'object' ),
					// The domain is bound here rather than read from the input, so a
					// caller cannot aim an ability at a scope option it was not
					// registered for.
					'execute_callback'    => $this->scope_callback( $domain, self::ABILITY_NAMESPACE . '/' . $meta['id'] ),
					'permission_callback' => array( $this, 'can_write_scope' ),
					'meta'                => array( 'mcp' => array( 'public' => true ) ),
				)
			);
		}
	}

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

	/* ---------------------------------------------------------------------
	 * Permission callbacks
	 * ------------------------------------------------------------------ */

	/**
	 * Stage 1. MCP clients act as logged-in WordPress users, so this really is the
	 * whole guard — there is no second gate behind it.
	 *
	 * @return bool
	 */
	public function can_read() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Stage 2. Re-checks the option even though a disabled stage 2 is never
	 * registered: registration happens once per request and could in principle be
	 * reached from a cached or otherwise unexpected context, and an option read is
	 * far cheaper than the consequences of being wrong here.
	 *
	 * @return bool
	 */
	public function can_write_scope() {
		return current_user_can( 'manage_options' ) && self::write_enabled();
	}

	/* ---------------------------------------------------------------------
	 * Execute callbacks
	 * ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed> $input Ability input (unused).
	 * @return array<string,mixed>
	 */
	public function run_self_test( $input = array() ) {
		unset( $input );

		return Ability_Probe::run();
	}

	/**
	 * Health figures.
	 *
	 * Reports the state of POW_SAVE_SPAM alongside the no-stamp counter on purpose.
	 * That counter reads _gdpr_reason rows, which only exist when save_message() ran,
	 * and saving spam is itself optional (HANDBUCH.md §12, "blind spot"). With spam
	 * saving off the counter sits at 0 no matter how much unprotected traffic there
	 * is — a reader who does not know that reads 0 as healthy.
	 *
	 * @param array<string,mixed> $input Ability input (unused).
	 * @return array<string,mixed>
	 */
	public function read_health( $input = array() ) {
		unset( $input );

		$save_spam    = (bool) get_option( Option::POW_SAVE_SPAM );
		$no_pow_count = Option::count_no_pow_reasons_since_hours( Option::HEALTH_NO_POW_WINDOW_HOURS );
		$matched      = (int) get_option( Option::POW_FP_MATCHED_TOTAL, 0 );
		$mismatched   = (int) get_option( Option::POW_FP_MISMATCHED_TOTAL, 0 );
		$share        = Option::fp_mismatch_share( $matched, $mismatched );
		$under_attack = Stamp::is_under_attack();

		return array(
			'difficulty'             => array(
				'base'      => (int) get_option( Option::POW_DIFFICULTY ),
				'effective' => ProofOfWork::effective_difficulty(
					(int) get_option( Option::POW_DIFFICULTY ),
					$under_attack && (bool) get_option( Option::POW_UNDER_ATTACK_MODE ),
					Stamp::UNDER_ATTACK_BONUS
				),
			),
			'under_attack'           => $under_attack,
			'spam_last_7_days'       => Option::count_messages_since_days( 2, 7 ),
			'inbox_last_7_days'      => Option::count_messages_since_days( 1, 7 ),
			'no_stamp_row_24h'       => $no_pow_count,
			'no_stamp_row_threshold' => Option::HEALTH_NO_POW_WARN_THRESHOLD,
			'echo_lock_entries'      => Echo_Store::count(),
			'address_change'         => array(
				'matched'    => $matched,
				'mismatched' => $mismatched,
				'percent'    => $share['percent'],
			),
			'settings'               => array(
				'blocking'        => (bool) get_option( Option::POW_BLOCK ),
				'save_spam'       => $save_spam,
				'simulation_mode' => (bool) get_option( Option::POW_SIMULATE_SPAM ),
			),
			'caveats'                => $this->health_caveats( $save_spam ),
		);
	}

	/**
	 * Things a reader must know before drawing a conclusion from the figures.
	 *
	 * @param bool $save_spam Whether spam messages are being stored.
	 * @return string[]
	 */
	private function health_caveats( $save_spam ) {
		$caveats = array();

		if ( ! $save_spam ) {
			$caveats[] = __( 'Storing spam is switched off, so "no_stamp_row_24h" is always 0 and says nothing about the real amount of unprotected traffic. Do not read 0 as healthy here.', 'gdpr-compliant-recaptcha-for-all-forms' );
		}
		if ( (bool) get_option( Option::POW_SIMULATE_SPAM ) ) {
			$caveats[] = __( 'Simulation mode is on: every submission is being treated as spam, which inflates the spam figures.', 'gdpr-compliant-recaptcha-for-all-forms' );
		}
		$caveats[] = __( 'The address-change percentage counts every solved puzzle, including the ones this plugin\'s own self-test solves. Repeated self-tests dilute it.', 'gdpr-compliant-recaptcha-for-all-forms' );

		return $caveats;
	}

	/**
	 * The live monitored scope, and optionally a coverage answer.
	 *
	 * Wildcard value rows are counted but never listed. They carry values an admin
	 * blocked by hand — real senders' email addresses and domains (handbuch/gate.md).
	 * That is personal data about third parties, and an MCP client is typically an
	 * external service, so listing them would quietly turn a "what do you monitor"
	 * question into a data transfer.
	 *
	 * @param array<string,mixed> $input Ability input.
	 * @return array<string,mixed>
	 */
	public function read_scope( $input = array() ) {
		$actions  = Scope_Sync::parse_lines( get_option( Option::POW_EXPLICIT_ACTION, '' ) );
		$patterns = Scope_Sync::parse_lines( get_option( Option::POW_PARAMETER_PATTERN, '' ) );
		$routes   = Scope_Sync::parse_lines( get_option( Option::POW_REST_ROUTES, '' ) );

		$listable = array();
		$wildcard = 0;
		foreach ( $patterns as $line ) {
			$decoded = json_decode( $line, true );
			if ( is_array( $decoded ) && array_key_exists( '*', $decoded ) ) {
				++$wildcard;
				continue;
			}
			$listable[] = $line;
		}

		$result = array(
			'actions'                  => $actions,
			'patterns'                 => $listable,
			'routes'                   => $routes,
			'blocked_values_count'     => $wildcard,
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

		// Same exemption list the live path builds, from the same method — a
		// diagnostic that scores differently from production is worse than none.
		$exempt   = Stamp::gibberish_exempt_field_names( $fields );
		$analysis = Gibberish_Detector::analyze_message( $fields, $exempt );

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
				'echo_lock'          => $echo_hit,
				'blocked_value'      => $wildcard_hit,
				'gibberish'          => $analysis['gibberish'],
				'gibberish_tokens'   => $analysis['letters'],
				'exempt_field_count' => count( $exempt ),
			),
			'proof_of_work_evaluated' => false,
			'under_attack'            => $under_attack,
			'quarantine_would_apply'  => $under_attack
				&& ! $is_spam
				&& (bool) get_option( Option::POW_UNDER_ATTACK_QUARANTINE ),
			'limits'                  => array(
				__( 'The proof-of-work stage was not evaluated: supplied text carries no solved puzzle. Live, that stage runs first and is by far the most common reason a submission is treated as spam.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				__( 'Nothing was stored, counted or remembered by this call.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
		);
	}

	/**
	 * Whether any supplied value matches a blocked-value pattern.
	 *
	 * @param array<string,mixed> $fields Supplied fields.
	 * @return bool
	 */
	private function wildcard_hit( $fields ) {
		$option = (string) get_option( Option::POW_PARAMETER_PATTERN );
		if ( '' === trim( $option ) ) {
			return false;
		}

		$lines  = preg_split( '/\r\n|\n|\r/', $option, -1, PREG_SPLIT_NO_EMPTY );
		$values = Echo_Values::wildcard_values_from_lines( is_array( $lines ) ? $lines : array() );
		if ( empty( $values ) ) {
			return false;
		}

		return Echo_Values::matches_wildcard_values( $fields, $values, Echo_Store::site_domains() );
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

	/* ---------------------------------------------------------------------
	 * Connectors (WordPress 7.0+) and admin notice
	 * ------------------------------------------------------------------ */

	/**
	 * Register the connector card.
	 *
	 * Core's registry accepts `method => 'none'` explicitly, and core itself
	 * registers Akismet under `type => 'spam_filtering'` — so this is the category
	 * we belong in, not a gap in the validation. There is nothing to connect and
	 * nothing to maintain: no key, no account, no endpoint. The card says so, which
	 * is the point of appearing on a screen listing what this site talks to.
	 *
	 * @param mixed $registry Connector registry instance, passed by core.
	 * @return void
	 */
	public function register_connector( $registry ) {
		if ( ! is_object( $registry ) || ! method_exists( $registry, 'register' ) ) {
			return;
		}

		$registry->register(
			self::CONNECTOR_ID,
			array(
				'name'           => __( 'Invisible Anti-Spam', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'description'    => __( 'Blocks form spam with an invisible proof-of-work challenge. Runs entirely on this site — no external service, no API key, and no submitted content leaves your server.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'type'           => 'spam_filtering',
				'authentication' => array( 'method' => 'none' ),
			)
		);
	}

	/**
	 * Permanent notice while stage 3 is on.
	 *
	 * Not dismissible, on the model of simulation mode: this is a state the operator
	 * chose and can undo, and forgetting it is the failure mode worth designing
	 * against.
	 *
	 * @return void
	 */
	public function render_unsafe_notice() {
		if ( ! current_user_can( 'manage_options' ) || ! self::unsafe_enabled() ) {
			return;
		}

		echo '<div class="notice notice-warning"><p>';
		echo esc_html__( 'Invisible Anti-Spam: AI agents can currently read stored submissions and change protection settings.', 'gdpr-compliant-recaptcha-for-all-forms' );
		echo '</p></div>';
	}
}
