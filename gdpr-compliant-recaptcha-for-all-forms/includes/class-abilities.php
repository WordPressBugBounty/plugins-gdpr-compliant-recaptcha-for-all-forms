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

	/**
	 * What the abilities DO, once core has called one of them.
	 *
	 * SCHNITTLINIE (Welle 4, PLAN-DATEIGROESSE.md): this file was 960 lines. It is split
	 * along the seam the plan names — REGISTRATION versus what an ability executes:
	 *   - class-abilities.php      — THIS file: the hooks, the catalogue with its schemas
	 *                                and labels, every permission_callback, the connector
	 *                                card and the standing stage-3 notice.
	 *   - trait-ability-actions.php — the execute callbacks: the self-test hand-off, the
	 *                                scope report, classify-text, the stage-2 scope write
	 *                                and the four stage-3 submission callbacks.
	 *
	 * A trait, not a second class, and three source-level pins are why. classify_text()
	 * calls the PRIVATE wildcard_hit() below, which BlocklistEvaluationWiringTest looks up
	 * BY FILE in this one — a separate class would have forced either a copy of that
	 * one-line delegation or a widened visibility, and the whole point of that pin is that
	 * the blocklist evaluation exists exactly once. A trait is compiled into this class,
	 * so nothing about visibility, the array( $this, … ) callbacks or the pins changes.
	 *
	 * WHAT DELIBERATELY DID NOT MOVE, so a later session does not "finish the job":
	 * read_health() stays here because StampWiringTest pins the exact SET of files that
	 * name the POW_FP_* counters — moving it would add a file to that set and the pin
	 * would fail, which is the pin doing its job. Every ability registration, every
	 * permission callback and the connector registration stay for the same kind of reason:
	 * AbilityRegistrationTest asserts over THIS file that each registration carries its own
	 * capability check.
	 */
	use Ability_Actions;

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
	 * Whether the write/delete half of stage 3 is switched on.
	 *
	 * Kept as a thin alias of Agent_Access::write_enabled() because the name is used
	 * in existing pins and reads correctly at the hook sites here.
	 *
	 * @return bool
	 */
	public static function unsafe_enabled() {
		return Agent_Access::write_enabled();
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

		// Stage 3, in two independently switchable halves. Same discipline as stage 2:
		// a disabled half is NOT registered at all, rather than registered and hidden
		// behind meta.mcp.public — an ability that exists is an ability some other path
		// can reach (core builds REST endpoints for abilities, and any plugin can call
		// wp_get_ability()->execute()).
		if ( Agent_Access::read_enabled() ) {
			$this->register_stage_three_read();
		}

		if ( Agent_Access::write_enabled() ) {
			$this->register_stage_three_write();
		}
	}

	/**
	 * Stage 3, read half. Registered only while POW_ABILITIES_READ_SUBMISSIONS is on.
	 *
	 * @return void
	 */
	private function register_stage_three_read() {
		wp_register_ability(
			self::ABILITY_NAMESPACE . '/list-submissions',
			array(
				'label'               => __( 'List stored submissions', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'description'         => __( 'Returns a page of stored submissions from the inbox or the spam folder: id, date, form action, classification reason and scoring. No field contents — use get-submission for one entry at a time. The analysis folder is not accessible.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'category'            => self::ABILITY_NAMESPACE,
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'folder' => array(
							'type'        => 'string',
							'enum'        => array_keys( Agent_Access::list_folders() ),
							'description' => __( 'Which folder to read.', 'gdpr-compliant-recaptcha-for-all-forms' ),
						),
						'limit'  => array(
							'type'        => 'integer',
							'description' => __( 'Page size, at most 50.', 'gdpr-compliant-recaptcha-for-all-forms' ),
						),
						'offset' => array(
							'type'        => 'integer',
							'description' => __( 'Rows to skip.', 'gdpr-compliant-recaptcha-for-all-forms' ),
						),
					),
					'required'   => array( 'folder' ),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'execute_callback'    => array( $this, 'list_submissions' ),
				'permission_callback' => array( $this, 'can_read_submissions' ),
				'meta'                => array( 'mcp' => array( 'public' => true ) ),
			)
		);

		wp_register_ability(
			self::ABILITY_NAMESPACE . '/get-submission',
			array(
				'label'               => __( 'Read one stored submission', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'description'         => __( 'Returns the stored fields of one submission from the inbox or the spam folder. Password fields are redacted. The analysis folder is not accessible.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'category'            => self::ABILITY_NAMESPACE,
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'id' => array(
							'type'        => 'integer',
							'description' => __( 'Submission id, as returned by list-submissions.', 'gdpr-compliant-recaptcha-for-all-forms' ),
						),
					),
					'required'   => array( 'id' ),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'execute_callback'    => array( $this, 'get_submission' ),
				'permission_callback' => array( $this, 'can_read_submissions' ),
				'meta'                => array( 'mcp' => array( 'public' => true ) ),
			)
		);
	}

	/**
	 * Stage 3, write half. Registered only while POW_ABILITIES_UNSAFE is on.
	 *
	 * @return void
	 */
	private function register_stage_three_write() {
		wp_register_ability(
			self::ABILITY_NAMESPACE . '/delete-submission',
			array(
				'label'               => __( 'Delete one stored submission', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'description'         => __( 'Permanently deletes one submission and its stored fields. Cannot be undone.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'category'            => self::ABILITY_NAMESPACE,
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'id' => array(
							'type'        => 'integer',
							'description' => __( 'Submission id.', 'gdpr-compliant-recaptcha-for-all-forms' ),
						),
					),
					'required'   => array( 'id' ),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'execute_callback'    => array( $this, 'delete_submission' ),
				'permission_callback' => array( $this, 'can_change_protection' ),
				'meta'                => array( 'mcp' => array( 'public' => true ) ),
			)
		);

		wp_register_ability(
			self::ABILITY_NAMESPACE . '/set-protection',
			array(
				'label'               => __( 'Change a protection setting', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'description'         => __( 'Changes one of three settings: the puzzle difficulty, whether spam is blocked, and whether under-attack mode is active. Nothing else can be changed this way — address trust, the monitored scope, spam simulation, spam storage, the token secret and the agent permissions themselves are all excluded.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'category'            => self::ABILITY_NAMESPACE,
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'setting' => array(
							'type'        => 'string',
							'enum'        => array_keys( Agent_Access::PROTECTION_SETTINGS ),
							'description' => __( 'Which setting to change.', 'gdpr-compliant-recaptcha-for-all-forms' ),
						),
						'value'   => array(
							'description' => __( 'New value: an integer for the difficulty, true/false for the switches.', 'gdpr-compliant-recaptcha-for-all-forms' ),
						),
					),
					'required'   => array( 'setting', 'value' ),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'execute_callback'    => array( $this, 'set_protection' ),
				'permission_callback' => array( $this, 'can_change_protection' ),
				'meta'                => array( 'mcp' => array( 'public' => true ) ),
			)
		);
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

	/**
	 * Stage 3, read half. Same belt-and-braces option recheck as stage 2.
	 *
	 * @return bool
	 */
	public function can_read_submissions() {
		return current_user_can( 'manage_options' ) && Agent_Access::read_enabled();
	}

	/**
	 * Stage 3, write half.
	 *
	 * @return bool
	 */
	public function can_change_protection() {
		return current_user_can( 'manage_options' ) && Agent_Access::write_enabled();
	}

	/* ---------------------------------------------------------------------
	 * Execute callbacks that stay HERE
	 *
	 * The rest of them live in trait-ability-actions.php; these two do not, and the
	 * `use Ability_Actions;` docblock above says why (a pinned file set, and a pinned
	 * private delegation).
	 * ------------------------------------------------------------------ */

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
		$no_pow_count = Option::no_pow_health_count();
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
			// The blind spot this used to warn about is closed since 5.3.4: the figure
			// now also comes from a storage-independent bucket counter, so it is real
			// even with spam storage off. What remains true is the narrower statement
			// below — that counter only knows what happened since it started counting,
			// so a freshly updated site reads low for up to its window.
			$caveats[] = __( 'Storing spam is switched off. "no_stamp_row_24h" is still measured (it no longer depends on stored messages), but it only covers submissions seen since this site last updated, so a low number right after an update says little.', 'gdpr-compliant-recaptcha-for-all-forms' );
		}
		if ( (bool) get_option( Option::POW_SIMULATE_SPAM ) ) {
			$caveats[] = __( 'Simulation mode is on: every submission is being treated as spam, which inflates the spam figures.', 'gdpr-compliant-recaptcha-for-all-forms' );
		}
		$caveats[] = __( 'The address-change percentage counts every solved puzzle, including the ones this plugin\'s own self-test solves. Repeated self-tests dilute it.', 'gdpr-compliant-recaptcha-for-all-forms' );

		return $caveats;
	}

	/**
	 * Whether any supplied value is on the operator's blocklist (POW_BLOCKED_VALUES).
	 *
	 * Calls the live evaluation ITSELF (Stamp::blocklist_matches()) rather than rebuilding
	 * it from the same parts — a diagnostic that judged differently from production would
	 * be worse than none, and "same parts" is what drifts. It used to read the option and
	 * assemble the comparison here, which was already one line-shape behind the day
	 * field-bound rules arrived.
	 *
	 * @param array<string,mixed> $fields Supplied fields.
	 * @return bool
	 */
	private function wildcard_hit( $fields ) {
		return Stamp::blocklist_matches( $fields );
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
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$read  = Agent_Access::read_enabled();
		$write = Agent_Access::write_enabled();

		if ( ! $read && ! $write ) {
			return;
		}

		// BOTH halves get the standing notice, and it NAMES which one is on.
		//
		// Splitting stage 3 in two was about giving the operator a real choice, not
		// about declaring the reading half harmless — it ships what visitors typed into
		// the site's forms to whatever agent is connected, which is precisely the
		// promise this plugin otherwise makes ("no tracking, nothing leaves the site").
		// A notice that appeared only for the writing half would read as "reading is
		// fine", which is the wrong lesson to teach silently.
		if ( $read && $write ) {
			$message = __( 'Invisible Anti-Spam: AI agents can currently read stored submissions AND change protection settings.', 'gdpr-compliant-recaptcha-for-all-forms' );
		} elseif ( $read ) {
			$message = __( 'Invisible Anti-Spam: AI agents can currently read stored submissions, including what visitors typed into your forms.', 'gdpr-compliant-recaptcha-for-all-forms' );
		} else {
			$message = __( 'Invisible Anti-Spam: AI agents can currently change protection settings and delete stored submissions.', 'gdpr-compliant-recaptcha-for-all-forms' );
		}

		echo '<div class="notice notice-warning"><p>';
		echo esc_html( $message );
		echo '</p></div>';
	}
}
