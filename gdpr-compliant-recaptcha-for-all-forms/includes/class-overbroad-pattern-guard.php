<?php
/**
 * The two halves that make an OVER-BROAD field pattern survivable: a warning with a
 * confirmation when it is saved, and a plain statement afterwards when one has already
 * discarded an admin's own save. See handbuch/admin.md.
 *
 * THE COST CASE (handbuch/gate.md, "Der eine Fall, in dem es doch beisst"): the
 * constructor gate does not tell frontend from backend traffic, so a pattern generic
 * enough to match a wp-admin screen — `{"email":null}` is the measured example — turns
 * that screen's save into a spam verdict. POW_BLOCK is on by default, so the save is
 * discarded, and wp-admin never receives the PoW script, so there is no challenge the
 * administrator could solve to get out of it. THE VERDICT ITSELF IS NOT TOUCHED HERE
 * (owner decision): what hurts is not the rule, it is the SURPRISE — the symptom points
 * nowhere near its cause.
 *
 * WHY THIS IS NOT SHAPED LIKE RestRoute::reject_self_lockout_lines(). That guard drops
 * the offending line hard, and there it is right: a `wp/v2` line has no legitimate use,
 * and the damage it does is irreversible without database or FTP access. A generic FIELD
 * pattern is a different animal — the very same `{"email":null}` is a plausible frontend
 * catch-all on a site whose forms need one — and its damage is reversible by editing the
 * textarea. So what is borrowed from that guard is the PRINCIPLE ("a pure decision, named
 * rather than swallowed"), not the severity: this one warns and then saves on the
 * administrator's word.
 *
 * THE SAVE ROUND TRIP, in three moves (Settings_Menu::update_settings()):
 *   1. First save carrying over-broad lines: update_option() for POW_PARAMETER_PATTERN is
 *      SKIPPED — the old value stays in the database — while every other option saves
 *      normally, and add_settings_error() names each offending line with the screens it
 *      hits.
 *   2. The submitted text is NOT lost: it is parked on the Settings_Menu instance and the
 *      value-loading loop renders it instead of the stored value in the SAME request.
 *      Deliberately no transient, no persistence — leave the page and the text is gone,
 *      exactly like any other unsaved form. Named and accepted.
 *   3. The confirmation is a checkbox plus a hidden sha256 over the CANONICALISED
 *      offending lines (trimmed, de-duplicated, sorted). The next save stores normally
 *      when the box is ticked AND the hash still matches the lines submitted THEN — edit
 *      to different over-broad lines after the warning and you are warned again. No
 *      second, forgettable option is created: the confirmation lives only inside the form
 *      round trip, so there is nothing anyone could leave switched on. No own nonce
 *      either — the save is already covered by the settings nonce and manage_options, and
 *      the hash is not a privilege, only evidence that a warning was seen.
 *
 * THE NOTICE AFTERWARDS exists because the warning only works forwards. Someone whose
 * pattern is already broad — or who installs a plugin tomorrow whose admin form happens
 * to carry an `email` field — only ever notices that their save vanished. Four properties,
 * all four load-bearing:
 *
 *   (a) NO CONSTRUCTOR SURGERY. Deciding "this POST targeted a real wp-admin screen"
 *       needs is_admin() (WP_ADMIN is defined in wp-admin/admin.php BEFORE wp-load),
 *       DOING_AJAX and SCRIPT_FILENAME — nothing that has to move. SCRIPT_FILENAME rather
 *       than $pagenow/PHP_SELF: those two are colourable through a PATH-INFO trick, and
 *       this decision must not be steerable from outside. admin-post.php is excluded even
 *       though it defines WP_ADMIN — it is a frontend submission endpoint that dispatches
 *       for anonymous callers as well — and admin-ajax.php is excluded via DOING_AJAX.
 *   (b) NO BLIND SPOT. The marker is written IN THE BLOCK BRANCH itself, independent of
 *       POW_SAVE_SPAM. Hanging it off stored messages would reproduce the health
 *       counter's blind spot (HANDBUCH.md §12, end): with spam storage off it would read
 *       silent forever, on precisely the sites where the operator can see nothing else.
 *       Option::increment_no_pow_health_counter() learnt that lesson already.
 *   (c) HARDENED AGAINST THE OBVIOUS ABUSE. An anonymous bot can POST to
 *       /wp-admin/profile.php; the plugin blocks at include time, BEFORE auth_redirect()
 *       would have thrown the request out, so the marker would exist without anybody
 *       being logged in. The vector is social engineering, so: (1) the notice NEVER offers
 *       a one-click removal or weakening, only text and a link to the settings page, and
 *       (2) the marker stores sha256(client ip) — the same hashing convention as `rgm_ip`
 *       — and the notice renders only for a manage_options viewer whose own current
 *       hashed address matches. A bot from a foreign address produces a marker nobody
 *       ever sees. THE REMAINING GAP, named rather than hidden: behind an unconfigured
 *       proxy every visitor collapses onto one address, and there the binding is
 *       colourable. The notice stays purely advisory, which is what keeps that tolerable.
 *   (d) FAIL-SAFE BY CONSTRUCTION, not by care. Recording is pure observation AFTER the
 *       classification is finished: one set_transient() whose return value is ignored.
 *       Reading happens only while rendering admin_notices; dismissing deletes. NO CODE
 *       PATH IN check_submit()/check_request() READS THE MARKER — pinned as a source-level
 *       invariant in tests/unit/OverbroadPatternMarkerWiringTest.php, so a future edit
 *       cannot quietly turn a diagnostic aid into an input of the spam decision.
 *
 * WHAT "OVER-BROAD" COVERS HERE — two SOURCES, not one. The save-time warning is about
 * FIELD patterns (`{"email":null}` in POW_PARAMETER_PATTERN), because those are what the
 * core-screen signature catalog can be compared against. The notice afterwards has to
 * cover the BLOCKED VALUES as well (`@gmail.com` in POW_BLOCKED_VALUES, what the one-click
 * "block this address/domain" button writes): such an entry matches on VALUES anywhere in
 * the submission, so it discards a profile save carrying that address, a comment
 * moderation carrying it, or a post whose text links the blocked domain — none of which
 * any forward-looking catalog could predict. blaming_lines() therefore reads BOTH options
 * (one parameter each) and takes the value reading from Echo_Values rather than restating
 * it. It also reports WHICH of the two is to blame, so the notice can send the operator to
 * the right box: the two settings now live in different groups, and "check your patterns"
 * for a line that is not in the pattern box at all is a diagnosis that costs more than it
 * gives.
 *
 * The pure halves (is_core_admin_screen_post(), confirmation_hash(), blaming_lines(),
 * screen_file()) carry no WordPress at all and are unit-tested directly:
 * tests/unit/OverbroadPatternGuardTest.php. ("No WordPress" survives the wildcard half:
 * Echo_Values' matching functions are pure too.)
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Save-time warning and after-the-fact notice for over-broad field patterns.
 */
final class Overbroad_Pattern_Guard {

	/**
	 * Transient holding the ONE marker: "an over-broad pattern discarded a wp-admin save".
	 *
	 * A transient, not an option, and short-lived on purpose: this is an observation with
	 * a shelf life, not a setting. Nothing but render_notice() reads it.
	 */
	const MARKER_TRANSIENT = 'gdpr_pow_overbroad_pattern_block';

	/** 48 h. Written as seconds so this file stays loadable without WordPress. */
	const MARKER_TTL_SECONDS = 172800;

	/** At most this many offending lines travel in one marker, across BOTH sources. */
	const MARKER_MAX_LINES = 5;

	/**
	 * The two things blaming_lines() can name: a monitoring pattern line from
	 * POW_PARAMETER_PATTERN, or a blocked value from POW_BLOCKED_VALUES.
	 *
	 * They are separate settings in separate groups since PLAN-BLOCKLIST-TRENNUNG.md, so
	 * the notice has to say which box the operator should open. Stored inside the marker
	 * transient, hence plain strings rather than an enum.
	 */
	const BLAME_PATTERN = 'pattern';

	/** @see BLAME_PATTERN */
	const BLAME_VALUE = 'value';

	/** POST field of the "save anyway" checkbox. */
	const ACK_FIELD = 'gdpr_pow_pattern_ack';

	/** POST field of the hash binding that confirmation to the lines it was shown for. */
	const ACK_HASH_FIELD = 'gdpr_pow_pattern_ack_hash';

	/** Query argument AND nonce action of the notice's dismiss link. */
	const DISMISS_ARG = 'gdpr_pow_pattern_notice_dismiss';

	/**
	 * Request paths that define WP_ADMIN but are NOT an admin screen a human is looking
	 * at. Compared per path SEGMENT (lower-cased), so no suffix or symlink spelling can
	 * hide one of them.
	 *
	 * admin-post.php is the important one: it sets WP_ADMIN and dispatches
	 * `admin_post_nopriv_*` for anonymous callers, i.e. it is a frontend submission
	 * endpoint wearing an admin path. admin-ajax.php is already excluded via DOING_AJAX;
	 * it is listed anyway because a belt-and-braces list costs nothing and a missing
	 * DOING_AJAX would otherwise turn every ajax POST into an "admin screen".
	 *
	 * @var string[]
	 */
	const NON_SCREEN_ENDPOINTS = array( 'admin-post.php', 'admin-ajax.php' );

	public function __construct() {
		add_action( 'admin_init', array( $this, 'handle_dismiss' ), 5 );
		add_action( 'admin_notices', array( $this, 'render_notice' ) );
	}

	/*
	 * ---------------------------------------------------------------------------------
	 * Pure decisions (no WordPress) — unit-tested in OverbroadPatternGuardTest.php
	 * ---------------------------------------------------------------------------------
	 */

	/**
	 * Did this request target a real wp-admin SCREEN (as opposed to a dispatch endpoint
	 * that merely happens to define WP_ADMIN)?
	 *
	 * The caller supplies the three inputs; none of them is read here, so the decision is
	 * testable and cannot drift into reading something colourable. SCRIPT_FILENAME is
	 * used rather than $pagenow/PHP_SELF precisely because those two can be steered with
	 * PATH-INFO.
	 *
	 * ERROR DIRECTION FOR AN EMPTY SCRIPT_FILENAME: false, i.e. no marker. The file name
	 * is the only thing that can rule out admin-post.php; without it the request cannot
	 * be claimed to be a screen. An unrecorded marker costs a diagnosis, a wrongly
	 * recorded one accuses a pattern that did nothing.
	 *
	 * @param bool   $is_admin        is_admin() — WP_ADMIN, set before wp-load runs.
	 * @param bool   $doing_ajax      wp_doing_ajax() / the DOING_AJAX constant.
	 * @param string $script_filename $_SERVER['SCRIPT_FILENAME'], raw.
	 * @return bool
	 */
	public static function is_core_admin_screen_post( bool $is_admin, bool $doing_ajax, string $script_filename ): bool {
		if ( ! $is_admin || $doing_ajax ) {
			return false;
		}
		$path = strtolower( trim( str_replace( '\\', '/', $script_filename ) ) );
		if ( '' === $path ) {
			return false;
		}
		foreach ( explode( '/', $path ) as $segment ) {
			if ( in_array( trim( $segment ), self::NON_SCREEN_ENDPOINTS, true ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The bare script name of a request path, for display in the notice ("profile.php").
	 *
	 * Reduced to a conservative character set and length because it ends up in rendered
	 * HTML: whatever the server put in SCRIPT_FILENAME, only a file-name-shaped remainder
	 * survives.
	 *
	 * @param string $script_filename $_SERVER['SCRIPT_FILENAME'], raw.
	 * @return string Empty when nothing file-name-shaped is left.
	 */
	public static function screen_file( string $script_filename ): string {
		$path     = trim( str_replace( '\\', '/', $script_filename ) );
		$segments = explode( '/', $path );
		$last     = (string) array_pop( $segments );
		$clean    = (string) preg_replace( '/[^A-Za-z0-9._-]/', '', $last );
		return substr( $clean, 0, 64 );
	}

	/**
	 * Which configured pattern lines match this request — i.e. which of them is to blame
	 * for the verdict that just discarded a backend save.
	 *
	 * Deliberately NOT filtered through Pattern_Matcher::overbroad_lines() first: that one
	 * answers "would this line hit a WordPress CORE screen", and the case this marker is
	 * for explicitly includes a third-party plugin's admin form that carries a generic
	 * field. Blame is therefore decided against the request that actually happened, using
	 * the same line interpretation the live gate uses.
	 *
	 * BOTH SOURCES, because the gate has two. A field pattern (`{"email":null}`, from
	 * POW_PARAMETER_PATTERN) is answered by Pattern_Matcher::line_matches(); a BLOCKED
	 * VALUE (`@gmail.com`, from POW_BLOCKED_VALUES) is not, and cannot be — it is not a
	 * pattern at all. Asking only the field matcher left this half of the configuration
	 * invisible here: a profile save that a blocked sender domain really discards returned
	 * an EMPTY result, so no marker was written and the notice stayed silent on precisely
	 * the kind of entry a one-click "block this domain" writes. Measured before the fix.
	 *
	 * The value half is answered by asking Echo_Values — the SAME functions that classify
	 * live (values_from_plaintext_lines() to read the line, matches_wildcard_values() to
	 * judge it) — never by a second rendering of the rule here. That is the construction
	 * principle spelled out in the Pattern_Matcher class docblock: a diagnosis built on a
	 * lookalike implementation is worse than none, because it eventually names the wrong
	 * line, and nothing exercises the two side by side.
	 *
	 * THE RESULT SAYS WHICH SOURCE, not just which text. Since the blocklist moved into
	 * its own option and its own settings group (PLAN-BLOCKLIST-TRENNUNG.md), "a pattern
	 * you configured" would be the wrong sentence for half the cases and would send the
	 * operator to a box that does not contain the named line.
	 *
	 * PURE DIAGNOSIS. This decides who is NAMED, never what is blocked — the cap, the
	 * de-duplication and the option order are unchanged, and no caller may turn the result
	 * into an input of the spam decision (pinned in OverbroadPatternMarkerWiringTest).
	 *
	 * @param string   $option_value   POW_PARAMETER_PATTERN, exactly as stored.
	 * @param mixed    $request        The field map the gate matched against.
	 * @param string[] $own_domains    Registrable domains of the site itself, as the live
	 *                                 matcher receives them. OPTIONAL ONLY so existing
	 *                                 callers keep working: left out, a blocked value on
	 *                                 the site's OWN domain is judged differently here than
	 *                                 by the live matcher (which excludes own domains from
	 *                                 URL extraction and from the sender-domain rule, see
	 *                                 Echo_Values::is_blockable_sender_domain()), so blame
	 *                                 can name an entry the gate did not act on. Callers
	 *                                 should pass it.
	 * @param string   $blocked_values POW_BLOCKED_VALUES, exactly as stored. Its own
	 *                                 parameter rather than a second reading of
	 *                                 $option_value: they are two different options with
	 *                                 two different formats, and one string cannot carry
	 *                                 both without the ambiguity this whole change removed.
	 * @return array<string, string> Trimmed offending line => BLAME_PATTERN|BLAME_VALUE,
	 *                               pattern lines first, each in its own option's order,
	 *                               capped at MARKER_MAX_LINES in total.
	 */
	public static function blaming_lines( string $option_value, $request, array $own_domains = array(), string $blocked_values = '' ): array {
		$blamed = array();

		foreach ( self::split_lines( $option_value ) as $line ) {
			if ( count( $blamed ) >= self::MARKER_MAX_LINES ) {
				return $blamed;
			}
			if ( isset( $blamed[ $line ] ) ) {
				continue;
			}
			if ( Pattern_Matcher::line_matches( $line, $request ) ) {
				$blamed[ $line ] = self::BLAME_PATTERN;
			}
		}

		foreach ( self::split_lines( $blocked_values ) as $line ) {
			if ( count( $blamed ) >= self::MARKER_MAX_LINES ) {
				return $blamed;
			}
			if ( isset( $blamed[ $line ] ) ) {
				continue;
			}
			if ( self::blocked_value_matches( $line, $request, $own_domains ) ) {
				$blamed[ $line ] = self::BLAME_VALUE;
			}
		}

		return $blamed;
	}

	/**
	 * One option value into its trimmed, non-empty lines.
	 *
	 * @param string $option_value Raw option value.
	 * @return string[]
	 */
	private static function split_lines( string $option_value ): array {
		$lines = preg_split( "/\r\n|\n|\r/", $option_value );
		if ( false === $lines ) {
			return array();
		}
		$out = array();
		foreach ( $lines as $raw_line ) {
			$line = trim( $raw_line );
			if ( '' !== $line ) {
				$out[] = $line;
			}
		}
		return $out;
	}

	/**
	 * Does this ONE blocklist entry match the request?
	 *
	 * Both halves are borrowed whole from Echo_Values, so there is exactly one place in
	 * the plugin that knows what a blocked value means and when it hits. An empty result
	 * from values_from_plaintext_lines() is the answer "this line carries no value at
	 * all" — the only thing decided here.
	 *
	 * @param string   $line        One trimmed blocklist line.
	 * @param mixed    $request     The field map the gate matched against.
	 * @param string[] $own_domains Registrable domains of the site itself.
	 * @return bool
	 */
	private static function blocked_value_matches( string $line, $request, array $own_domains ): bool {
		$values = Echo_Values::values_from_plaintext_lines( array( $line ) );
		if ( empty( $values ) ) {
			return false;
		}
		return (bool) Echo_Values::matches_wildcard_values( $request, $values, $own_domains );
	}

	/**
	 * The confirmation hash: sha256 over the canonicalised offending lines.
	 *
	 * Canonical = trimmed, empty dropped, de-duplicated, sorted — so re-ordering the
	 * textarea does not invalidate a confirmation the admin just gave, while editing to a
	 * DIFFERENT over-broad line does. That is the whole binding: it says "you were warned
	 * about exactly these", nothing more. It carries no privilege and needs no nonce.
	 *
	 * @param string[] $lines Offending lines.
	 * @return string 64 hex characters, or '' for an empty set.
	 */
	public static function confirmation_hash( array $lines ): string {
		$canonical = array();
		foreach ( $lines as $line ) {
			$trimmed = trim( (string) $line );
			if ( '' !== $trimmed ) {
				$canonical[] = $trimmed;
			}
		}
		if ( empty( $canonical ) ) {
			return '';
		}
		$canonical = array_values( array_unique( $canonical ) );
		sort( $canonical, SORT_STRING );
		return hash( 'sha256', implode( "\n", $canonical ) );
	}

	/*
	 * ---------------------------------------------------------------------------------
	 * Settings-page half: warn on save, keep the input, take the confirmation
	 * ---------------------------------------------------------------------------------
	 */

	/**
	 * Has the administrator confirmed EXACTLY these over-broad lines in this submission?
	 *
	 * Both halves are required: the box has to be ticked and the hidden hash has to match
	 * the lines being submitted NOW. The caller (Settings_Menu::update_settings()) has
	 * already verified the settings nonce and manage_options before anything here runs.
	 *
	 * @param string[] $flagged_lines Over-broad lines of the CURRENT submission.
	 * @return bool
	 */
	public static function confirmed( array $flagged_lines ): bool {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- reached only from Settings_Menu::update_settings(), which verifies gdpr_settings_nonce and manage_options before calling; this pair carries no privilege of its own (see confirmation_hash()).
		if ( ! isset( $_POST[ self::ACK_FIELD ] ) || ! isset( $_POST[ self::ACK_HASH_FIELD ] ) ) {
			return false;
		}
		$submitted = sanitize_text_field( wp_unslash( $_POST[ self::ACK_HASH_FIELD ] ) );
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		$expected = self::confirmation_hash( $flagged_lines );
		if ( '' === $expected || '' === $submitted ) {
			return false;
		}
		return hash_equals( $expected, $submitted );
	}

	/**
	 * The message add_settings_error() shows: every offending line, with the core screens
	 * it hits, plus what happens next.
	 *
	 * The line is esc_html()'d HERE because settings_errors() prints its message
	 * UNESCAPED — the string travels as ready-to-print HTML, and it carries text the
	 * administrator typed into a textarea (`{"email":"<img onerror=…>"}` is a perfectly
	 * well-formed pattern line).
	 *
	 * @param array<string, string[]> $flagged Pattern_Matcher::overbroad_lines() result.
	 * @return string
	 */
	public static function warning_message( array $flagged ): string {
		$labels = self::screen_labels();
		$parts  = array();
		foreach ( $flagged as $line => $screens ) {
			$named = array();
			foreach ( $screens as $screen ) {
				$named[] = isset( $labels[ $screen ] ) ? $labels[ $screen ] : $screen;
			}
			$parts[] = sprintf(
				/* translators: 1: the pattern line as entered, 2: comma-separated admin screen names */
				__( '%1$s (matches: %2$s)', 'gdpr-compliant-recaptcha-for-all-forms' ),
				esc_html( (string) $line ),
				implode( ', ', $named )
			);
		}

		return sprintf(
			/* translators: %s: the offending pattern lines with the screens they match */
			__( 'These field patterns were NOT saved yet, because they also match WordPress\' own admin screens: %s. While such a pattern is active, saving one of those screens is treated as spam and discarded — and wp-admin never gets a puzzle to solve, so you could not work around it. Either make the pattern specific to your form (add a field only that form sends), or tick "Save these patterns anyway" below and save again. Everything else on this page was saved.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			implode( '; ', $parts )
		);
	}

	/**
	 * The confirmation block, rendered INSIDE the settings form (that is why it does not
	 * live in the add_settings_error() message: those render above the form, where a
	 * checkbox would never be submitted).
	 *
	 * THE `inline` CLASS IS LOAD-BEARING, not styling. wp-admin/js/common.js relocates
	 * every `div.notice` that is not `.inline` to just after the first heading in `.wrap`
	 * — which is OUTSIDE this form. Without it, the checkbox and the hidden hash would be
	 * moved out of the form by JavaScript and never submitted, and no HTML-scraping test
	 * could see it: the markup is identical either way, only a real browser moves it.
	 *
	 * @param array<string, string[]> $flagged Pattern_Matcher::overbroad_lines() result.
	 * @return void
	 */
	public static function render_confirmation_block( array $flagged ) {
		if ( empty( $flagged ) ) {
			return;
		}
		$hash = self::confirmation_hash( array_keys( $flagged ) );
		?>
		<div class="notice notice-warning inline gdpr-overbroad-warning" id="gdpr-overbroad-warning">
			<p><strong><?php esc_html_e( 'These field patterns also match WordPress\' own admin screens:', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></strong></p>
			<ul>
				<?php foreach ( array_keys( $flagged ) as $line ) : ?>
					<li><code><?php echo esc_html( $line ); ?></code></li>
				<?php endforeach; ?>
			</ul>
			<p><?php esc_html_e( 'They were kept out of the saved value for now; the text box below still holds what you typed. Make the pattern specific to your form, or confirm that you want it as it is.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></p>
			<p>
				<label>
					<input type="checkbox" name="<?php echo esc_attr( self::ACK_FIELD ); ?>" value="1" />
					<?php esc_html_e( 'Save these patterns anyway', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
				</label>
				<input type="hidden" name="<?php echo esc_attr( self::ACK_HASH_FIELD ); ?>" value="<?php echo esc_attr( $hash ); ?>" />
			</p>
		</div>
		<?php
	}

	/*
	 * ---------------------------------------------------------------------------------
	 * Notice half: record the marker, show it, let it be dismissed
	 * ---------------------------------------------------------------------------------
	 */

	/**
	 * Record that an over-broad pattern just caused a wp-admin save to be discarded.
	 *
	 * PURE OBSERVATION. Called from the block branch of Stamp::check_submit() after the
	 * classification is complete; the set_transient() return value is ignored on purpose,
	 * because nothing about the request may depend on whether this worked. Silent in
	 * simulation mode: there EVERYTHING is spam by configuration, so blaming a pattern
	 * would be an accusation the evidence does not support.
	 *
	 * @param mixed  $request   The field map the gate matched against.
	 * @param string $hashed_ip sha256 of the resolved client address (see the class docblock, (c)).
	 * @return void
	 */
	public static function record_backend_block( $request, string $hashed_ip ) {
		if ( get_option( Option::POW_SIMULATE_SPAM ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- server-set path, only compared against a fixed list of file names and reduced to a file-name shape before display (screen_file()).
		$script = isset( $_SERVER['SCRIPT_FILENAME'] ) ? (string) $_SERVER['SCRIPT_FILENAME'] : '';
		if ( ! self::is_core_admin_screen_post( is_admin(), wp_doing_ajax(), $script ) ) {
			return;
		}
		// The site's own domains, so a blocked value is judged here exactly as the live
		// matcher judged it (Echo_Values::is_blockable_sender_domain() refuses an own-domain
		// entry as a sender-domain rule). Read AFTER the screen gate above, never on an
		// arbitrary request; it is three option reads, no query.
		$blamed = self::blaming_lines(
			(string) get_option( Option::POW_PARAMETER_PATTERN ),
			$request,
			Echo_Store::site_domains(),
			(string) get_option( Option::POW_BLOCKED_VALUES )
		);
		if ( empty( $blamed ) ) {
			return;
		}
		set_transient(
			self::MARKER_TRANSIENT,
			array(
				// The map line => BLAME_*, so the notice can name the right settings box.
				// render_notice() also accepts the pre-5.4.0 LIST shape, because a marker
				// written before the update can still be within its 48 h when it is read.
				'ip'     => $hashed_ip,
				'lines'  => $blamed,
				'screen' => self::screen_file( $script ),
				'at'     => time(),
			),
			self::MARKER_TTL_SECONDS
		);
	}

	/**
	 * The marker's `lines` entry, normalised to the map line => BLAME_*.
	 *
	 * Accepts BOTH shapes on purpose. Before PLAN-BLOCKLIST-TRENNUNG.md the marker held a
	 * plain LIST of lines, all of them pattern lines; such a marker can still be inside its
	 * 48 h TTL when a site updates, and dropping it would swallow the one notice that
	 * explains a save the operator just lost. An unkeyed entry is therefore read as a
	 * pattern line, which is exactly what it was.
	 *
	 * @param mixed $stored The marker's `lines` value.
	 * @return array<string, string>
	 */
	private static function blamed_map( $stored ): array {
		$map = array();
		foreach ( (array) $stored as $key => $value ) {
			if ( is_string( $key ) ) {
				$map[ $key ] = self::BLAME_VALUE === $value ? self::BLAME_VALUE : self::BLAME_PATTERN;
				continue;
			}
			$map[ (string) $value ] = self::BLAME_PATTERN;
		}
		return $map;
	}

	/**
	 * The notice's opening sentence: what kind of configuration discarded the save, and
	 * where it happened.
	 *
	 * Written as whole sentences per case rather than assembled from fragments — a
	 * translator needs the sentence, not a noun and a verb to glue together.
	 *
	 * @param string $screen      Sanitised script name, '' when unknown.
	 * @param bool   $has_pattern A pattern line is among the blamed entries.
	 * @param bool   $has_value   A blocked value is among the blamed entries.
	 * @return string
	 */
	private static function notice_intro( string $screen, bool $has_pattern, bool $has_value ): string {
		if ( '' === $screen ) {
			if ( $has_pattern && $has_value ) {
				return __( 'A field pattern AND a blocked value you configured both match WordPress\' own admin form, so the submission was treated like a spam submission.', 'gdpr-compliant-recaptcha-for-all-forms' );
			}
			if ( $has_value ) {
				return __( 'A value on your "Blocked values" list appears in WordPress\' own admin form, so the submission was treated like a spam submission.', 'gdpr-compliant-recaptcha-for-all-forms' );
			}
			return __( 'A field pattern you configured matches WordPress\' own admin form, so the submission was treated like a spam submission.', 'gdpr-compliant-recaptcha-for-all-forms' );
		}
		if ( $has_pattern && $has_value ) {
			return sprintf(
				/* translators: %s: the wp-admin script the blocked request went to, e.g. profile.php */
				__( 'A field pattern AND a blocked value you configured both match the form on %s, so the submission was treated like a spam submission.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				$screen
			);
		}
		if ( $has_value ) {
			return sprintf(
				/* translators: %s: the wp-admin script the blocked request went to, e.g. profile.php */
				__( 'A value on your "Blocked values" list appears in the form on %s, so the submission was treated like a spam submission.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				$screen
			);
		}
		return sprintf(
			/* translators: %s: the wp-admin script the blocked request went to, e.g. profile.php */
			__( 'A field pattern you configured matches the form on %s, so the submission was treated like a spam submission.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			$screen
		);
	}

	/**
	 * Render the notice — for an administrator, and only for the one whose own current
	 * address matches the one the blocked request came from (class docblock, (c)).
	 *
	 * There is deliberately NO button that removes or relaxes the pattern: this notice can
	 * be provoked by a stranger POSTing to an admin URL, and the worst outcome would be an
	 * administrator disabling their own protection one click after being nudged to. Text
	 * and a link to the settings page; the decision is made there, with the whole textarea
	 * in view.
	 *
	 * @return void
	 */
	public function render_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$marker = get_transient( self::MARKER_TRANSIENT );
		if ( ! is_array( $marker ) || empty( $marker['lines'] ) || empty( $marker['ip'] ) ) {
			return;
		}
		if ( ! hash_equals( (string) $marker['ip'], ProofOfWork::hash_value( Stamp::resolve_client_ip() ) ) ) {
			return;
		}

		$blamed         = self::blamed_map( $marker['lines'] );
		$pattern_lines  = array_keys( $blamed, self::BLAME_PATTERN, true );
		$blocked_values = array_keys( $blamed, self::BLAME_VALUE, true );
		$screen         = isset( $marker['screen'] ) ? (string) $marker['screen'] : '';

		// The core-screen catalog only knows FIELD patterns — a blocked value is not a
		// pattern and would only add noise here, so it is deliberately not fed in.
		$flagged = Pattern_Matcher::overbroad_lines( implode( "\n", $pattern_lines ) );
		$labels  = self::screen_labels();
		$named   = array();
		foreach ( $flagged as $screens ) {
			foreach ( $screens as $key ) {
				$named[ $key ] = isset( $labels[ $key ] ) ? $labels[ $key ] : $key;
			}
		}

		$settings_url = admin_url( 'options-general.php' . Option::PAGE_QUERY );
		$dismiss_url  = wp_nonce_url( add_query_arg( self::DISMISS_ARG, '1' ), self::DISMISS_ARG );
		?>
		<div class="notice notice-warning is-dismissible gdpr-overbroad-notice">
			<p>
				<strong><?php esc_html_e( 'Invisible Anti-Spam: an admin page save was just discarded as spam.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></strong>
				<?php echo esc_html( self::notice_intro( $screen, (bool) $pattern_lines, (bool) $blocked_values ) ); ?>
			</p>
			<?php if ( ! empty( $pattern_lines ) ) : ?>
				<p>
					<?php esc_html_e( 'The pattern responsible, from "Apply on pattern":', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					<code><?php echo esc_html( implode( ' ', $pattern_lines ) ); ?></code>
					<?php if ( ! empty( $named ) ) : ?>
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: comma-separated admin screen names */
								__( 'It also matches: %s.', 'gdpr-compliant-recaptcha-for-all-forms' ),
								implode( ', ', $named )
							)
						);
						?>
					<?php endif; ?>
				</p>
			<?php endif; ?>
			<?php if ( ! empty( $blocked_values ) ) : ?>
				<p>
					<?php esc_html_e( 'The blocked value responsible, from "Blocked values":', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					<code><?php echo esc_html( implode( ' ', $blocked_values ) ); ?></code>
				</p>
			<?php endif; ?>
			<p>
				<?php if ( ! empty( $pattern_lines ) ) : ?>
					<?php esc_html_e( 'Add a field only your own form sends to make the pattern specific, and the admin screens stop matching.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
				<?php endif; ?>
				<?php if ( ! empty( $blocked_values ) ) : ?>
					<?php esc_html_e( 'A blocked value matches wherever it appears, including in your own admin forms — remove it from "Blocked values" or replace it with something more specific.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
				<?php endif; ?>
				<a href="<?php echo esc_url( $settings_url ); ?>"><?php esc_html_e( 'Open the recognition settings', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></a>
				&middot;
				<a href="<?php echo esc_url( $dismiss_url ); ?>"><?php esc_html_e( 'Dismiss', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * Dismiss the notice. Capability plus nonce, like every other state-changing link this
	 * plugin renders — and it only ever deletes the marker, never touches a pattern.
	 *
	 * @return void
	 */
	public function handle_dismiss() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- presence check only; check_admin_referer() below is the guard, and it runs before anything is deleted.
		if ( ! isset( $_GET[ self::DISMISS_ARG ] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		check_admin_referer( self::DISMISS_ARG );
		delete_transient( self::MARKER_TRANSIENT );
		wp_safe_redirect( remove_query_arg( array( self::DISMISS_ARG, '_wpnonce' ) ) );
		exit;
	}

	/**
	 * Human, translated names for the stable screen keys of
	 * Pattern_Matcher::CORE_BACKEND_SIGNATURES (that class is WordPress-free and must not
	 * translate, so the mapping lives here).
	 *
	 * @return array<string, string>
	 */
	private static function screen_labels() {
		return array(
			'profile'         => __( 'Profile / Edit user', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'options-general' => __( 'Settings → General', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'post-editor'     => __( 'Post editor', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'user-new'        => __( 'Add new user', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'comment-edit'    => __( 'Edit comment', 'gdpr-compliant-recaptcha-for-all-forms' ),
		);
	}
}
