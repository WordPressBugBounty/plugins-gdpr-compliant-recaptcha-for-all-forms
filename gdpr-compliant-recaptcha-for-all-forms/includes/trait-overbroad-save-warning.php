<?php
/**
 * The SAVE ROUND TRIP of the over-broad-pattern guard: warn on save, keep what was
 * typed, take the administrator's confirmation.
 *
 * SCHNITTLINIE (Welle 4, PLAN-DATEIGROESSE.md) — the three-way split and why these are
 * traits rather than classes is documented once, in trait-overbroad-blame.php. What
 * lives here is everything the SETTINGS PAGE calls (Settings_Menu::update_settings()
 * and the page renderer): confirmed(), the two warning texts and the two confirmation
 * blocks. The notice that appears AFTERWARDS — a different audience, a different moment,
 * and the marker's only reader — stays in class-overbroad-pattern-guard.php.
 *
 * The two boxes deliberately keep their own checkbox, their own hash field and their own
 * sentences; only confirmation_hash() is shared, and it stays in the class. See the
 * ACK_VALUE_FIELD constant for why sharing the checkbox would wave the more dangerous of
 * the two through.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse (Traits
// bekommen keine eigene Indexzeile; sie sind Teil ihrer Klasse).

/**
 * The settings-page half of the over-broad guard. Composed into
 * Overbroad_Pattern_Guard.
 */
trait Overbroad_Save_Warning {

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
	 * @param string   $ack_field     Checkbox field name; the BLOCKED VALUES box passes its
	 *                                own (ACK_VALUE_FIELD), see that constant for why the
	 *                                two must not share one.
	 * @param string   $hash_field    Hidden hash field name belonging to $ack_field.
	 * @return bool
	 */
	public static function confirmed( array $flagged_lines, string $ack_field = self::ACK_FIELD, string $hash_field = self::ACK_HASH_FIELD ): bool {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- reached only from Settings_Menu::update_settings(), which verifies gdpr_settings_nonce and manage_options before calling; this pair carries no privilege of its own (see confirmation_hash()).
		if ( ! isset( $_POST[ $ack_field ] ) || ! isset( $_POST[ $hash_field ] ) ) {
			return false;
		}
		$submitted = sanitize_text_field( wp_unslash( $_POST[ $hash_field ] ) );
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
	 * The same message for the BLOCKED VALUES box — different sentence, because a block
	 * rule fails differently from a monitoring pattern and the two must not be explained
	 * with one text.
	 *
	 * A monitoring pattern that is too wide watches more submissions; a BLOCK rule that is
	 * too wide DISCARDS them. And the most likely way to write one is not a subtle mistake
	 * but a mix-up of the two boxes: `{"_wpcf7":null}` is a sensible line to type into
	 * "Apply on pattern" and a form-shredder here. The message therefore says what the rule
	 * would do, not merely that it is broad.
	 *
	 * esc_html() here for the same reason as warning_message(): settings_errors() prints
	 * the message UNESCAPED and the lines are administrator-typed text.
	 *
	 * @param array<string, string[]> $flagged Pattern_Matcher::overbroad_blocklist_lines() result.
	 * @return string
	 */
	public static function blocklist_warning_message( array $flagged ): string {
		$labels = self::reason_labels();
		$parts  = array();
		foreach ( $flagged as $line => $reasons ) {
			$named = array();
			foreach ( $reasons as $reason ) {
				$named[] = isset( $labels[ $reason ] ) ? $labels[ $reason ] : $reason;
			}
			$parts[] = sprintf(
				/* translators: 1: the blocklist rule as entered, 2: comma-separated reasons */
				__( '%1$s (%2$s)', 'gdpr-compliant-recaptcha-for-all-forms' ),
				esc_html( (string) $line ),
				implode( ', ', $named )
			);
		}

		return sprintf(
			/* translators: %s: the offending blocklist rules with the reasons they were held back */
			__( 'These blocked-value rules were NOT saved yet: %s. A rule here BLOCKS what it matches — a rule that pins no value on a field people fill in discards everything that form sends. If you meant to watch that form rather than block it, the line belongs in "Apply on pattern" instead. Otherwise add a value condition, or tick "Save these rules anyway" below and save again. Everything else on this page was saved.', 'gdpr-compliant-recaptcha-for-all-forms' ),
			implode( '; ', $parts )
		);
	}

	/**
	 * Human, translated names for the reason codes of
	 * Pattern_Matcher::overbroad_blocklist_lines(): the screen keys plus the one reason
	 * that is not a screen.
	 *
	 * @return array<string, string>
	 */
	private static function reason_labels() {
		$labels = self::screen_labels();
		$labels[ Pattern_Matcher::BLOCKLIST_FORM_WIDE ] = __( 'blocks the whole form', 'gdpr-compliant-recaptcha-for-all-forms' );
		return $labels;
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

	/**
	 * The same block for the BLOCKED VALUES box. A sister renderer rather than the same one
	 * with parameters: every sentence in it differs (a rule blocks, a pattern watches), and
	 * a translator needs whole sentences, not a shared skeleton with swapped nouns. What IS
	 * shared is the part that must not diverge — confirmation_hash().
	 *
	 * The `inline` class is load-bearing here for the same reason as above: without it
	 * wp-admin's own JavaScript moves the notice out of the form and the checkbox is never
	 * submitted.
	 *
	 * @param array<string, string[]> $flagged Pattern_Matcher::overbroad_blocklist_lines() result.
	 * @return void
	 */
	public static function render_blocklist_confirmation_block( array $flagged ) {
		if ( empty( $flagged ) ) {
			return;
		}
		$hash = self::confirmation_hash( array_keys( $flagged ) );
		?>
		<div class="notice notice-warning inline gdpr-overbroad-warning" id="gdpr-overbroad-blocklist-warning">
			<p><strong><?php esc_html_e( 'These blocked-value rules would block far more than a single value:', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></strong></p>
			<ul>
				<?php foreach ( array_keys( $flagged ) as $line ) : ?>
					<li><code><?php echo esc_html( $line ); ?></code></li>
				<?php endforeach; ?>
			</ul>
			<p><?php esc_html_e( 'They were kept out of the saved value for now; the text box below still holds what you typed. A rule that names only a form, and no value on a field people fill in, discards every submission of that form. If you wanted to watch that form instead of blocking it, put the line in "Apply on pattern".', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></p>
			<p>
				<label>
					<input type="checkbox" name="<?php echo esc_attr( self::ACK_VALUE_FIELD ); ?>" value="1" />
					<?php esc_html_e( 'Save these rules anyway', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
				</label>
				<input type="hidden" name="<?php echo esc_attr( self::ACK_VALUE_HASH_FIELD ); ?>" value="<?php echo esc_attr( $hash ); ?>" />
			</p>
		</div>
		<?php
	}
}
