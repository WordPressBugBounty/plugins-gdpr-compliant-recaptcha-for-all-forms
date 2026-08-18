<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Page: das Rendern der Einstellungsseite — Gruppen/Pill-Tabs,
 * Badge-Karte, kses-Allowlist, Kopfzeile, eine Karte je Option und der synthetische
 * Reiter "Diagnostics" samt seiner beiden Ajax-Aktionen.
 *
 * SCHNITTLINIE (Welle 3, PLAN-DATEIGROESSE.md): Settings_Menu war eine Datei mit
 * 2592 Zeilen. Sie ist entlang ihrer Sektionen aufgeteilt:
 *   - class-settings-menu.php             — Konstruktion, Hooks, Menue, Selbsttest,
 *                                           prepare_options() und der Proxy-Vorschlag.
 *   - trait-settings-defaults.php         — die drei get_default_*()-Seeds (handbuch/gate.md).
 *   - trait-settings-options.php          — Options-Matrix, Teil 1 (Reiter "Most relevant",
 *                                           "Spam Processing").
 *   - trait-settings-options-storage.php  — Options-Matrix, Teil 2 (Reiter "Saving Messages",
 *                                           "Scope", "WordPress Administration", "Algorithm",
 *                                           "AI & Agents").
 *   - trait-settings-status.php           — Status-Leiste und die Proxy-Hinweise darunter.
 *   - trait-settings-save.php             — update_settings(), die Persistenz samt Save-Guards.
 *   - trait-settings-page.php             — das Rendern der Seite (Tabs, Karten, Diagnose).
 *
 * Traits statt zweiter Klassen, und zwar bewusst: diese Methoden sind als
 * `array( $this, ... )`-Hooks registriert, lesen `$this->options`/`$this->plugin_name`
 * und die request-scoped `$pending_*`-Felder, und mehrere Quelltext-Pins in tests/unit
 * haengen an genau dieser Bindung. Ein Trait wird zur Kompilierzeit in die Klasse
 * kopiert — die Aufteilung ist damit ein Umzug, kein Umbau, und kein Aufrufer,
 * kein Hook und keine Sichtbarkeit aendert sich.
 */
trait Settings_Page {
	/** Ordered list of distinct option groups (tab/panel order), derived from
	 * $this->options insertion order.
	 *
	 * @return string[]
	 */
	private function get_groups() {
		$groups = array();
		foreach ( $this->options as $option ) {
			$group = $option->get_group();
			if ( ! in_array( $group, $groups, true ) ) {
				$groups[] = $group;
			}
		}
		return $groups;
	}

	/** Badge map for option rows (design-layer only, not part of the options-matrix).
	 *
	 * @return array<string, array{class: string, text: string}>
	 */
	private function get_badge_map() {
		$warn = array(
			'class' => 'gdpr-badge gdpr-badge-warn',
			'text'  => __( 'Can lock out visitors', 'gdpr-compliant-recaptcha-for-all-forms' ),
		);
		return array(
			Option::POW_BLOCK                      => $warn,
			Option::POW_BLOCK_LOGIN                => $warn,
			Option::POW_ABILITIES_WRITE            => array(
				'class' => 'gdpr-badge gdpr-badge-warn',
				'text'  => __( 'Agent can change monitoring', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
			Option::POW_ABILITIES_READ_SUBMISSIONS => array(
				'class' => 'gdpr-badge gdpr-badge-warn',
				'text'  => __( 'Submissions can leave your site', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
			Option::POW_ABILITIES_UNSAFE           => array(
				'class' => 'gdpr-badge gdpr-badge-warn',
				'text'  => __( 'Agent can weaken protection', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
			// Static recommendation: there is no difficulty ceiling any more, so there
			// is nothing left to warn about here (the boost is never clipped).
			Option::POW_DIFFICULTY                 => array(
				'class' => 'gdpr-badge gdpr-badge-recommend',
				'text'  => __( 'Recommended: 15–16', 'gdpr-compliant-recaptcha-for-all-forms' ),
			),
		);
	}

	/** Allowlist shared by the header message and the per-option help popovers.
	 *
	 * @return array<string, array<string, array<int, string>>>
	 */
	private function get_allowed_html() {
		return array(
			'br'     => array(),
			'ol'     => array(),
			'ul'     => array(),
			'li'     => array(),
			'strong' => array(),
			'b'      => array(),
			'u'      => array(),
			'em'     => array(),
			'code'   => array(),
			'span'   => array( 'class' => array() ),
			'a'      => array(
				'href'  => array(),
				'title' => array(),
			),
		);
	}

	/** Renders the review/FAQ header line, escaped via wp_kses with a tight allowlist. */
	private function render_header_message() {
		$review_link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( 'https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/reviews/#new-post' ),
			esc_html__( 'Help us and rate it', 'gdpr-compliant-recaptcha-for-all-forms' )
		);
		$faq_link    = sprintf(
			'<a href="%s">%s</a>',
			esc_url( 'https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/' ),
			esc_html__( 'Get help in the support forum', 'gdpr-compliant-recaptcha-for-all-forms' )
		);

		$message1 = sprintf(
			/* translators: 1: checkmark icon, 2,3: line breaks */
			__( '%1$s The plugin is now active on all of your forms and logins.%2$s%3$s', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'<span class="large-checkmark">&#10003;</span>',
			'<br>',
			'<br>'
		);
		$message2 = sprintf(
			/* translators: 1: smiley icon, 2: review link, 3,4: line breaks, 5: thinking-smiley icon, 6: FAQ link */
			__( '%1$s Happy with the plugin? %2$s %3$s%4$s %5$s Problems, questions, hints, improvements? %6$s', 'gdpr-compliant-recaptcha-for-all-forms' ),
			'<span class="large-smiley">&#128578;</span>',
			$review_link,
			'<br>',
			'<br>',
			'<span class="large-smiley">&#129300;</span>',
			$faq_link
		);

		echo wp_kses( $message1 . $message2, $this->get_allowed_html() );
	}

	/** Renders one option row: label, optional badge, optional short description,
	 * control, help toggle + popover.
	 *
	 * @param string $key
	 * @param Option $option
	 */
	private function render_option_row( $key, Option $option ) {
		$badge_map = $this->get_badge_map();
		$short     = $option->get_short();
		?>
		<div class="gdpr-option-row">
			<div class="gdpr-option-main">
				<label class="gdpr-option-label" for="<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $option->get_name() ); ?></label>
				<?php if ( isset( $badge_map[ $key ] ) ) : ?>
					<span class="<?php echo esc_attr( $badge_map[ $key ]['class'] ); ?>"><?php echo esc_html( $badge_map[ $key ]['text'] ); ?></span>
				<?php endif; ?>
				<?php if ( '' !== $short ) : ?>
					<p class="gdpr-option-short"><?php echo esc_html( $short ); ?></p>
				<?php endif; ?>
			</div>
			<div class="gdpr-option-control">
				<?php $this->render_control( $key, $option ); ?>
				<button type="button" class="gdpr-help-toggle" aria-expanded="false" aria-controls="help_<?php echo esc_attr( $key ); ?>">?</button>
				<div class="gdpr-help-popover" id="help_<?php echo esc_attr( $key ); ?>" hidden>
					<?php echo wp_kses( $option->get_hint(), $this->get_allowed_html() ); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/** Renders the input control for one option, by type.
	 *
	 * @param string $key
	 * @param Option $option
	 */
	private function render_control( $key, Option $option ) {
		$type = $option->get_type();
		$val  = $option->get_value();

		if ( Option::BOOL === $type ) {
			?>
			<label class="gdpr-toggle">
				<input type="checkbox" name="<?php echo esc_attr( $key ); ?>" id="<?php echo esc_attr( $key ); ?>" <?php checked( (bool) $val ); ?> />
				<span class="gdpr-toggle-slider"></span>
			</label>
			<?php
		} elseif ( Option::INT === $type ) {
			?>
			<input type="number" name="<?php echo esc_attr( $key ); ?>" class="regular-text" id="<?php echo esc_attr( $key ); ?>" value="<?php echo esc_attr( $val ); ?>" />
			<?php
		} elseif ( Option::STRING === $type ) {
			?>
			<input type="text" name="<?php echo esc_attr( $key ); ?>" class="regular-text" id="<?php echo esc_attr( $key ); ?>" value="<?php echo esc_attr( $val ); ?>" />
			<?php
		} elseif ( Option::TEXT === $type ) {
			?>
			<textarea name="<?php echo esc_attr( $key ); ?>" class="regular-text" id="<?php echo esc_attr( $key ); ?>"><?php echo esc_textarea( $val ); ?></textarea>
			<?php
		} elseif ( Option::ROLE_DROPDOWN === $type ) {
			// ROLE_DROPDOWN branch kept functional though unused by the current
			// options-matrix (see SETTINGS_MODERNIZE_PLAN.md).
			$selected_roles = (array) $val;
			$all_roles      = get_editable_roles();
			?>
			<select name="<?php echo esc_attr( $key ); ?>[]" id="<?php echo esc_attr( $key ); ?>" multiple="multiple">
				<?php foreach ( $all_roles as $role_key => $role ) : ?>
					<option value="<?php echo esc_attr( $role_key ); ?>" <?php selected( in_array( $role_key, $selected_roles, true ) ); ?>>
						<?php echo esc_html( $role['name'] ); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<?php
		}
	}

	/**
	 * Drawing the options page for the plugin: status strip, pill tabs and one
	 * card per group, all rendered directly (no WP-Settings-API indirection).
	 */
	public function options_page() {
		$groups  = $this->get_groups();
		$tab_ids = array();
		foreach ( $groups as $group ) {
			$tab_ids[] = 'gdpr-tab-' . sanitize_title( $group );
		}
		// The one panel that is NOT derived from an option group: three ACTIONS with a
		// live state and no stored value (self-test, and the two diagnostic resets).
		// They used to hang above the tabs as loose forms, which is exactly what made
		// the head of this page look like a junk drawer. get_groups() stays purely
		// option-derived; only this method knows about the extra tab — and $tab_ids must
		// carry it too, or a save from this tab bounces the admin back to the first one.
		$tab_ids[] = self::TAB_DIAGNOSTICS;

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- read-only: only re-selects the active pill tab for display (sanitize_key()'d, no state change); the actual save path in update_settings() already verifies gdpr_settings_nonce before writing anything.
		$requested_tab = isset( $_POST['gdpr-settings-selection'] ) ? sanitize_key( wp_unslash( $_POST['gdpr-settings-selection'] ) ) : '';
		// $tab_ids is never empty since the Diagnostics tab is appended unconditionally,
		// so the first entry always exists — no isset() dance needed any more.
		$active_tab = in_array( $requested_tab, $tab_ids, true ) ? $requested_tab : $tab_ids[0];
		?>
		<div class="wrap gdpr-settings-wrap">
			<h1><?php echo esc_html( $this->plugin_name . ' - ' . __( 'Settings', 'gdpr-compliant-recaptcha-for-all-forms' ) ); ?></h1>
			<?php $this->render_header_message(); ?>
			<?php $this->render_status_strip(); ?>
			<nav class="gdpr-pill-tabs">
				<?php foreach ( $groups as $group ) : ?>
					<?php
					$tab_id    = 'gdpr-tab-' . sanitize_title( $group );
					$is_active = ( $tab_id === $active_tab );
					?>
					<button type="button" class="gdpr-pill-tab<?php echo $is_active ? ' is-active' : ''; ?>" data-tab-target="<?php echo esc_attr( $tab_id ); ?>"><?php echo esc_html( $group ); ?></button>
				<?php endforeach; ?>
				<button type="button" class="gdpr-pill-tab<?php echo self::TAB_DIAGNOSTICS === $active_tab ? ' is-active' : ''; ?>" data-tab-target="<?php echo esc_attr( self::TAB_DIAGNOSTICS ); ?>"><?php esc_html_e( 'Diagnostics', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></button>
			</nav>
			<form class="gdpr-settings-form" method="post" action="<?php echo esc_attr( Option::PAGE_QUERY ); ?>">
				<?php wp_nonce_field( 'gdpr_settings_nonce', 'gdpr_settings_nonce_field' ); // CSRF-protection add ?>
				<input type="hidden" name="<?php echo esc_attr( self::RCM_ACTION ); ?>" value="<?php echo esc_attr( self::UPDATE ); ?>">
				<input type="hidden" id="gdpr-settings-selection" name="gdpr-settings-selection" value="<?php echo esc_attr( $active_tab ); ?>">
				<?php
				// Inside the form, and above the tabs: the confirmation for an over-broad
				// pattern this request refused to store yet. It has to sit inside the form
				// because it carries a checkbox and a hidden field; the settings-error
				// message that names the lines renders above the form and cannot.
				// No-op whenever there is nothing to confirm.
				Overbroad_Pattern_Guard::render_confirmation_block( $this->pending_pattern_lines );
				// Same for a blocked-value RULE that would discard a whole form. Its own
				// block with its own checkbox, so one save can hold back both textareas and
				// the operator confirms each on its own merits.
				Overbroad_Pattern_Guard::render_blocklist_confirmation_block( $this->pending_blocked_lines );
				?>
				<?php foreach ( $groups as $group ) : ?>
					<?php
					$tab_id    = 'gdpr-tab-' . sanitize_title( $group );
					$is_active = ( $tab_id === $active_tab );
					?>
					<section class="gdpr-tab-panel" id="<?php echo esc_attr( $tab_id ); ?>"<?php echo $is_active ? '' : ' hidden'; ?>>
						<div class="gdpr-card">
							<?php
							foreach ( $this->options as $key => $option ) {
								if ( $option->get_group() === $group ) {
									$this->render_option_row( $key, $option );
								}
							}
							?>
						</div>
					</section>
				<?php endforeach; ?>
				<?php $this->render_diagnostics_panel( self::TAB_DIAGNOSTICS === $active_tab ); ?>
				<div id="submit-container">
					<?php submit_button(); ?>
				</div>
			</form>
		</div>
		<?php
	}

	/** The Diagnostics panel: actions, not settings.
	 *
	 * Same grammar as render_option_row() — label + one-line description on the left,
	 * control on the right, the long explanation behind the same `?` popover — because
	 * those long sentences standing in the open above the tabs were the actual eyesore.
	 * Two things an option row does not have: a live VALUE the action operates on (shown
	 * next to the button, so "what will this do" is answered before the click), and a
	 * full-width RESULT area under the row, since a self-test verdict is several
	 * sentences and must not be squeezed into the control column.
	 *
	 * Every button here is type="button" on purpose: the panel sits inside the settings
	 * form, so a forgotten type would turn a diagnostic click into a settings save.
	 *
	 * @param bool $is_active Whether this panel is the visible one.
	 * @return void
	 */
	private function render_diagnostics_panel( $is_active ) {
		$fp_share   = Option::fp_mismatch_share(
			get_option( Option::POW_FP_MATCHED_TOTAL, 0 ),
			get_option( Option::POW_FP_MISMATCHED_TOTAL, 0 )
		);
		$echo_count = Echo_Store::count();
		$diag_nonce = wp_create_nonce( self::AJAX_DIAG_TASK );
		?>
	<section class="gdpr-tab-panel" id="<?php echo esc_attr( self::TAB_DIAGNOSTICS ); ?>"<?php echo $is_active ? '' : ' hidden'; ?>>
		<div class="gdpr-card">

			<div class="gdpr-option-row gdpr-action-row" id="gdpr-self-test">
				<div class="gdpr-option-main">
					<span class="gdpr-option-label"><?php esc_html_e( 'Self-test', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></span>
					<p class="gdpr-option-short"><?php esc_html_e( 'Runs the whole invisible check against your own site and answers in one sentence.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></p>
				</div>
				<div class="gdpr-option-control">
					<button type="button" class="button button-secondary" id="gdpr-self-test-btn"
						data-nonce="<?php echo esc_attr( wp_create_nonce( self::AJAX_SELF_TEST ) ); ?>"
						data-running="<?php esc_attr_e( 'Testing…', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>"
						data-failed="<?php esc_attr_e( 'The test itself could not be run. Reload the page and try again.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>"
							data-verdict-ok="<?php esc_attr_e( 'Everything works', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>"
							data-verdict-problem="<?php esc_attr_e( 'Something is wrong', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>">
						<?php esc_html_e( 'Run self-test', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					</button>
					<button type="button" class="gdpr-help-toggle" aria-expanded="false" aria-controls="help_gdpr_self_test">?</button>
					<div class="gdpr-help-popover" id="help_gdpr_self_test" hidden>
						<?php esc_html_e( 'Fetches a puzzle from this site, solves it and hands it back in — exactly the handshake a visitor\'s browser performs. It says whether that works and, if not, what to do about it. This is the first thing to run when submissions are being flagged as spam.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					</div>
				</div>
				<div class="gdpr-action-result" id="gdpr-self-test-result" hidden></div>
			</div>

			<div class="gdpr-option-row gdpr-action-row" data-diag-task="reset_fp">
				<div class="gdpr-option-main">
					<span class="gdpr-option-label"><?php esc_html_e( 'Address measurement', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></span>
					<p class="gdpr-option-short"><?php esc_html_e( 'How often a solved puzzle came back from a different address than it was handed to — the sign of a cache or proxy in front of your site.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></p>
				</div>
				<div class="gdpr-option-control">
					<span class="gdpr-action-value" data-diag-value="fp">
						<?php
						echo esc_html(
							$fp_share['total'] > 0
								/* translators: 1: percentage from another address, 2: number of measured puzzles */
								? sprintf( __( '%1$d%% of %2$d measured', 'gdpr-compliant-recaptcha-for-all-forms' ), $fp_share['percent'], $fp_share['total'] )
								: __( 'nothing measured yet', 'gdpr-compliant-recaptcha-for-all-forms' )
						);
						?>
					</span>
					<button type="button" class="button button-secondary" data-diag-run="reset_fp"
						data-nonce="<?php echo esc_attr( $diag_nonce ); ?>"
						<?php disabled( 0, $fp_share['total'] ); ?>>
						<?php esc_html_e( 'Reset', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					</button>
					<button type="button" class="gdpr-help-toggle" aria-expanded="false" aria-controls="help_gdpr_reset_fp">?</button>
					<div class="gdpr-help-popover" id="help_gdpr_reset_fp" hidden>
						<?php esc_html_e( 'Each puzzle is handed to one visitor and solved a moment later. This measures how often the solution comes back from a different IP address than the puzzle went to. Submissions are accepted either way — a high share simply means a cache or proxy sits in front of your site, or the visitor\'s address changes between requests. If it is high, check the "Trusted proxies" setting. Resetting starts a fresh measurement, e.g. after changing that setting.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					</div>
				</div>
				<div class="gdpr-action-result" hidden></div>
			</div>

			<?php // The `id` is a deep-link target: a message blocked as "Known spam value" links straight here (Message_Page::render_message()). Pinned in EchoLockLinkWiringTest. ?>
			<div class="gdpr-option-row gdpr-action-row" id="gdpr-reset-echo" data-diag-task="reset_echo">
				<div class="gdpr-option-main">
					<span class="gdpr-option-label"><?php esc_html_e( 'Repeat-sender lock', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></span>
					<p class="gdpr-option-short"><?php esc_html_e( 'Values from recent spam, briefly remembered as one-way hashes so the same sender is caught again on any form.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?></p>
				</div>
				<div class="gdpr-option-control">
					<span class="gdpr-action-value" data-diag-value="echo">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %d: number of values currently held in the repeat-sender lock */
								_n( '%d value held', '%d values held', $echo_count, 'gdpr-compliant-recaptcha-for-all-forms' ),
								$echo_count
							)
						);
						?>
					</span>
					<button type="button" class="button button-secondary" data-diag-run="reset_echo"
						data-nonce="<?php echo esc_attr( $diag_nonce ); ?>"
						data-confirm="<?php esc_attr_e( 'Release all held values?', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>"
						data-confirm-yes="<?php esc_attr_e( 'Release', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>"
						data-confirm-no="<?php esc_attr_e( 'Cancel', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>"
						<?php disabled( 0, $echo_count ); ?>>
						<?php esc_html_e( 'Release', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					</button>
					<button type="button" class="gdpr-help-toggle" aria-expanded="false" aria-controls="help_gdpr_reset_echo">?</button>
					<div class="gdpr-help-popover" id="help_gdpr_reset_echo" hidden>
						<?php esc_html_e( 'The repeat-sender lock briefly remembers values from spam submissions (as one-way hashes) so the same sender is caught again on any form. Releasing frees every value it currently holds at once — use it if a legitimate sender got caught. No data is lost, and the lock rebuilds itself as new spam arrives.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
					</div>
				</div>
				<div class="gdpr-action-result" hidden></div>
			</div>

		</div>
	</section>
		<?php
	}

	/**
	 * Run one of the two diagnostic resets and answer with the FRESH value, so the row
	 * can update itself — the changed number is the success feedback, no toast needed.
	 *
	 * Admin-only and nonce-guarded, like the self-test: one of these clears a spam
	 * defence, which is nothing a stranger who knows an action name may trigger.
	 *
	 * @return void
	 */
	public function diag_task_callback() {
		$nonce = isset( $_POST['security_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['security_nonce'] ) ) : '';
		$task  = isset( $_POST['task'] ) ? sanitize_key( wp_unslash( $_POST['task'] ) ) : '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $nonce, self::AJAX_DIAG_TASK ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		if ( 'reset_fp' === $task ) {
			delete_option( Option::POW_FP_MATCHED_TOTAL );
			delete_option( Option::POW_FP_MISMATCHED_TOTAL );
			delete_option( Option::POW_FP_LAST_MISMATCH_AT );

			wp_send_json_success(
				array(
					'value'   => __( 'nothing measured yet', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'message' => __( 'Measurement restarted.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'empty'   => true,
				)
			);
		}

		if ( 'reset_echo' === $task ) {
			Echo_Store::clear();

			wp_send_json_success(
				array(
					'value'   => sprintf(
						/* translators: %d: number of values currently held in the repeat-sender lock */
						_n( '%d value held', '%d values held', 0, 'gdpr-compliant-recaptcha-for-all-forms' ),
						0
					),
					'message' => __( 'All held values released.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					'empty'   => true,
				)
			);
		}

		wp_send_json_error( array( 'message' => __( 'Unknown task.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
	}
}
