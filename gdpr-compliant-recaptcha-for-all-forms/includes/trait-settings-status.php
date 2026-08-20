<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Status: die Status-Leiste am Kopf der Einstellungsseite
 * (Schutz-/Simulationszustand, effektive Difficulty, Wochen-Zaehler, Health-Zaehler,
 * Speicher-Fehlerfeld, aufgeloeste Admin-IP) und die drei Proxy-Hinweise darunter.
 * Die Logik des Proxy-Vorschlags selbst bleibt in class-settings-menu.php
 * (ProxyCandidateWiringTest pinnt sie dort).
 *
 * SCHNITTLINIE (Welle 3, PLAN-DATEIGROESSE.md): Settings_Menu war eine Datei mit
 * 2592 Zeilen. Sie ist entlang ihrer Sektionen aufgeteilt:
 *   - class-settings-menu.php             — Konstruktion, Hooks, Menue, Selbsttest,
 *                                           prepare_options() und der Proxy-Vorschlag.
 *   - trait-settings-default-actions.php  — get_default_ajax_actions() (handbuch/gate.md).
 *   - trait-settings-default-patterns.php — get_default_recognition_patterns() (handbuch/gate.md).
 *   - trait-settings-default-routes.php   — get_default_rest_routes() (handbuch/gate.md).
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
trait Settings_Status {
	/** Status strip: protection/simulation state, effective difficulty, under-attack
	 * flag, weekly spam count (see SETTINGS_MODERNIZE_PLAN.md "Status-Leiste").
	 */
	private function render_status_strip() {
		$simulate        = get_option( Option::POW_SIMULATE_SPAM );
		$base_difficulty = (int) get_option( Option::POW_DIFFICULTY );
		// Same gate as Stamp::get_stamp(): the boost only applies while the
		// under-attack option is enabled (explicit `true` fallback, see there).
		$under_attack   = get_option( Option::POW_UNDER_ATTACK_MODE, true ) && Stamp::is_under_attack();
		$effective      = ProofOfWork::effective_difficulty( $base_difficulty, $under_attack, Stamp::UNDER_ATTACK_BONUS );
		$spam_this_week = Option::count_messages_since_days( 2, 7 );

		$items = array();

		if ( $simulate ) {
			$items[] = array(
				'class' => 'gdpr-status-amber',
				'text'  => __( 'Simulation mode active', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		} else {
			$items[] = array(
				'class' => 'gdpr-status-green',
				'text'  => __( 'Protection active', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		if ( $under_attack ) {
			$items[] = array(
				'class' => '',
				'text'  => sprintf(
					/* translators: 1: base difficulty, 2: applied under-attack bonus */
					__( 'Difficulty %1$d +%2$d (under attack)', 'gdpr-compliant-recaptcha-for-all-forms' ),
					$base_difficulty,
					$effective - $base_difficulty
				),
			);
			$items[] = array(
				'class' => 'gdpr-status-amber',
				'text'  => __( 'Under attack', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		} else {
			$items[] = array(
				'class' => '',
				/* translators: %d: configured difficulty */
				'text'  => sprintf( __( 'Difficulty %d', 'gdpr-compliant-recaptcha-for-all-forms' ), $base_difficulty ),
			);
		}

		// WHICH ADDRESS DOES THE PLUGIN ACTUALLY BIND? Answering that used to require
		// opening the network tab, and it is the first question in nearly every
		// proxy/cache support case (whitelist has no effect, fail2ban logs the wrong
		// address, every visitor counts as one). Now it is a line on the strip, with the
		// SOURCE named — the address alone does not say whether it was believed.
		//
		// Privacy: this is the address of the logged-in administrator reading the page,
		// shown only to them, and nothing is stored. Different situation entirely from
		// the token fingerprint, which has to be address-free because the page it sits
		// in is cacheable and shared between visitors.
		$items[] = array(
			'class' => '',
			'text'  => sprintf(
				/* translators: 1: resolved client IP address, 2: where it came from */
				__( 'Your address: %1$s (%2$s)', 'gdpr-compliant-recaptcha-for-all-forms' ),
				Stamp::resolve_client_ip(),
				self::client_ip_source()
			),
		);

		// Quarantine is gated on the raw wave detection (Stamp::is_under_attack()),
		// independent of POW_UNDER_ATTACK_MODE (which only gates the difficulty boost
		// above) — so it can be actively sorting even when $under_attack is false here.
		// Surface a subtle hint only while it is actually acting (option on + wave +
		// not simulating, mirroring the check_submit() gate).
		if ( ! $simulate && get_option( Option::POW_UNDER_ATTACK_QUARANTINE ) && Stamp::is_under_attack() ) {
			$items[] = array(
				'class' => '',
				'text'  => __( 'Quarantine active', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		$items[] = array(
			'class' => '',
			/* translators: %d: number of spam messages blocked in the last 7 days */
			'text'  => sprintf( __( '%d spam blocked this week', 'gdpr-compliant-recaptcha-for-all-forms' ), $spam_this_week ),
		);

		// Health counter: submissions whose classification reason was "no usable stamp
		// row" (no_pow:*) in the last 24h — the fingerprint of a broken client-PoW
		// pipeline (HANDBUCH §12). Amber above the threshold; the decision itself is the
		// pure Option::health_counter_status().
		$no_pow_count  = Option::no_pow_health_count();
		$no_pow_status = Option::health_counter_status( $no_pow_count, Option::HEALTH_NO_POW_WARN_THRESHOLD );
		$items[]       = array(
			'class' => $no_pow_status['class'],
			'text'  => sprintf(
				/* translators: %d: number of submissions in the last 24 hours that had no usable proof-of-work stamp */
				_n( '%d submission without a stamp row (24h)', '%d submissions without a stamp row (24h)', $no_pow_count, 'gdpr-compliant-recaptcha-for-all-forms' ),
				$no_pow_count
			),
		);

		// Storage alarm: the server accepted a proof of work and could NOT write its row
		// (Stamp::record_store_failure()). This is the only state in which everything else
		// on this page looks healthy while literally every submission is classified spam —
		// so it gets its own red item plus the database error underneath the strip.
		$store_failures = (int) get_option( Option::POW_STORE_FAILED_TOTAL, 0 );
		$store_status   = Option::store_failure_status(
			$store_failures,
			(int) get_option( Option::POW_STORE_LAST_FAILED_AT, 0 ),
			time()
		);
		if ( $store_status['show'] ) {
			$items[] = array(
				'class' => $store_status['class'],
				'text'  => __( 'Solved puzzles cannot be stored', 'gdpr-compliant-recaptcha-for-all-forms' ),
			);
		}

		?>
		<div class="gdpr-status-strip">
			<?php foreach ( $items as $item ) : ?>
				<span class="gdpr-status-item <?php echo esc_attr( $item['class'] ); ?>"><?php echo esc_html( $item['text'] ); ?></span>
			<?php endforeach; ?>
		</div>
		<?php if ( $store_status['show'] ) : ?>
			<p class="gdpr-store-failure-hint">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %d: how often a solved puzzle could not be written to the database */
						_n(
							'%d solved puzzle could not be written to the database. While this lasts, every submission is treated as spam — the check that protects your forms looks for exactly that stored puzzle.',
							'%d solved puzzles could not be written to the database. While this lasts, every submission is treated as spam — the check that protects your forms looks for exactly that stored puzzle.',
							$store_failures,
							'gdpr-compliant-recaptcha-for-all-forms'
						),
						$store_failures
					)
				);
				?>
				<?php $store_error = (string) get_option( Option::POW_STORE_LAST_ERROR, '' ); ?>
				<?php if ( '' !== $store_error ) : ?>
					<br><code><?php echo esc_html( $store_error ); ?></code>
				<?php endif; ?>
				<br><?php esc_html_e( 'Usually the plugin\'s own table is missing or the database is read-only. Deactivating and reactivating the plugin re-creates the table; if it comes back, your host has to look at the database user\'s write permissions. Once you have fixed it, run the self-test under Diagnostics — a green result clears this message.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
			</p>
		<?php endif; ?>
		<?php $this->render_proxy_hint(); ?>
		<?php $this->render_proxy_adopted_notice(); ?>
		<?php
	}

	/** Hint when THIS admin request arrived carrying forwarding headers while the
	 * trusted-proxy list is empty — i.e. the site very likely sits behind a proxy the
	 * plugin has not been told about, so every visitor is seen under the proxy's
	 * address (whitelist, fail2ban and per-IP limits then work on the wrong address).
	 *
	 * Read-only observation of the CURRENT request: only the presence of a header is
	 * evaluated, never its (client-settable) value, and nothing is stored. Only
	 * X-Forwarded-For is ever honored for resolution — the other names are listed
	 * because their presence is still evidence of a proxy hop.
	 *
	 * @return void
	 */
	private function render_proxy_hint() {
		if ( '' !== trim( (string) get_option( Option::POW_TRUSTED_PROXIES ) ) ) {
			return;
		}

		$present = array();
		foreach ( ClientIp::DIAGNOSTIC_HEADERS as $header_name ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- presence check only; the value is never read, stored or printed.
			if ( ! empty( $_SERVER[ $header_name ] ) ) {
				$present[] = str_replace( '_', '-', substr( $header_name, 5 ) );
			}
		}

		if ( empty( $present ) ) {
			return;
		}
		?>
		<p class="gdpr-echo-reset-hint">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %s: comma-separated list of forwarding header names seen on the current request */
					__( 'This request reached WordPress through a proxy (%s), but no trusted proxies are configured. Visitors are therefore all seen under the proxy\'s address, which affects the IP whitelist, fail2ban logging and per-IP limits. Enter the proxy address under "Trusted proxies" below. Only X-Forwarded-For is evaluated, and only from an address listed there.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					implode( ', ', $present )
				)
			);
			// The operator standing in front of this hint is precisely the one who often
			// cannot answer it: a managed host puts the proxy there and does not publish
			// its address. Naming the fallback here rather than only in the settings row
			// below is the difference between a hint and a dead end.
			if ( self::is_private_peer() ) {
				echo ' ';
				echo esc_html__( 'This request also came from a private network address, which normally means the proxy is your own hosting infrastructure. If you cannot find out its address, the "Trust a private-network proxy" setting below is the fallback — read what it costs before enabling it.', 'gdpr-compliant-recaptcha-for-all-forms' );
			}
			?>
		</p>
		<?php
		$this->render_proxy_suggestion();
	}

	/**
	 * The second half of the hint above: name the address and offer to enter it.
	 *
	 * THE PROPOSED ADDRESS IS REMOTE_ADDR — the peer this server actually talked to —
	 * and never an address parsed out of a forwarding header. Reason, in one line:
	 * POW_TRUSTED_PROXIES is matched against REMOTE_ADDR and the chain hops in
	 * ClientIp::resolve(), so the peer is structurally the value that belongs there; the
	 * header is only the EVIDENCE that a hop exists and is displayed as such. See
	 * class-proxy-candidate-ledger.php for the full argument, including why the counting
	 * ledger is a stability filter and not a defence against spoofing.
	 *
	 * @return void
	 */
	private function render_proxy_suggestion() {
		$ledger = Proxy_Candidate_Ledger::normalize( get_option( Option::POW_PROXY_CANDIDATE ) );
		if ( ! Proxy_Candidate_Ledger::is_ripe( $ledger, time() ) ) {
			return;
		}

		$span = Proxy_Candidate_Ledger::observed_span( $ledger );
		$link = wp_nonce_url(
			admin_url( 'options-general.php' . Option::PAGE_QUERY . '&' . self::ACTION_ADOPT_PROXY . '=' . rawurlencode( $ledger['ip'] ) ),
			self::ACTION_ADOPT_PROXY
		);
		?>
		<p class="gdpr-echo-reset-hint">
			<strong><?php echo esc_html( $ledger['ip'] ); ?></strong>
			<?php
			echo esc_html(
				sprintf(
					/* translators: 1: number of observations, 2: human-readable time span, e.g. "3 hours", 3: forwarding header name */
					_n(
						'is the address this server saw the connection come from — observed %1$d time over %2$s, each time with a %3$s header carrying a public address. It is not taken from that header: the header only shows that a proxy is in front of you.',
						'is the address this server saw the connection come from — observed %1$d times over %2$s, each time with a %3$s header carrying a public address. It is not taken from that header: the header only shows that a proxy is in front of you.',
						$ledger['count'],
						'gdpr-compliant-recaptcha-for-all-forms'
					),
					$ledger['count'],
					human_time_diff( 0, $span ),
					'' !== $ledger['header'] ? $ledger['header'] : 'X-Forwarded-For'
				)
			);
			?>
			<br>
			<?php esc_html_e( 'Add it only if it really is your own reverse proxy or load balancer. Trusting an address means the plugin believes the X-Forwarded-For header it sends, and from then on that header decides which visitor an IP whitelist entry, a fail2ban ban and a per-IP limit apply to.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
			<br>
			<a class="button button-secondary" href="<?php echo esc_url( $link ); ?>">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: the proposed proxy IP address */
						__( 'Add %s to trusted proxies', 'gdpr-compliant-recaptcha-for-all-forms' ),
						$ledger['ip']
					)
				);
				?>
			</a>
		</p>
		<?php
	}

	/**
	 * Confirmation that the address was entered — shown once, after the redirect.
	 *
	 * Needed because the hint that carried the button disappears the moment the address
	 * is stored (a non-empty trusted-proxy list ends render_proxy_hint() at its first
	 * line). Without a word here, the one-click would look like it did nothing.
	 *
	 * @return void
	 */
	private function render_proxy_adopted_notice() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only: decides whether one sentence is printed; the state change happened in maybe_adopt_proxy_candidate(), which verifies capability and nonce.
		if ( ! isset( $_GET[ self::ARG_PROXY_ADOPTED ] ) ) {
			return;
		}
		?>
		<p class="gdpr-echo-reset-hint">
			<?php esc_html_e( 'The proxy address was added to "Trusted proxies". Visitor addresses now come from the X-Forwarded-For header that proxy sends — check the address shown above to confirm it is what you expect, and remove the entry again if it is not.', 'gdpr-compliant-recaptcha-for-all-forms' ); ?>
		</p>
		<?php
	}
}
