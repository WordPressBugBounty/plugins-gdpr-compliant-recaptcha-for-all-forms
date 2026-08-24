<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Trait Settings_Save: update_settings() — die Persistenz der Einstellungsseite
 * samt ihrer drei Save-Guards (Selbst-Aussperrung ueber REST-Routen, ueberbreites
 * Feld-Muster, ueberbreite Blockregel) und der Wildcard-Monitoring-Notice.
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
trait Settings_Save {
	/** Updating the values for the options
	 *
	 */
	public function update_settings() {
		$post_action = strval( filter_input( INPUT_POST, self::RCM_ACTION, FILTER_SANITIZE_SPECIAL_CHARS ) );
		// If update and current user is allowed to manage options
		if ( self::UPDATE === $post_action && current_user_can( 'manage_options' ) ) {
			$hash  = null;
			$nonce = isset( $_POST['gdpr_settings_nonce_field'] ) ? sanitize_text_field( wp_unslash( $_POST['gdpr_settings_nonce_field'] ) ) : '';
			if ( '' === $nonce || ! wp_verify_nonce( $nonce, 'gdpr_settings_nonce' ) ) {
				wp_die( esc_html__( 'Security check failed. This request was blocked by an active CSRF protection mechanism. It may have been triggered by another webpage you recently visited or an unrelated browser tab. To resolve this issue, close untrusted sites, check browser extensions, and refresh your WordPress session by logging in again.', 'gdpr-compliant-recaptcha-for-all-forms' ) );
			}

			foreach ( $this->options as $key => $option ) {
				$type = $option->get_type();
				// Check if the input is an array or a single value
				$is_array = Option::ROLE_DROPDOWN === $type;

				if ( $is_array ) {
					// For arrays, filter as strings. The sanitized result MUST be
					// assigned back — array_map() does not mutate its input, so a bare
					// expression statement here silently threw the sanitization away
					// and update_option() below stored the raw filter_input() array
					// (PHPStan level 7, argument.type; found 2026-08-12, dead at the
					// time because no Option currently uses ROLE_DROPDOWN — but the
					// bug would reappear the moment one does).
					$post_value = filter_input( INPUT_POST, $key, FILTER_DEFAULT, FILTER_REQUIRE_ARRAY );
					$post_value = $post_value ? array_map( 'sanitize_text_field', $post_value ) : array();
				} elseif ( Option::TEXT === $type || Option::STRING === $type ) {
					$post_value = isset( $_POST[ $key ] ) ? wp_kses_post( wp_unslash( $_POST[ $key ] ) ) : null;
				} else {
					// For single values, apply the specified filter
					$post_value = filter_input( INPUT_POST, $key, $this->get_option_filter( $type ) );
				}

				// The fail2ban log path is a filesystem location the plugin writes to. On
				// multisite a plain site admin (manage_options) must not be able to aim it
				// at an arbitrary path — restrict that to super admins — and reject path
				// traversal on any install. An invalid value is left unchanged (the old
				// path stays), never silently redirected.
				if ( Option::POW_FAIL_2_BAN_PATH === $key && ! empty( $post_value )
					&& ( ( is_multisite() && ! is_super_admin() ) || 0 !== validate_file( (string) $post_value ) ) ) {
					continue;
				}

				// A REST-route line that covers one of WordPress' OWN namespaces is a
				// one-way door, not a typo the admin can walk back: POW_BLOCK is on by
				// default, so the block editor's own save (`/wp/v2/posts/<id>`) would be
				// discarded as spam — and wp-admin never receives the PoW script, so there
				// is no challenge to solve either. Only the database or FTP would get them
				// out. Such lines are dropped BEFORE storing and then NAMED to the admin
				// (never swallowed silently); everything else in the textarea is saved
				// normally. The decision itself is pure and unit-tested:
				// RestRoute::reject_self_lockout_lines() / tests/unit/RestRouteTest.php.
				// The gibberish selection is normally written by the per-field button, so a
				// line typed here is the exception — and the two ways it goes wrong are
				// both silent by nature: a line the parser cannot read simply disappears
				// from the rules, and a line naming a form that is no longer monitored
				// looks like a check while checking nothing (the same failure class as an
				// action name that was never registered, CLAUDE.md). Both are NAMED here
				// rather than swallowed. Nothing is dropped or rewritten: the operator's
				// text is stored as typed, this only tells him what it will do.
				if ( Option::POW_GIBBERISH_FIELDS === $key && is_string( $post_value ) ) {
					$unreadable = array();
					foreach ( preg_split( '/\r\n|\n|\r/', $post_value, -1, PREG_SPLIT_NO_EMPTY ) as $line ) {
						if ( '' !== trim( $line ) && ! Gibberish_Fields::parse_lines( $line ) ) {
							$unreadable[] = trim( $line );
						}
					}
					if ( ! empty( $unreadable ) ) {
						add_settings_error(
							Option::PREFIX . 'options',
							'gdpr-gibberish-unreadable',
							sprintf(
								/* translators: %s: the unreadable lines, comma separated */
								__( 'These gibberish lines do nothing, because they could not be read: %s. A line looks like <code>pattern {"_wpcf7":null} =&gt; your-message</code> — how the form is recognised, then <code>=&gt;</code>, then the field names.', 'gdpr-compliant-recaptcha-for-all-forms' ),
								// esc_html() because settings_errors() prints unescaped and
								// this interpolates text the administrator just typed —
								// same reason as the route guard below.
								esc_html( implode( ', ', $unreadable ) )
							),
							'error'
						);
					}
					$inactive = array();
					foreach ( Gibberish_Fields::parse_lines( $post_value ) as $rule ) {
						if ( ! Gibberish_Signature::is_active( $rule, get_option( Option::POW_EXPLICIT_ACTION ), get_option( Option::POW_PARAMETER_PATTERN ), get_option( Option::POW_REST_ROUTES ) ) ) {
							$inactive[] = $rule['signature'];
						}
					}
					if ( ! empty( $inactive ) ) {
						add_settings_error(
							Option::PREFIX . 'options',
							'gdpr-gibberish-inactive',
							sprintf(
								/* translators: %s: the signatures no longer monitored, comma separated */
								__( 'Saved, but these forms are not monitored at the moment, so nothing is checked for them: %s. Add them under Apply on pattern, Apply on ajax action or Apply on REST route first. (A broader entry may still cover the form — this check only looks for the exact line.)', 'gdpr-compliant-recaptcha-for-all-forms' ),
								esc_html( implode( ', ', $inactive ) )
							),
							'warning'
						);
					}
				}

				if ( Option::POW_REST_ROUTES === $key && is_string( $post_value ) ) {
					list( $post_value, $rejected_routes ) = RestRoute::reject_self_lockout_lines( $post_value );
					if ( ! empty( $rejected_routes ) ) {
						add_settings_error(
							Option::PREFIX . 'options',
							'gdpr-rest-routes-rejected',
							sprintf(
								/* translators: %s: the rejected route lines, comma separated */
								__( 'These REST route lines were not saved: %s. They would also cover WordPress\' own core routes, which would block your post saves and lock you out of wp-admin. All other lines were saved.', 'gdpr-compliant-recaptcha-for-all-forms' ),
								// esc_html() because settings_errors() prints its message
								// UNESCAPED — the string travels as ready-to-print HTML,
								// and what is interpolated here is text the administrator
								// just typed into a textarea. Same reason as
								// Overbroad_Pattern_Guard::warning_message().
								esc_html( implode( ', ', $rejected_routes ) )
							),
							'error'
						);
					}
				}

				// An over-broad FIELD pattern is the mirror image of the route guard above,
				// and it is deliberately NOT treated the same way: `{"email":null}` is a
				// plausible frontend catch-all on some sites, and the damage it does is
				// reversible by editing this very textarea. So it is not rejected — it is
				// held back ONCE, named, and stored on the next save if the administrator
				// confirms it. The whole decision (which lines, the confirmation, the hash
				// that binds it to them) lives in Overbroad_Pattern_Guard; what happens
				// here is the `continue`, i.e. "skip update_option() for this one key".
				// The submitted text is parked so the value-loading loop can render it
				// back — the input must not be lost over a warning.
				if ( Option::POW_PARAMETER_PATTERN === $key && is_string( $post_value ) ) {
					$flagged = Pattern_Matcher::overbroad_lines( $post_value );

					// Monitoring-vs-blocking notice (PLAN-BLOCKLIST-TRENNUNG.md AP3/§3.2).
					// Deliberately placed AFTER the overbroad detection line above, so the
					// overbroad guard's own decision — the `continue` a few lines below,
					// untouched — is computed first and never sees or is influenced by
					// this. It still has to run even when that guard is about to hold the
					// save back: a line the guard parks for now gets this note too, because
					// the note describes what the LINE MEANS (monitors, does not block),
					// never whether it made it into the database on this particular save.
					$new_wildcard_lines = $this->new_wildcard_monitor_lines( $post_value, (string) get_option( Option::POW_PARAMETER_PATTERN, '' ) );
					if ( ! empty( $new_wildcard_lines ) ) {
						add_settings_error(
							Option::PREFIX . 'options',
							'gdpr-pattern-wildcard-monitor',
							sprintf(
								/* translators: %s: the new {"*":"value"} lines, comma separated */
								__( 'These lines only monitor matching submissions, they do not block them: %s. To block a value outright, use the new "Blocked values" setting instead.', 'gdpr-compliant-recaptcha-for-all-forms' ),
								// Unescaped by settings_errors(), admin-typed input — same
								// reason as Overbroad_Pattern_Guard::warning_message() and
								// the REST-route/trusted-proxy guards above.
								esc_html( implode( ', ', $new_wildcard_lines ) )
							),
							'warning'
						);
					}

					if ( ! empty( $flagged ) && ! Overbroad_Pattern_Guard::confirmed( array_keys( $flagged ) ) ) {
						$this->pending_pattern_value = $post_value;
						$this->pending_pattern_lines = $flagged;
						add_settings_error(
							Option::PREFIX . 'options',
							'gdpr-pattern-overbroad',
							Overbroad_Pattern_Guard::warning_message( $flagged ),
							'error'
						);
						continue;
					}
				}

				// The blocklist's own version of that round trip. A line here may now be a
				// RULE ({"_wpcf7":"123","your-email":"@gmail.com"} — only this form, only
				// this field), and the dangerous shape is the one that names a form but
				// pins no value on a field people fill in: it discards everything that form
				// sends, while the very same line in the pattern box above merely watches
				// it. Held back once and named, never rejected — the decision is the
				// administrator's, only the silence is not. Which lines, and why, is decided
				// in Pattern_Matcher::overbroad_blocklist_lines(); the confirmation uses its
				// OWN checkbox, so confirming a pattern never confirms a block rule.
				if ( Option::POW_BLOCKED_VALUES === $key && is_string( $post_value ) ) {
					// A line that starts with "{" but is not a readable rule matches
					// nothing. Saved anyway (fail-open at match time is the only safe
					// direction for a blocklist typo) — but said out loud, because an
					// inert line that looks like a rule is exactly what sends an operator
					// debugging the wrong thing.
					$partition = Echo_Values::partition_blocklist_lines(
						(array) preg_split( "/\r\n|\n|\r/", $post_value )
					);
					if ( ! empty( $partition['invalid'] ) ) {
						add_settings_error(
							Option::PREFIX . 'options',
							'gdpr-blocked-values-invalid',
							sprintf(
								/* translators: %s: the unreadable blocklist lines, comma separated */
								__( 'These lines start with "{" but are not a readable rule, so they never match anything: %s. A rule is a JSON object with at least one condition, for example {"your-email":"@disposable.tld"}.', 'gdpr-compliant-recaptcha-for-all-forms' ),
								// Unescaped by settings_errors(), admin-typed input — same
								// reason as Overbroad_Pattern_Guard::warning_message().
								esc_html( implode( ', ', $partition['invalid'] ) )
							),
							'warning'
						);
					}

					// Readable, but impossible: a rule with an empty value condition
					// ({"message":""}) can never match, and neither of the other two
					// warnings sees it — it is valid JSON and it does pin a value. Left
					// unsaid it looks exactly like protection. Same warn-and-store
					// treatment as an unreadable line, for the same reason.
					$dead_rules = Pattern_Matcher::never_matching_blocklist_lines( $post_value );
					if ( ! empty( $dead_rules ) ) {
						add_settings_error(
							Option::PREFIX . 'options',
							'gdpr-blocked-values-never-match',
							sprintf(
								/* translators: %s: the blocklist rules that can never match, comma separated */
								__( 'These rules can never match, because they ask a field to hold an empty value: %s. If you meant "this field only has to be there", write null instead of "".', 'gdpr-compliant-recaptcha-for-all-forms' ),
								// Unescaped by settings_errors(), admin-typed input — same
								// reason as Overbroad_Pattern_Guard::warning_message().
								esc_html( implode( ', ', $dead_rules ) )
							),
							'warning'
						);
					}

					$flagged_rules = Pattern_Matcher::overbroad_blocklist_lines( $post_value, Echo_Store::site_domains() );
					if ( ! empty( $flagged_rules ) && ! Overbroad_Pattern_Guard::confirmed(
						array_keys( $flagged_rules ),
						Overbroad_Pattern_Guard::ACK_VALUE_FIELD,
						Overbroad_Pattern_Guard::ACK_VALUE_HASH_FIELD
					) ) {
						$this->pending_blocked_value = $post_value;
						$this->pending_blocked_lines = $flagged_rules;
						add_settings_error(
							Option::PREFIX . 'options',
							'gdpr-blocked-values-overbroad',
							Overbroad_Pattern_Guard::blocklist_warning_message( $flagged_rules ),
							'error'
						);
						continue;
					}
				}

				// A `/0` trusted-proxy line trusts every peer on the internet, which makes
				// every X-Forwarded-For believable and the resolved visitor address freely
				// choosable. ClientIp::matches_list() already refuses to honour one, so
				// the site is safe either way — but an entry that saves and then quietly
				// does nothing sends the operator debugging the wrong thing. Dropped
				// before storing and NAMED, exactly like the self-lockout route guard
				// above.
				if ( Option::POW_TRUSTED_PROXIES === $key && is_string( $post_value ) ) {
					list( $post_value, $rejected_ranges ) = ClientIp::reject_all_matching_ranges( $post_value );
					if ( ! empty( $rejected_ranges ) ) {
						add_settings_error(
							Option::PREFIX . 'options',
							'gdpr-trusted-proxies-rejected',
							sprintf(
								/* translators: %s: the rejected proxy lines, comma separated */
								__( 'These trusted-proxy lines were not saved: %s. A /0 range covers every address on the internet, which would make every visitor able to choose their own apparent address — defeating the IP whitelist, fail2ban logging and per-IP limits. Enter your proxy\'s actual address or subnet instead. All other lines were saved.', 'gdpr-compliant-recaptcha-for-all-forms' ),
								// Unescaped by settings_errors(), admin-typed input — see the
								// route guard above.
								esc_html( implode( ', ', $rejected_ranges ) )
							),
							'error'
						);
					}
				}

				if ( Option::BOOL === $type && ( null === $post_value || false === $post_value ) ) {
					// Checkbox unchecked: persist an explicit '0' instead of
					// delete_option(). Bestand: delete_option() + the options-matrix
					// default-fallback in prepare_options() made an unchecked
					// default-true option show as "on" again after saving, while the
					// runtime already read it as "off" via get_option() (no fallback
					// there) — a visible/actual state mismatch.
					update_option( $key, '0' );
				} elseif ( null !== $post_value && ( $is_array || false !== $post_value ) ) {
					update_option( $key, $post_value );

					if ( $is_array ) {
						$hash .= implode( '', $post_value );
					} elseif ( '_key' === substr( $key, -strlen( '_key' ) ) ) {
						$hash .= $post_value;
					}
				} else {
					delete_option( $key );
				}
			}
			// Add success message
			add_settings_error(
				Option::PREFIX . 'options',
				'my-plugin-success',
				__( 'Success! Your settings have been saved.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'updated'
			);
		}
	}

	/**
	 * PLAN-BLOCKLIST-TRENNUNG.md AP3/§3.2: which {"*":"value"} lines in the SUBMITTED
	 * Apply-on-pattern textarea are NEW — present now, absent (after trimming) from
	 * what was stored before this save. Only new lines are reported: a line that
	 * survives from an earlier save was already accepted as a monitoring line once
	 * and does not need repeating on every subsequent save.
	 *
	 * Pure line comparison — no field matching, no WordPress calls beyond none — so
	 * this cannot affect, and is not affected by, Pattern_Matcher::overbroad_lines()
	 * at the call site: same input, two independent readings of it.
	 *
	 * @param string $submitted The pattern textarea value exactly as posted.
	 * @param string $previous  The pattern option value as stored before this save.
	 * @return string[] Trimmed new {"*":"value"} lines, de-duplicated, in submission order.
	 */
	private function new_wildcard_monitor_lines( $submitted, $previous ) {
		$previous_lines = preg_split( "/\r\n|\n|\r/", $previous );
		$previous_lines = false === $previous_lines ? array() : array_map( 'trim', $previous_lines );

		$submitted_lines = preg_split( "/\r\n|\n|\r/", $submitted );
		$submitted_lines = false === $submitted_lines ? array() : $submitted_lines;

		$new_lines = array();
		foreach ( $submitted_lines as $raw_line ) {
			$trimmed = trim( $raw_line );
			if ( '' === $trimmed || in_array( $trimmed, $previous_lines, true ) ) {
				continue;
			}
			$decoded = json_decode( $trimmed, true );
			if ( is_array( $decoded ) && 1 === count( $decoded ) && array_key_exists( '*', $decoded )
				&& is_string( $decoded['*'] ) && '' !== trim( $decoded['*'] ) ) {
				$new_lines[] = $trimmed;
			}
		}
		return array_values( array_unique( $new_lines ) );
	}

	/** Filter special chars if not int
	 *
	 */
	private function get_option_filter( $type ) {
		$filter = '';
		if ( Option::INT === $type ) {
			$filter = FILTER_SANITIZE_NUMBER_INT;
		} elseif ( Option::BOOL === $type ) {
			$filter = FILTER_VALIDATE_BOOLEAN;
		} else {
			$filter = FILTER_SANITIZE_FULL_SPECIAL_CHARS;
		}
		return $filter;
	}
}
