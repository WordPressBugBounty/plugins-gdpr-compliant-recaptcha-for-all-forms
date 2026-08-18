<?php
/**
 * WordPress glue for the learned credential-field list: how entries get there.
 *
 * The list itself is trivial; the question this class answers is the one the
 * design turned on — HOW IT GETS MAINTAINED, so it does not stay empty. Three
 * paths, in this order of importance:
 *
 *  (a) PRIMARY, and the only one that scales: observe(). Every submission that
 *      ran the plugin's JS carries `hashPWFields`, i.e. the names of the real
 *      `input[type=password]` fields. A marker path that neither the heuristic
 *      nor the learned list recognises is the evidence "this form has a password
 *      field with an inconspicuous name". The name — never a value — becomes a
 *      proposal, surfaced as a dismissible admin notice with a one-click add,
 *      exactly like Scope_Sync does it: the plugin proposes, the admin confirms.
 *      Submissions WITH JS thereby protect the later ones WITHOUT it.
 *  (b) RESCUE: the "Treat as credential field" button on the message detail view
 *      (Message_Page::render_message() renders it, ajax_treat_as_credential()
 *      handles it). For when a password is already sitting readable in the
 *      inbox — it adds the name AND redacts that message immediately.
 *  (c) TRANSPARENCY: the plain settings field (POW_CREDENTIAL_FIELDS) for
 *      reviewing, removing and manually adding. Explicitly NOT the main door.
 *
 * THE ABUSE CASE, which is what this class is really written around: the
 * proposal channel is fed from UNAUTHENTICATED request data. Anyone can post a
 * forged `hashPWFields` claiming `email` or `message` is a password field; an
 * admin who confirms that out of notice fatigue blinds their own inbox. Hence:
 * never an automatic add (nothing writes POW_CREDENTIAL_FIELDS outside the two
 * capability- and nonce-gated handlers below), diagnostic names suppressed
 * before they can ever be rendered as a button, one proposal per name ever, and
 * the notice showing its evidence (name, referring site, how often seen) so the
 * decision can be made instead of guessed.
 *
 * Pure parts live in Learned_Credential_Fields (format/matching/arming) and
 * Credential_Suggestion_Ledger (dedup/state) and are unit-tested there; what is
 * left here is options, notices, nonces and one ajax handler.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/credentials.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Proposal notice, one-click confirmation and the learned-list accessor.
 */
final class Credential_Learning {

	/** Query arg + nonce action of the one-click add (the name is bound into the nonce). */
	private const ACTION_ADD = 'gdpr_pow_credential_add';

	/** Query arg + nonce action of the dismiss link. */
	private const ACTION_DISMISS = 'gdpr_pow_credential_dismiss';

	/** Ajax action of the message-inbox rescue button. */
	public const AJAX_ACTION = 'gdpr_credential_field';

	/** Nonce action prefix of the rescue button (the message type is appended). */
	public const AJAX_NONCE = 'gdpr_credential_field_';

	/** Most proposals rendered in one notice — the rest follow once these are settled. */
	private const NOTICE_LIMIT = 3;

	public function __construct() {
		add_action( 'admin_init', array( $this, 'handle_actions' ), 5 );
		add_action( 'admin_notices', array( $this, 'render_notices' ) );
		add_action( 'wp_ajax_' . self::AJAX_ACTION, array( $this, 'ajax_treat_as_credential' ) );
	}

	/**
	 * The learned names, normalised. One cached get_option() on an autoloaded
	 * option — cheap enough for the persistence path of every submission.
	 *
	 * @return string[]
	 */
	public static function learned_names(): array {
		return Learned_Credential_Fields::parse_list( get_option( Option::POW_CREDENTIAL_FIELDS, '' ) );
	}

	/**
	 * Record proposals for password fields whose names nothing recognises yet.
	 *
	 * Called from Stamp::save_message() with the already-decoded marker paths, so
	 * it costs nothing at all when the submission carries no marker (the common
	 * case). It NEVER writes POW_CREDENTIAL_FIELDS — see the class docblock.
	 *
	 * @param array    $marker_paths  Paths from Credential_Fields::marker_paths_from_raw().
	 * @param string[] $learned_names Currently learned names.
	 */
	public static function observe( array $marker_paths, array $learned_names ): void {
		if ( 0 === count( $marker_paths ) ) {
			return;
		}

		$candidates = Learned_Credential_Fields::candidates_from_marker_paths( $marker_paths, $learned_names );
		if ( 0 === count( $candidates ) ) {
			return;
		}

		$ledger  = Credential_Suggestion_Ledger::normalize( get_option( Option::POW_CREDENTIAL_SUGGESTIONS ) );
		$updated = Credential_Suggestion_Ledger::record( $ledger, $candidates, self::from_site() );

		// Only write on a real change: a settled name seen a thousand times more
		// must not cost a thousand option writes.
		if ( $updated !== $ledger ) {
			update_option( Option::POW_CREDENTIAL_SUGGESTIONS, $updated, true );
		}
	}

	/**
	 * Referring site as evidence for the notice (same shape save_message() stores
	 * as `from_site`). Evidence only — nothing is matched against it.
	 *
	 * @return string
	 */
	private static function from_site(): string {
		if ( ! isset( $_SERVER['HTTP_REFERER'] ) ) {
			return '';
		}
		$referer = sanitize_text_field( wp_unslash( $_SERVER['HTTP_REFERER'] ) );
		return (string) preg_replace( '/^(https?:\/\/)/i', '', $referer );
	}

	/**
	 * Add a name to the learned list and settle its proposal.
	 *
	 * The ONE place the list grows. Both callers are capability- and nonce-gated.
	 * The retroactive cleanup needs no call here: it compares a hash of this list
	 * against the set it has already swept and re-arms itself on the next load
	 * (Credential_Cleanup::maybe_run()), which also covers a manual edit on the
	 * settings page.
	 *
	 * @param mixed $name Candidate name.
	 * @return string|null The stored name, or null when it was not usable.
	 */
	private static function add_learned( $name ): ?string {
		$normalized = Learned_Credential_Fields::normalize_name( $name );
		if ( null === $normalized || Learned_Credential_Fields::is_diagnostic_name( $normalized ) ) {
			return null;
		}

		$names = self::learned_names();
		if ( ! in_array( $normalized, $names, true ) ) {
			if ( count( $names ) >= Learned_Credential_Fields::MAX_LIST_SIZE ) {
				return null;
			}
			$names[] = $normalized;
			update_option( Option::POW_CREDENTIAL_FIELDS, Learned_Credential_Fields::to_lines( $names ) );
		}

		self::settle( array( $normalized ), Credential_Suggestion_Ledger::STATE_ADDED );

		return $normalized;
	}

	/**
	 * Move ledger entries into a settled state (added/dismissed): they are never
	 * proposed again, whatever a later request claims.
	 *
	 * @param string[] $names Names.
	 * @param string   $state Target state.
	 */
	private static function settle( array $names, string $state ): void {
		$ledger  = Credential_Suggestion_Ledger::normalize( get_option( Option::POW_CREDENTIAL_SUGGESTIONS ) );
		$updated = Credential_Suggestion_Ledger::mark( $ledger, $names, $state );
		if ( $updated !== $ledger ) {
			update_option( Option::POW_CREDENTIAL_SUGGESTIONS, $updated, true );
		}
	}

	/**
	 * Handle the notice's add/dismiss links.
	 *
	 * Both are capability-gated and nonce-bound TO THE NAME, and the add refuses
	 * any name that is not an open proposal — so a crafted link cannot smuggle in
	 * a name that was never seen (nor a diagnostic one, which never becomes a
	 * proposal in the first place).
	 */
	public function handle_actions(): void {
		if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the nonce is verified via check_admin_referer() below, before any state change; the value is only read to build the name-bound nonce action.
		if ( isset( $_GET[ self::ACTION_ADD ] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- see above.
			$name = Learned_Credential_Fields::normalize_name( sanitize_text_field( wp_unslash( $_GET[ self::ACTION_ADD ] ) ) );
			check_admin_referer( self::ACTION_ADD . '_' . (string) $name );

			$ledger = Credential_Suggestion_Ledger::normalize( get_option( Option::POW_CREDENTIAL_SUGGESTIONS ) );
			if ( null !== $name && Credential_Suggestion_Ledger::is_open( $ledger, $name ) ) {
				self::add_learned( $name );
			}
			self::redirect_clean();
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the nonce is verified via check_admin_referer() below, before any state change; the value is only read to build the name-bound nonce action.
		if ( isset( $_GET[ self::ACTION_DISMISS ] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- see above.
			$name = Learned_Credential_Fields::normalize_name( sanitize_text_field( wp_unslash( $_GET[ self::ACTION_DISMISS ] ) ) );
			check_admin_referer( self::ACTION_DISMISS . '_' . (string) $name );

			if ( null !== $name ) {
				self::settle( array( $name ), Credential_Suggestion_Ledger::STATE_DISMISSED );
			}
			self::redirect_clean();
		}
	}

	/**
	 * Redirect back with the plugin's own query args removed, so a reload does not
	 * repeat the action (same trick as Scope_Sync).
	 */
	private static function redirect_clean(): void {
		wp_safe_redirect( remove_query_arg( array( self::ACTION_ADD, self::ACTION_DISMISS, '_wpnonce' ) ) );
		exit;
	}

	/**
	 * The proposal notice: evidence first, then two explicit buttons.
	 *
	 * Deliberately worded as a question about the admin's OWN form, because the
	 * proposal comes from a stranger's request — the admin is the only one who can
	 * tell a real password field from a forged claim.
	 */
	public function render_notices(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$open = Credential_Suggestion_Ledger::open_entries(
			Credential_Suggestion_Ledger::normalize( get_option( Option::POW_CREDENTIAL_SUGGESTIONS ) )
		);
		if ( 0 === count( $open ) ) {
			return;
		}

		$shown = 0;
		foreach ( $open as $name => $entry ) {
			if ( $shown >= self::NOTICE_LIMIT ) {
				break;
			}
			++$shown;

			$add_url     = wp_nonce_url(
				add_query_arg( self::ACTION_ADD, rawurlencode( (string) $name ) ),
				self::ACTION_ADD . '_' . (string) $name
			);
			$dismiss_url = wp_nonce_url(
				add_query_arg( self::ACTION_DISMISS, rawurlencode( (string) $name ) ),
				self::ACTION_DISMISS . '_' . (string) $name
			);

			echo '<div class="notice notice-warning is-dismissible"><p>';
			echo esc_html__( 'Invisible Anti-Spam: a submission reported a password field with an unusual name:', 'gdpr-compliant-recaptcha-for-all-forms' );
			echo ' <code>' . esc_html( (string) $name ) . '</code>.</p><p>';
			echo esc_html__( 'Reported from:', 'gdpr-compliant-recaptcha-for-all-forms' );
			echo ' <code>' . esc_html( '' === $entry['site'] ? '-' : $entry['site'] ) . '</code> — ';
			echo esc_html(
				sprintf(
					/* translators: %s: how often the field was reported. */
					__( 'seen %s times.', 'gdpr-compliant-recaptcha-for-all-forms' ),
					(string) $entry['count']
				)
			);
			echo '</p><p>';
			echo esc_html__( 'Confirm this only if it really is a password field on one of your own forms. Values of confirmed fields are stored as "[redacted]" — including in messages you already received.', 'gdpr-compliant-recaptcha-for-all-forms' );
			echo '</p><p>';
			echo '<a class="button button-primary" href="' . esc_url( $add_url ) . '">' . esc_html__( 'Treat as credential field', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</a> ';
			echo '<a class="button" href="' . esc_url( $dismiss_url ) . '">' . esc_html__( 'Not a password field', 'gdpr-compliant-recaptcha-for-all-forms' ) . '</a>';
			echo '</p></div>';
		}
	}

	/**
	 * Rescue path (b): confirm a field name straight from the message detail view
	 * and redact that message on the spot.
	 *
	 * manage_options + nonce, like every other write in Message_Page. Diagnostic
	 * names are refused here too — the settings field stays as the deliberate,
	 * unmistakable override for the (implausible) site whose password input really
	 * is called `email`.
	 */
	public function ajax_treat_as_credential(): void {
		$message_type   = filter_var( isset( $_POST['messageType'] ) ? wp_unslash( $_POST['messageType'] ) : '', FILTER_VALIDATE_INT );
		$security_nonce = isset( $_POST['security_nonce'] ) ? filter_var( wp_unslash( $_POST['security_nonce'] ), FILTER_UNSAFE_RAW ) : '';

		if ( ! current_user_can( 'manage_options' ) || ! wp_verify_nonce( $security_nonce, self::AJAX_NONCE . $message_type ) ) {
			wp_send_json_error( array( 'error_message' => __( 'Unauthorized request!', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		$message_id = (int) filter_var( isset( $_POST['messageID'] ) ? wp_unslash( $_POST['messageID'] ) : 0, FILTER_SANITIZE_NUMBER_INT );
		$attribute  = isset( $_POST['attribute'] ) ? sanitize_text_field( wp_unslash( $_POST['attribute'] ) ) : '';
		$segments   = explode( '->', $attribute );
		$name       = Learned_Credential_Fields::normalize_name( $segments[ count( $segments ) - 1 ] );

		if ( null === $name ) {
			wp_send_json_error( array( 'error_message' => __( 'This field name cannot be used as a credential field.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}
		if ( Learned_Credential_Fields::is_diagnostic_name( $name ) ) {
			wp_send_json_error(
				array(
					'error_message' => __( 'This field name carries the plugin\'s own diagnostics and cannot be redacted from here. Add it on the settings page if you are certain.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				)
			);
		}

		if ( null === self::add_learned( $name ) ) {
			wp_send_json_error( array( 'error_message' => __( 'The credential field list is full.', 'gdpr-compliant-recaptcha-for-all-forms' ) ) );
		}

		// Visible feedback: this very message loses the cleartext right now. Every
		// OTHER existing message follows through the re-armed cleanup.
		$redacted = Credential_Cleanup::redact_message_now( $message_id, array( $name ) );

		wp_send_json_success(
			array(
				'message'  => __( 'Field is now treated as a credential field.', 'gdpr-compliant-recaptcha-for-all-forms' ),
				'name'     => $name,
				'redacted' => $redacted,
				'value'    => Credential_Fields::REDACTED_VALUE,
			)
		);
	}
}
