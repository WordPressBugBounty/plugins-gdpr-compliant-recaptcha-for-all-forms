<?php
/**
 * The risk class inside Stamp: the ONE place that decides "record, but do not enforce".
 *
 * Design: PLAN-RISIKOKLASSE.md ("Die Entscheidung", point 4). Area doc:
 * handbuch/detection.md, "Risikoklasse". Which request is a risk request is
 * Risk_Signatures' question, whether its class is armed Risk_Enforcement's; this trait
 * only carries the answer through check_submit() and hands it to every side effect.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/detection.md.
// Index/Absprungstelle: HANDBUCH.md — Traits bekommen keine eigene Indexzeile.

/**
 * Observe-only for unarmed risk requests. Composed into Stamp.
 */
trait Stamp_Risk {

	/**
	 * The risk class of THIS REQUEST, computed once in the constructor (pure request
	 * inspection, like route_found) — so the type-4 analysis row, written before
	 * check_submit() runs, already knows it (card-number redaction by value).
	 *
	 * @var string|null
	 */
	private $request_risk_class = null;

	/**
	 * Called from the constructor, next to check_rest_routes().
	 *
	 * @return void
	 */
	private function classify_request_risk() {
		$request = is_array( $this->whole_request_data ) ? $this->whole_request_data : array();
		$action  = isset( $request['action'] ) && is_string( $request['action'] ) ? sanitize_text_field( $request['action'] ) : '';

		$this->request_risk_class = Risk_Signatures::classify_request( $action, $request, $this->get_rest_route() );
	}

	/**
	 * The risk class of the submission being judged, or null. Reset per check_submit().
	 *
	 * @var string|null
	 */
	private $risk_class = null;

	/**
	 * True while an unarmed risk request is judged: classify and store, enforce nothing.
	 * Set in exactly one place, evaluate_risk_class().
	 *
	 * @var bool
	 */
	private $risk_observe_only = false;

	/**
	 * Computes $risk_class and $risk_observe_only for THIS submission — at the head of
	 * check_submit(), before the first stage can feed a counter.
	 *
	 * Never for the login hook: a login is judged by the login path, and no risk line
	 * may ever reach wp_authenticate_user (PLAN-RISIKOKLASSE.md, "Der Login ist bereits
	 * gedeckt"). Never for a 'login' origin either, for the same reason.
	 *
	 * @param string $hook_name current_filter().
	 * @param string $origin    check_submit()'s $origin.
	 * @return void
	 */
	private function evaluate_risk_class( $hook_name, $origin ) {
		$this->risk_class        = null;
		$this->risk_observe_only = false;
		if ( 'wp_authenticate_user' === $hook_name || 'login' === $origin ) {
			return;
		}
		$this->risk_class = $this->request_risk_class;
		if ( null === $this->risk_class ) {
			return;
		}
		// Also in scope through an ORDINARY line (one the operator had before the risk
		// class, or any non-catalog line)? Then it stays enforced — no silent loss of a
		// block on update (Risk_Signatures::ordinary_line_matches()).
		$request = is_array( $this->whole_request_data ) ? $this->whole_request_data : array();
		$action  = isset( $request['action'] ) && is_string( $request['action'] ) ? sanitize_text_field( $request['action'] ) : '';
		if ( Risk_Signatures::ordinary_line_matches(
			$action,
			$request,
			$this->get_rest_route(),
			(string) get_option( Option::POW_EXPLICIT_ACTION, '' ),
			(string) get_option( Option::POW_PARAMETER_PATTERN, '' ),
			(string) get_option( Option::POW_REST_ROUTES, '' )
		) ) {
			return;
		}
		$this->risk_observe_only = Risk_Enforcement::observe_only( $this->risk_class );
	}

	/**
	 * May this verdict be ENFORCED — blocked, counted, echo-seeded, logged for fail2ban,
	 * flagged into the submitted fields? False only for an unarmed risk request.
	 *
	 * @return bool
	 */
	private function enforcement_allowed() {
		return ! $this->risk_observe_only;
	}

	/**
	 * The guard of the four feeds that simulation mode already suppressed (three wave-
	 * counter feeds, the echo record): neither in simulation nor for an unarmed risk
	 * request. The simulation half is the exact term that stood there before.
	 *
	 * @return bool
	 */
	private function side_effects_allowed() {
		return $this->enforcement_allowed() && ! get_option( Option::POW_SIMULATE_SPAM );
	}

	/**
	 * Tallies a spam verdict that was recorded but not enforced — the evidence next to
	 * the arming switch. Called once per check_submit(), after the verdict is final.
	 *
	 * @return void
	 */
	private function record_risk_observation() {
		// Not in simulation: there everything is "spam", and the number next to the switch
		// would claim refused purchases that would never have been refused.
		if ( $this->risk_observe_only && $this->plugin_spam && null !== $this->risk_class && ! get_option( Option::POW_SIMULATE_SPAM ) ) {
			Risk_Enforcement::record_observed( $this->risk_class );
		}
	}

	/**
	 * Adds the `_gdpr_not_enforced` detail row (value: the class) to a stored message
	 * that was spam but not enforced — the message view shows it as "Not blocked".
	 * Leading underscore: Echo_Values::is_technical_key() never lets it seed or match.
	 *
	 * @param array<string, mixed> $technical_fields The detail rows so far.
	 * @return array<string, mixed>
	 */
	private function with_risk_detail( array $technical_fields ) {
		if ( $this->risk_observe_only && $this->plugin_spam && null !== $this->risk_class ) {
			$technical_fields['_gdpr_not_enforced'] = $this->risk_class;
		}
		return $technical_fields;
	}
}
