<?php
/**
 * The proposal ledger behind the learned credential-field list — pure logic.
 *
 * One entry per field name, EVER. That single rule carries the two ways this
 * feature could die:
 *
 *  1. ABUSE. The proposals are derived from `hashPWFields`, i.e. from
 *     UNAUTHENTICATED request data. An attacker can claim any field is a
 *     password field. The ledger therefore only ever RECORDS a name — nothing in
 *     this class or its callers adds anything to the learned list; that needs an
 *     explicit admin click (capability + nonce). A name that was dismissed once
 *     never returns, so an attacker cannot re-raise it until it is confirmed out
 *     of fatigue, and the entry carries its evidence (the referring site and how
 *     often it was seen) so the admin can judge it instead of guessing.
 *  2. NAG FATIGUE. The same "one entry ever" rule is what stops a notice from
 *     reappearing after every submission.
 *
 * Bounded by construction, because the write path is reachable by anybody:
 * MAX_OPEN caps how many proposals can be pending at once, MAX_ENTRIES the whole
 * ledger (it is an autoloaded option), MAX_COUNT stops the evidence counter — and
 * with it the option write — once the number has made its point.
 *
 * No WordPress dependencies → tests/unit/CredentialSuggestionLedgerTest.php.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/detection.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * De-duplicating ledger of proposed credential-field names.
 */
final class Credential_Suggestion_Ledger {

	/** Ledger layout version — a mismatch discards the stored value. */
	public const VERSION = 1;

	/** Proposed, waiting for the admin. */
	public const STATE_OPEN = 'open';

	/** Confirmed by the admin; the name is on the learned list. */
	public const STATE_ADDED = 'added';

	/** Rejected by the admin. Never proposed again. */
	public const STATE_DISMISSED = 'dismissed';

	/** Most pending proposals at any time (nag- and flood-bound). */
	public const MAX_OPEN = 20;

	/** Most entries in total, including settled ones (option-size bound). */
	public const MAX_ENTRIES = 200;

	/** Evidence counter ceiling. Reaching it also stops the option writes. */
	public const MAX_COUNT = 100;

	/** Longest stored evidence site string. */
	private const MAX_SITE_LENGTH = 190;

	/** Candidates accepted from a single request. */
	public const MAX_PER_REQUEST = 10;

	/**
	 * Turn whatever is stored into a usable ledger.
	 *
	 * Total: any shape of stored value is accepted; a foreign or outdated one
	 * yields an empty ledger rather than an error.
	 *
	 * @param mixed $stored Raw option value.
	 * @return array{v:int,entries:array<string,array{site:string,count:int,state:string}>}
	 */
	public static function normalize( $stored ): array {
		$entries = array();

		if ( is_array( $stored ) && isset( $stored['v'] ) && self::VERSION === (int) $stored['v']
			&& isset( $stored['entries'] ) && is_array( $stored['entries'] ) ) {
			foreach ( $stored['entries'] as $name => $entry ) {
				$key = Learned_Credential_Fields::normalize_name( $name );
				if ( null === $key || ! is_array( $entry ) || isset( $entries[ $key ] ) ) {
					continue;
				}
				$entries[ $key ] = array(
					'site'  => isset( $entry['site'] ) && is_scalar( $entry['site'] )
						? substr( (string) $entry['site'], 0, self::MAX_SITE_LENGTH )
						: '',
					'count' => isset( $entry['count'] ) ? max( 0, min( self::MAX_COUNT, (int) $entry['count'] ) ) : 0,
					'state' => self::normalize_state( isset( $entry['state'] ) ? $entry['state'] : '' ),
				);
				if ( count( $entries ) >= self::MAX_ENTRIES ) {
					break;
				}
			}
		}

		return array(
			'v'       => self::VERSION,
			'entries' => $entries,
		);
	}

	/**
	 * Record candidate names as proposals.
	 *
	 * Returns the ledger unchanged whenever nothing has to be persisted — the
	 * caller compares and only then writes, so a flood of submissions carrying an
	 * already-settled name costs no database write at all.
	 *
	 * @param array $ledger     Normalised ledger.
	 * @param array $candidates Candidate names (Learned_Credential_Fields::candidates_from_marker_paths()).
	 * @param mixed $from_site  Referring site, evidence only.
	 * @return array New ledger.
	 */
	public static function record( array $ledger, array $candidates, $from_site ): array {
		$entries = isset( $ledger['entries'] ) && is_array( $ledger['entries'] ) ? $ledger['entries'] : array();
		$site    = is_scalar( $from_site ) ? substr( (string) $from_site, 0, self::MAX_SITE_LENGTH ) : '';
		$open    = self::count_open( $entries );
		$taken   = 0;

		foreach ( $candidates as $candidate ) {
			if ( $taken >= self::MAX_PER_REQUEST ) {
				break;
			}
			$name = Learned_Credential_Fields::normalize_name( $candidate );
			if ( null === $name || Learned_Credential_Fields::is_diagnostic_name( $name ) ) {
				continue;
			}
			++$taken;

			if ( isset( $entries[ $name ] ) ) {
				// Known name: only an OPEN proposal still collects evidence. A settled
				// one (added/dismissed) is never touched and never proposed again.
				if ( self::STATE_OPEN === $entries[ $name ]['state'] && $entries[ $name ]['count'] < self::MAX_COUNT ) {
					++$entries[ $name ]['count'];
				}
				continue;
			}

			if ( $open >= self::MAX_OPEN || count( $entries ) >= self::MAX_ENTRIES ) {
				// Full. Deliberately refuse the new one instead of evicting an older
				// entry: eviction would let a flood push a genuine proposal out.
				continue;
			}

			$entries[ $name ] = array(
				'site'  => $site,
				'count' => 1,
				'state' => self::STATE_OPEN,
			);
			++$open;
		}

		return array(
			'v'       => self::VERSION,
			'entries' => $entries,
		);
	}

	/**
	 * Settle names (admin action). Unknown names are recorded in that state, so a
	 * name confirmed from the message inbox is never proposed afterwards either.
	 *
	 * @param array    $ledger Normalised ledger.
	 * @param string[] $names  Names to settle.
	 * @param string   $state  STATE_ADDED or STATE_DISMISSED.
	 * @return array New ledger.
	 */
	public static function mark( array $ledger, array $names, string $state ): array {
		$entries = isset( $ledger['entries'] ) && is_array( $ledger['entries'] ) ? $ledger['entries'] : array();
		$state   = self::normalize_state( $state );
		if ( self::STATE_OPEN === $state ) {
			// Re-opening is not a thing: it would resurrect a dismissed proposal.
			return array(
				'v'       => self::VERSION,
				'entries' => $entries,
			);
		}

		foreach ( $names as $candidate ) {
			$name = Learned_Credential_Fields::normalize_name( $candidate );
			if ( null === $name ) {
				continue;
			}
			if ( isset( $entries[ $name ] ) ) {
				$entries[ $name ]['state'] = $state;
				continue;
			}
			if ( count( $entries ) >= self::MAX_ENTRIES ) {
				continue;
			}
			$entries[ $name ] = array(
				'site'  => '',
				'count' => 0,
				'state' => $state,
			);
		}

		return array(
			'v'       => self::VERSION,
			'entries' => $entries,
		);
	}

	/**
	 * Pending proposals, newest-first is irrelevant — insertion order is kept.
	 *
	 * @param array $ledger Normalised ledger.
	 * @return array<string,array{site:string,count:int,state:string}>
	 */
	public static function open_entries( array $ledger ): array {
		$out = array();
		if ( ! isset( $ledger['entries'] ) || ! is_array( $ledger['entries'] ) ) {
			return $out;
		}
		foreach ( $ledger['entries'] as $name => $entry ) {
			if ( is_array( $entry ) && isset( $entry['state'] ) && self::STATE_OPEN === $entry['state'] ) {
				$out[ $name ] = $entry;
			}
		}
		return $out;
	}

	/**
	 * Is this name pending confirmation? The admin actions require it: a link
	 * naming anything else is refused, so a crafted URL cannot add a name that
	 * was never proposed.
	 *
	 * @param array $ledger Normalised ledger.
	 * @param mixed $name   Candidate name.
	 * @return bool
	 */
	public static function is_open( array $ledger, $name ): bool {
		$key = Learned_Credential_Fields::normalize_name( $name );
		if ( null === $key ) {
			return false;
		}
		$open = self::open_entries( $ledger );
		return isset( $open[ $key ] );
	}

	/**
	 * Number of pending proposals.
	 *
	 * @param array $entries Entry map.
	 * @return int
	 */
	private static function count_open( array $entries ): int {
		$count = 0;
		foreach ( $entries as $entry ) {
			if ( is_array( $entry ) && isset( $entry['state'] ) && self::STATE_OPEN === $entry['state'] ) {
				++$count;
			}
		}
		return $count;
	}

	/**
	 * Map anything to a known state (unknown → open, the only state that still
	 * shows the entry to the admin instead of silently swallowing it).
	 *
	 * @param mixed $state Raw state.
	 * @return string
	 */
	private static function normalize_state( $state ): string {
		$value = is_scalar( $state ) ? (string) $state : '';
		if ( self::STATE_ADDED === $value || self::STATE_DISMISSED === $value ) {
			return $value;
		}
		return self::STATE_OPEN;
	}
}
