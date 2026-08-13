<?php
/**
 * The confirmation ledger behind the suggested trusted-proxy address — pure logic.
 *
 * WHAT IS PROPOSED, AND WHY IT IS NOT WHAT YOU MIGHT EXPECT.
 * The candidate this ledger carries is REMOTE_ADDR: the TCP peer the web server itself
 * observed. It is NEVER an address read out of a forwarding header. That is the whole
 * security argument of this feature, and it is not a detail that can be relaxed later:
 *
 *   - POW_TRUSTED_PROXIES is matched against REMOTE_ADDR (and against the hops inside
 *     the chain) in ClientIp::resolve(). The address an operator has to enter there is
 *     therefore STRUCTURALLY the peer — proposing anything else would propose a value
 *     that cannot do the job.
 *   - The forwarding header is the INDICATOR that a proxy exists at all, and it is shown
 *     as evidence next to the proposal. Its value is never the candidate. A header is
 *     client-settable; a peer address is not.
 *   - The gate that produces a candidate (see Settings_Menu::observe_proxy_candidate())
 *     additionally requires the peer to be private/loopback. So the attacker set is not
 *     "anyone on the internet who can send a header" but "someone who already reaches
 *     this server from a private address" — a co-tenant or an insider. That is exactly
 *     the residual surface the shipped POW_TRUST_PRIVATE_PROXY opt-in already accepts.
 *
 * THIS LEDGER IS A STABILITY FILTER, NOT A SECURITY CONTROL. Say it that way in any
 * follow-up too. N requests spread over T minutes is trivially produced by a script; the
 * counter buys exactly one thing, and only one: a single outlier request cannot raise a
 * proposal, so a transient hop or a one-off odd request does not end up in front of the
 * admin as a recommendation. Nothing here defends against spoofing — the candidate
 * definition above does that, alone.
 *
 * PRIVACY. The candidate is stored in CLEARTEXT while everything else in this plugin
 * stores addresses hashed (rgs_ip = sha256(ip)). That is deliberate and does not bend the
 * privacy invariant: the whole point is that the administrator READS this address and
 * types it into a setting, so a hash would be useless; and by the gate above the value is
 * always a private/loopback address — infrastructure, not a visitor, and not even
 * globally routable. The public address seen in the forwarding header (which could be a
 * visitor's) is never stored, only the NAME of the header that carried it. Stored history
 * is three integers: first sighting, last sighting, count — no per-request trail — and it
 * expires TTL_SECONDS after the last sighting.
 *
 * No WordPress dependencies → tests/unit/ProxyCandidateLedgerTest.php.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/pow.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * Counting ledger for a single, repeatedly observed reverse-proxy peer address.
 */
final class Proxy_Candidate_Ledger {

	/** Ledger layout version — a mismatch discards the stored value. */
	public const VERSION = 1;

	/**
	 * N — how many counted sightings make a candidate ripe for proposal.
	 *
	 * Five, together with SLOT_SECONDS below, means the same peer has to hold across at
	 * least four slot boundaries, i.e. ~20 minutes of wall clock. Chosen so that a single
	 * request, a burst of requests inside one page load, and a short-lived hop all fall
	 * short, while an operator who is actually working in wp-admin reaches it inside one
	 * sitting. CALIBRATION OF A STABILITY FILTER, NOT A SECURITY THRESHOLD — raising it
	 * to 50 would buy no security at all, only a later proposal (see the class docblock).
	 *
	 * @var int
	 */
	public const CONFIRM_COUNT = 5;

	/**
	 * T — the slot length. At most one sighting is counted per slot, so the counter
	 * measures elapsed time rather than traffic volume: a busy admin screen full of
	 * ajax polls must not ripen a candidate in three seconds. It doubles as the write
	 * bound — one option write per five minutes at most while counting.
	 *
	 * @var int
	 */
	public const SLOT_SECONDS = 300;

	/**
	 * Once ripe, the counter stops but the last sighting is still refreshed — at most
	 * hourly. Without a refresh the proposal would expire under TTL_SECONDS while the
	 * proxy is still right there, and blink back in twenty minutes later; without the
	 * hourly bound it would be an option write per slot forever.
	 *
	 * @var int
	 */
	public const REFRESH_SECONDS = 3600;

	/**
	 * How long after the last sighting the ledger still means anything. Past it, the
	 * stored state is treated as absent (is_ripe() says no) and the next sighting starts
	 * a fresh count. This is the data-retention half of the privacy note above: a proxy
	 * that is gone stops being remembered within a day, without anything having to run.
	 *
	 * @var int
	 */
	public const TTL_SECONDS = 86400;

	/** Longest stored evidence header name. */
	private const MAX_HEADER_LENGTH = 40;

	/**
	 * The state of "nothing observed".
	 *
	 * @return array{v:int,ip:string,header:string,first_seen:int,last_seen:int,count:int}
	 */
	public static function empty_ledger(): array {
		return array(
			'v'          => self::VERSION,
			'ip'         => '',
			'header'     => '',
			'first_seen' => 0,
			'last_seen'  => 0,
			'count'      => 0,
		);
	}

	/**
	 * Turn whatever is stored into a usable ledger. Any foreign or outdated shape — and
	 * any stored value that is not a valid IP — yields the empty ledger rather than an
	 * error, so a corrupted option can never put a bogus address in front of the admin.
	 *
	 * @param mixed $stored Raw option value.
	 * @return array{v:int,ip:string,header:string,first_seen:int,last_seen:int,count:int}
	 */
	public static function normalize( $stored ): array {
		if ( ! is_array( $stored ) || ! isset( $stored['v'] ) || self::VERSION !== (int) $stored['v'] ) {
			return self::empty_ledger();
		}

		$ip = isset( $stored['ip'] ) && is_scalar( $stored['ip'] ) ? trim( (string) $stored['ip'] ) : '';
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return self::empty_ledger();
		}

		$count = isset( $stored['count'] ) ? (int) $stored['count'] : 0;

		return array(
			'v'          => self::VERSION,
			'ip'         => $ip,
			'header'     => self::normalize_header( isset( $stored['header'] ) ? $stored['header'] : '' ),
			'first_seen' => isset( $stored['first_seen'] ) ? max( 0, (int) $stored['first_seen'] ) : 0,
			'last_seen'  => isset( $stored['last_seen'] ) ? max( 0, (int) $stored['last_seen'] ) : 0,
			'count'      => max( 0, min( self::CONFIRM_COUNT, $count ) ),
		);
	}

	/**
	 * Record one sighting of $candidate.
	 *
	 * Returns the ledger unchanged whenever nothing has to be persisted; the caller
	 * writes only on `changed`, which is what keeps this off the write path of every
	 * single admin request.
	 *
	 * A DIFFERENT candidate restarts the count instead of competing with the stored one.
	 * That is on purpose: rotating peer addresses mean a POOL of proxies, and a pool has
	 * no single line to suggest — such a site never reaches a proposal, which is the
	 * honest outcome, not a bug to route around.
	 *
	 * @param array  $ledger    Normalised ledger.
	 * @param mixed  $candidate The observed peer address (REMOTE_ADDR — never a header value).
	 * @param mixed  $header    Name of the forwarding header that indicated the hop (evidence only).
	 * @param int    $now       Current unix time. Passed in — this class never calls time().
	 * @return array{ledger:array{v:int,ip:string,header:string,first_seen:int,last_seen:int,count:int},changed:bool,ripe:bool}
	 */
	public static function observe( array $ledger, $candidate, $header, int $now ): array {
		$ledger    = self::normalize( $ledger );
		$candidate = is_scalar( $candidate ) ? trim( (string) $candidate ) : '';

		if ( false === filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
			return self::result( $ledger, false, $now );
		}

		$header  = self::normalize_header( $header );
		$expired = $ledger['last_seen'] > 0 && ( $now - $ledger['last_seen'] ) > self::TTL_SECONDS;

		if ( '' === $ledger['ip'] || $ledger['ip'] !== $candidate || $expired ) {
			return self::result(
				array(
					'v'          => self::VERSION,
					'ip'         => $candidate,
					'header'     => $header,
					'first_seen' => $now,
					'last_seen'  => $now,
					'count'      => 1,
				),
				true,
				$now
			);
		}

		$elapsed = $now - $ledger['last_seen'];

		if ( $ledger['count'] >= self::CONFIRM_COUNT ) {
			if ( $elapsed < self::REFRESH_SECONDS ) {
				return self::result( $ledger, false, $now );
			}
			$ledger['last_seen'] = $now;
			$ledger['header']    = $header;
			return self::result( $ledger, true, $now );
		}

		if ( $elapsed < self::SLOT_SECONDS ) {
			return self::result( $ledger, false, $now );
		}

		$ledger['last_seen'] = $now;
		$ledger['header']    = $header;
		++$ledger['count'];

		return self::result( $ledger, true, $now );
	}

	/**
	 * Is there a candidate that has been confirmed often enough AND recently enough to
	 * be shown? Both halves matter: the count is the stability filter, the TTL is what
	 * keeps a proposal from outliving the situation it describes.
	 *
	 * @param array $ledger Normalised ledger.
	 * @param int   $now    Current unix time.
	 * @return bool
	 */
	public static function is_ripe( array $ledger, int $now ): bool {
		$ledger = self::normalize( $ledger );

		return '' !== $ledger['ip']
			&& $ledger['count'] >= self::CONFIRM_COUNT
			&& ( $now - $ledger['last_seen'] ) <= self::TTL_SECONDS;
	}

	/**
	 * Does $address name exactly the stored candidate?
	 *
	 * The adopt link carries the address it offers, and the handler compares it here
	 * before writing anything. So the request parameter can only ever CONFIRM the address
	 * this ledger already holds — a crafted URL cannot introduce one.
	 *
	 * @param array $ledger  Normalised ledger.
	 * @param mixed $address Address from the request.
	 * @return bool
	 */
	public static function matches_candidate( array $ledger, $address ): bool {
		$ledger  = self::normalize( $ledger );
		$address = is_scalar( $address ) ? trim( (string) $address ) : '';

		return '' !== $ledger['ip'] && $ledger['ip'] === $address;
	}

	/**
	 * How long the candidate has been under observation, in seconds.
	 *
	 * @param array $ledger Normalised ledger.
	 * @return int
	 */
	public static function observed_span( array $ledger ): int {
		$ledger = self::normalize( $ledger );

		return max( 0, $ledger['last_seen'] - $ledger['first_seen'] );
	}

	/**
	 * Pack a return value.
	 *
	 * @param array $ledger  Ledger to return.
	 * @param bool  $changed Whether the caller has to persist it.
	 * @param int   $now     Current unix time.
	 * @return array{ledger:array,changed:bool,ripe:bool}
	 */
	private static function result( array $ledger, bool $changed, int $now ): array {
		return array(
			'ledger'  => $ledger,
			'changed' => $changed,
			'ripe'    => self::is_ripe( $ledger, $now ),
		);
	}

	/**
	 * Reduce a header name to the harmless shape it is displayed in. Evidence, never a
	 * decision — but it is rendered to an admin, so it is bounded and stripped of
	 * everything that is not a header-name character.
	 *
	 * @param mixed $header Raw header name.
	 * @return string
	 */
	private static function normalize_header( $header ): string {
		$value = is_scalar( $header ) ? (string) $header : '';
		$value = (string) preg_replace( '/[^A-Za-z0-9-]/', '', $value );

		return substr( $value, 0, self::MAX_HEADER_LENGTH );
	}
}
