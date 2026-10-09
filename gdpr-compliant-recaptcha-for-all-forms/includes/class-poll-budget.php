<?php
/**
 * Pure, WordPress-independent decision: how long Stamp::poll_for_row() may wait for a
 * stamp row to appear.
 *
 * No options, no $wpdb, no hooks — the caller passes in the one fact this depends on, so
 * the whole thing is unit-testable in isolation (tests/unit/PollBudgetTest.php).
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
 * The attempt budget of the row poll, and the one reason it is not a single number.
 */
final class Poll_Budget {

	/**
	 * A POST may still be racing the handshake that writes its row.
	 *
	 * check_stamp() lands the row from a separate ajax call, so at the moment a form
	 * POST arrives the row can legitimately be seconds old or not yet written at all —
	 * on a slow device the visitor can submit before his proof of work has finished.
	 * 51 attempts at the 100ms interval, check-before-sleep, means a worst case of
	 * 50 * 100ms = 5s of waiting.
	 *
	 * 5s IS AN OWNER DECISION (2026-10), and it restores the original value. The poll
	 * began as 5 * 1s = 5s, chosen as the tolerance for slow devices; AP1 (2026-07-15,
	 * c6663c2) cut it to 20 * 100ms ≈ 2s with the argument that a spam flood holds a PHP
	 * worker 5s per request. The owner rejects that trade: a false block is the worst
	 * error this plugin can make, and a real visitor on a slow phone is exactly who the
	 * shorter window threw out. The price is named and accepted — a tokenless flood now
	 * holds a worker up to 5s per request; the Under-Attack mode (handbuch/pow.md) is
	 * the answer to a flood, not a shorter wait for everybody. The 100ms interval and
	 * check-before-sleep stay, so a row that is already there costs no wait at all.
	 */
	const ATTEMPTS_POST = 51;

	/**
	 * Anything that is not a POST cannot be racing anything, so it waits almost not at all.
	 *
	 * WHY THE TWO CASES ARE DIFFERENT, not a tuning knob: the client stamps no GET form
	 * (isGetForm() in scripts/recaptcha-gdpr-pow.js bails out), and a visitor following a
	 * link has long since finished the page's proactive PoW. A GET that matches a
	 * monitored signature therefore has no handshake in flight — the wait can only ever
	 * run out. Measured on the running instance before this split: a plain GET took
	 * 0.23s, a GET matching a seeded pattern took 2.00s, and every one of those two
	 * seconds was spent polling for a row that was never going to be written.
	 *
	 * That mattered because a matching GET needs no form and no body. Since 2026-08-17
	 * the core comment pattern ships unconditionally (trait-settings-default-patterns.php),
	 * so a bodyless request with the comment form's field names matches on EVERY
	 * installation — cheap for the sender, invisible to any page cache, and it held a PHP
	 * worker for two seconds.
	 *
	 * WHAT THIS DOES NOT CHANGE — and this is the load-bearing half: the verdict.
	 * consume_ip_row() still runs, so whoever the IP fallback rescued is still rescued;
	 * only the waiting for a row that could still arrive DURING the request goes away.
	 * Not zero, for that reason: check-before-sleep means the first attempt happens
	 * regardless, and 3 leaves ~0.2s in which a row landing concurrently is still seen.
	 *
	 * The one price once named here — a shorter rescue window for the organic
	 * WooCommerce GET cart — no longer exists: the cart is not checked at all since
	 * 2026-10-09 (handbuch/seeds.md).
	 */
	const ATTEMPTS_NON_POST = 3;

	/**
	 * The effective attempt budget for the request currently being served.
	 *
	 * @param bool $is_post Whether this request is a POST (the caller reads
	 *                      $_SERVER['REQUEST_METHOD']; this class stays free of it).
	 * @return int Attempt budget, never below 1.
	 */
	public static function attempts( $is_post ) {
		return $is_post ? self::ATTEMPTS_POST : self::ATTEMPTS_NON_POST;
	}
}
