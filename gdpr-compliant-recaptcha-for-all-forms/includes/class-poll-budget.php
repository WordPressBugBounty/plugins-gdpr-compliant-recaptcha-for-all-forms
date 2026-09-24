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
	 * POST arrives the row can legitimately be seconds old or not yet written at all.
	 * 20 attempts at the 100ms interval, check-before-sleep, means a worst case of
	 * 19 * 100ms ≈ 2s of waiting — the value this path has carried since the poll was
	 * cut down from 5s.
	 */
	const ATTEMPTS_POST = 20;

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
	 * THE ONE NAMED PRICE, known and accepted by the owner: the rescue window for the
	 * organic WooCommerce GET cart shrinks from 2s to ~0.3s. That reaches shops which
	 * switched the ajax option off, and only on a visitor's very first click, before the
	 * page's own PoW has produced a row.
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
