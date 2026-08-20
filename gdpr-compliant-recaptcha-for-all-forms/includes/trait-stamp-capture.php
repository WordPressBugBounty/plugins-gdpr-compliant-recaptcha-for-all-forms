<?php
/**
 * The CAPTURE half of Stamp: what the request brings in, and how it is unpacked before
 * anything looks at it. See handbuch/envelopes.md.
 *
 * SCHNITTLINIE (PLAN-DATEIGROESSE.md). class-stamp.php stood at 2408 lines against a
 * ledger cap of 2410 — two lines of headroom — when the envelope unpacking had to be
 * wired in. The cut takes a piece that is one responsibility and nothing else: filling
 * $request_data / $whole_request_data, and the two accessors for what unpacking left
 * behind. Same decision and same reason as trait-stamp-persistence.php and
 * trait-stamp-triage.php — a trait, not a second class, because this reads and writes
 * the SAME instance state as the constructor and check_submit().
 *
 * THREE LAYERS OF INPUT, and they are not interchangeable:
 *   1. $_POST / $_REQUEST — the shape every form builder that posts form-urlencoded
 *      uses. Captured verbatim.
 *   2. A JSON REQUEST BODY (Content-Type: application/json), merged on top. This has
 *      been here since 4.x and covers builders that post the whole submission as a JSON
 *      document, with the client twins in scripts/recaptcha-gdpr-pow.js
 *      (injectTokenIntoBody) and recaptcha-gdpr-analysis-model.js (formToJSON).
 *   3. A JSON ENVELOPE INSIDE A FIELD VALUE — layer 2 one level deeper, and until 5.5.0
 *      the one shape nothing here handled. Ninja Forms posts form-urlencoded with a
 *      single `formData` field carrying the whole form as JSON, so it fell between
 *      layers 1 and 2: not a JSON body, and a field map with exactly one opaque field.
 *      Field_Envelopes::unpack() closes that gap; its docblock holds the field datum and
 *      the five rules that keep the unpacking narrow.
 *
 * A REFUSED BODY IS NOT SIMPLY DROPPED. Layer 2 carries the same caps as layer 3 since
 * 5.6.0, and a cap that merges nothing would silently disarm the operator's blocklist for
 * that shape — so the raw bytes go to the blocklist check and nowhere else, see $body_raw.
 *
 * BOTH COPIES ARE UNPACKED, and they are unpacked SEPARATELY rather than one being
 * derived from the other: $request_data ($_POST) and $whole_request_data ($_REQUEST)
 * are different maps with different keys, and every downstream reader picks one of them
 * on purpose (the classification reads $request_data, the pattern gate reads
 * $whole_request_data). A single unpack on one of them would leave the other holding
 * the opaque string, which is exactly the divergence this plugin avoids elsewhere by
 * sharing ONE implementation.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

trait Stamp_Capture {

	/**
	 * The ORIGINAL string of every field Field_Envelopes::unpack() replaced, keyed by
	 * field name. Request-local, never persisted, and read by exactly one caller:
	 * matches_blocked_values(), which hands it to the blocklist check as additional
	 * content strings.
	 *
	 * WHY IT IS KEPT AT ALL — the regression it prevents is concrete. Until 5.5.0 the
	 * blocklist extracted addresses and URLs from the RAW value of every field, so a
	 * blocked domain sitting anywhere inside the envelope was found, including in a JSON
	 * KEY. Unpacking turns keys into keys, and nothing scores keys, so the operator's
	 * explicit block would have silently stopped working through our own update. Feeding
	 * exactly these bytes back into the blocklist check restores exactly that coverage —
	 * same bytes, same extractor, no new comparison semantics.
	 *
	 * NOT to the gibberish scan (that is the Ninja Forms bug rebuilt) and NOT to the
	 * echo lock (which SEEDS from what it is given; see Echo_Values::build_echo_set()'s
	 * $no_text_roots for what a constant text inside a form's configuration would do).
	 *
	 * @var array<string,string>
	 */
	private $envelope_raw = array();

	/**
	 * The raw REQUEST BODY of a JSON request that decode_body() could not take whole —
	 * truncated to the entry budget, or refused for being over the byte cap — capped at
	 * MAX_BYTES. Null whenever the body was merged in full.
	 *
	 * WHY IT IS KEPT, and it is the same argument as $envelope_raw one layer up: until
	 * 5.5.0 a JSON body was decoded unconditionally, so the blocklist saw every address
	 * and URL in it. With the cap, whatever falls off the end is invisible to the content
	 * checks — so an attacker who SOLVES the proof of work and pads their body would get
	 * their payload past us while WordPress's own REST dispatch parses the very same body
	 * and hands the complete submission to the target plugin. Delivered, unjudged. The
	 * operator's explicit block would have stopped working through our own update, which
	 * is exactly the regression class the raw side channel exists for.
	 *
	 * BLOCKLIST ONLY, same as $envelope_raw: match-only, never seeded, never scored for
	 * gibberish, never stored. Gibberish and the echo lock stay blind to this shape on
	 * purpose — that is the conceded adaptive-attacker class, named as a limit in
	 * handbuch/envelopes.md rather than papered over.
	 *
	 * @var string|null
	 */
	private $body_raw = null;

	/**
	 * The top-level field names that Field_Envelopes::unpack() replaced by a structure.
	 * Passed to Echo_Store::record()/matches() so the long-text hash skips those
	 * subtrees — a builder's configuration texts are constant per form, and a constant
	 * seeded into the echo store matches every later submission of that same form.
	 *
	 * @return string[]
	 */
	public function envelope_roots() {
		return array_keys( $this->envelope_raw );
	}

	/**
	 * The raw strings of the replaced fields, for the blocklist check. See
	 * $envelope_raw for why they exist.
	 *
	 * @return string[]
	 */
	public function envelope_raw() {
		$raw = array_values( $this->envelope_raw );
		if ( null !== $this->body_raw ) {
			$raw[] = $this->body_raw;
		}
		return $raw;
	}

	/**
	 * Fill $request_data / $whole_request_data from the request, then unpack the JSON
	 * envelopes among their top-level values.
	 *
	 * @return void
	 */
	private function capture_request_data() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Spam filter must inspect every third-party form POST; no nonce exists for foreign forms. Read-only capture only; the real gate is the PoW/token check downstream.
		$this->request_data = $_POST; // Standard POST data
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- see note above: read-only capture of the full request for inspection, not a state-changing action.
		$this->whole_request_data = $_REQUEST; // Standard REQUEST data

		// If the request is JSON, read data from php://input. Decoded through
		// Field_Envelopes::decode_body() rather than json_decode() directly, so this path
		// carries the SAME caps as layer 3 — without that, the entry budget below would be
		// one Content-Type header away from being pointless (see that method's docblock).
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD']
			&& isset( $_SERVER['CONTENT_TYPE'] ) && strpos( $_SERVER['CONTENT_TYPE'], 'application/json' ) !== false ) {
			$body       = file_get_contents( 'php://input' );
			$incomplete = false;
			$json_data  = Field_Envelopes::decode_body( $body, $incomplete );
			if ( ! empty( $json_data ) ) {
				$this->request_data       = array_merge( $this->request_data, $json_data );
				$this->whole_request_data = array_merge( $this->whole_request_data, $json_data );
			}
			if ( $incomplete ) {
				// What did not make it in is invisible to the content checks. Keep the bytes
				// for the blocklist — see $body_raw for the regression that closes.
				$this->body_raw = substr( (string) $body, 0, Field_Envelopes::MAX_BYTES );
			}
		}

		// Layer 3 (see the file docblock). In place per field, never merged upwards —
		// otherwise a sender's own envelope could overwrite our copy of `action`,
		// `security` or `gdpr_pow_token`.
		$post                     = Field_Envelopes::unpack( $this->request_data );
		$request                  = Field_Envelopes::unpack( $this->whole_request_data );
		$this->request_data       = $post['fields'];
		$this->whole_request_data = $request['fields'];
		$this->envelope_raw       = $post['raw'] + $request['raw'];
	}
}
