/**
 * Client-side hashcash proof-of-work + Ajax error-message interception.
 *
 * Enqueued (in the page <head>, not the footer) by Stamp::add_script_to_header().
 * Per-request/config values arrive via wp_localize_script as the global `gdprPow`
 * ( { stamp, difficulty, ajaxUrl, timeout } ) — deliberately nothing derived from the
 * visitor's IP address: page HTML is cacheable and shared between visitors.
 *
 * The proof-of-work algorithm here MUST stay in lockstep with the server side
 * (includes/class-proof-of-work.php) and the PHPUnit ProofOfWorkTest — otherwise
 * valid clients get rejected as spam. See HANDBUCH.md §3/§4.
 *
 * AP3 submission-binding: `gdprPow.stamp` is now a single-use TOKEN (opaque to this
 * script — it is only ever used as the hashcash input string, same as the old
 * bucket-stamp). Once a solved token has been POSTed to check_stamp, it is kept in
 * `gdpr_compliant_recaptcha_token` and injected as a hidden `gdpr_pow_token` field
 * into every `<form>` (and best-effort into outgoing Ajax POST bodies), so the next
 * real submission can be bound to it server-side. See HANDBUCH.md §3.
 *
 * AP4 adaptive difficulty: `gdprPow.difficulty`/the per-token difficulty returned
 * by `get_stamp` can now vary (server-side base option + a site-wide "under
 * attack" boost, see class-stamp.php) — this file treats it as an opaque number
 * exactly as before, it just may be a few bits higher on a given request. To
 * absorb the extra hashing work, `hashHex()` prefers `crypto.subtle.digest()`
 * (secure contexts only — https/localhost) over the hand-rolled `sha256()`,
 * which stays in this file as the fallback for http:// sites/old browsers.
 */
// Defensive default: if wp_localize_script somehow did not run (missing/duplicated
// enqueue, an aborted head), reading gdprPow.* at parse time would throw a
// ReferenceError and take the WHOLE file down — including the Ajax error-message
// interception. Fall back to an empty object so the file still parses; without real
// values it simply no-ops instead of crashing.
var gdprPow = (typeof window !== 'undefined' && window.gdprPow) ? window.gdprPow : (typeof gdprPow !== 'undefined' ? gdprPow : {});
var gdpr_compliant_recaptcha_stamp = gdprPow.stamp;
var gdpr_compliant_recaptcha_nonce = null;
var gdpr_compliant_recaptcha_difficulty = gdprPow.difficulty;
var gdpr_compliant_recaptcha_token = null;
var gdpr_compliant_recaptcha = {
	stampLoaded : false,
	renewDebounceTimer : null,
	// Create an array to store override functions
	originalFetches : [],
	originalXhrOpens : [],
	originalXhrSends : [],
	// typeof guards keep the object literal evaluable outside a browser too (the
	// Node-based regression tests require this file for its pure helpers) — in the
	// browser these globals always exist, so behaviour there is unchanged.
	originalFetch : ( typeof window !== 'undefined' ) ? window.fetch : null,
	abortController : ( typeof AbortController !== 'undefined' ) ? new AbortController() : null,
	originalXhrOpen : ( typeof XMLHttpRequest !== 'undefined' ) ? XMLHttpRequest.prototype.open : null,
	originalXhrSend : ( typeof XMLHttpRequest !== 'undefined' ) ? XMLHttpRequest.prototype.send : null,

	// Function to check if a string is a valid JSON
	isValidJson : function( str ) {
		try {
			JSON.parse( str );
			return true;
		} catch ( error ) {
			return false;
		}
	},

	// Tolerant JSON-OBJECT parse for Ajax responses that may carry noise before/after
	// the JSON: a PHP notice/deprecation printed by ANOTHER plugin under display_errors
	// (common on PHP 8.x hosts), a BOM, or leading/trailing whitespace. Returns the
	// parsed plain object, or null — it NEVER throws. This matters because initCaptcha()
	// used response.json() directly: a single stray byte before the "{" made it reject,
	// which (with no .catch) killed the entire proof-of-work pipeline → no stamp was
	// ever computed → every submission was classified as spam server-side.
	//
	// Strictly a CLIENT-side convenience: it only loosens what THIS browser accepts,
	// never any server-side verification (check_stamp still HMAC-verifies the token and
	// re-runs the PoW), so it cannot weaken the spam decision. Arrays/scalars → null.
	parseJsonLoose : function ( text ) {
		if ( typeof text !== 'string' || text === '' ) {
			return null;
		}
		var candidates = [ text ];
		var start = text.indexOf( '{' );
		var end = text.lastIndexOf( '}' );
		if ( start !== -1 && end !== -1 && end > start ) {
			candidates.push( text.slice( start, end + 1 ) );
		}
		for ( var i = 0; i < candidates.length; i++ ) {
			try {
				var parsed = JSON.parse( candidates[ i ] );
				if ( parsed && typeof parsed === 'object' && ! Array.isArray( parsed ) ) {
					return parsed;
				}
			} catch ( e ) {
				// Try the next candidate (e.g. the salvaged { ... } slice).
			}
		}
		return null;
	},

	// Map a (possibly bracketed) form-field name to a nested object, used to record
	// password-field paths that must never be stored in the inbox. Returns {} for a
	// null/empty/unmatchable name instead of throwing — a password <input> without a
	// name attribute previously made str.match() run on null → TypeError, aborting the
	// interception setup in addFirstStamp().
	fieldNameToNestedObject : function ( str ) {
		var keys = ( typeof str === 'string' ) ? str.match( /[^\[\]]+|\[[^\[\]]+\]/g ) : null;
		if ( ! keys ) {
			return {};
		}
		var obj = {};
		var tempObj = obj;
		for ( var i = 0; i < keys.length; i++ ) {
			var key = keys[ i ];
			if ( key.startsWith( '[' ) && key.endsWith( ']' ) ) {
				key = key.substring( 1, key.length - 1 );
			}
			tempObj[ key ] = ( i === keys.length - 1 ) ? null : {};
			tempObj = tempObj[ key ];
		}
		return obj;
	},

	// Clamp the renew interval to a sane floor. gdprPow.timeout is the raw
	// POW_TIME_WINDOW option (minutes); if it is empty/0/NaN, `raw * 60000` would be ~0
	// and setInterval would hammer admin-ajax on every tick (self-DoS). Floor at 1 min.
	renewIntervalMs : function ( rawTimeout ) {
		var minutes = parseInt( rawTimeout, 10 );
		if ( ! ( minutes > 0 ) ) {
			minutes = 10;
		}
		return minutes * 60000;
	},

	// Unique-per-call value appended to the get_stamp GET as `_=`. That response is a
	// FRESH, IP-BOUND token with a short lifetime and must never be shared between
	// visitors: a hoster/CDN/proxy cache that ignores WordPress' nocache headers would
	// otherwise hand one visitor's token to everybody, whose check_stamp then fails —
	// no stamp row is written and every submission is classified as spam. `cache:
	// 'no-store'` covers the browser's own cache, this covers intermediary caches, which
	// key on the full URL. Time alone is not enough (two visitors can hit the same
	// millisecond), so a random suffix is mixed in. Base-36, so the value stays short
	// and URL-safe.
	cacheBuster : function () {
		return Date.now().toString( 36 ) + Math.random().toString( 36 ).slice( 2, 10 );
	},

	// Whether an outgoing request is the plugin's own get_stamp/check_stamp Ajax call
	// (action given either in the URL query string or in the body). These must never
	// be touched (no token injection) and never count as an auto-renew trigger.
	isPluginCall : function (url, body) {
		var urlStr = '';
		if (typeof url === 'string') {
			urlStr = url;
		} else if (url && typeof url.url === 'string') {
			urlStr = url.url;
		}
		if (/[?&]action=(get_stamp|check_stamp)(&|$)/.test(urlStr)) {
			return true;
		}
		if (!body) {
			return false;
		}
		if (typeof FormData !== 'undefined' && body instanceof FormData) {
			var action = body.get ? body.get('action') : null;
			return action === 'get_stamp' || action === 'check_stamp';
		}
		if (typeof body === 'string') {
			if (/(^|&)action=(get_stamp|check_stamp)(&|$)/.test(body)) {
				return true;
			}
			if (gdpr_compliant_recaptcha.isValidJson(body)) {
				try {
					var parsed = JSON.parse(body);
					if (parsed && (parsed.action === 'get_stamp' || parsed.action === 'check_stamp')) {
						return true;
					}
				} catch (e) {
					// Not actually JSON despite isValidJson — fall through untouched.
				}
			}
		}
		return false;
	},

	// Best-effort injection of the current submission-binding token into an outgoing
	// POST body. Only recognized shapes are touched (FormData / urlencoded string /
	// JSON string); anything else is left untouched — the server-side IP fallback
	// covers what this can't reach.
	injectTokenIntoBody : function (body) {
		var token = gdpr_compliant_recaptcha_token;
		if (!token) {
			return body;
		}
		if (typeof FormData !== 'undefined' && body instanceof FormData) {
			if (!body.has || !body.has('gdpr_pow_token')) {
				body.append('gdpr_pow_token', token);
			}
			return body;
		}
		if (typeof body === 'string') {
			if (gdpr_compliant_recaptcha.isValidJson(body)) {
				try {
					var parsed = JSON.parse(body);
					if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && !parsed.gdpr_pow_token) {
						parsed.gdpr_pow_token = token;
						return JSON.stringify(parsed);
					}
					return body;
				} catch (e) {
					// Fall through to the urlencoded heuristic below.
				}
			}
			// Urlencoded-looking body ("k=v&k2=v2..."), not already carrying a token.
			if (/^[^{}\[\]]*=[^{}\[\]&]*(&[^{}\[\]]*=[^{}\[\]&]*)*$/.test(body) && body.indexOf('gdpr_pow_token=') === -1) {
				return body + (body.length ? '&' : '') + 'gdpr_pow_token=' + encodeURIComponent(token);
			}
		}
		return body;
	},

	// Whether a form submits via GET (method="get" or absent — HTML's default).
	// form.method normalises to "get"/"post"; we treat anything not explicitly "post"
	// as GET. Hidden fields on a GET form become VISIBLE query parameters, so injecting
	// the token there would append "&gdpr_pow_token=<100 chars>" to e.g. a theme search
	// URL ("?s=coffee&gdpr_pow_token=...") — ugly and harmful when the URL is shared.
	// The plugin only ever inspects POST submissions ($_POST), so a GET form never
	// needs the token anyway; skipping it costs no protection.
	isGetForm : function (form) {
		var method = (form && typeof form.method === 'string') ? form.method.toLowerCase() : 'get';
		return method !== 'post';
	},

	// Append (once) / refresh a hidden gdpr_pow_token field on every POST form. Appended
	// at the END (not prepended like hashPWFields): the field must never become the
	// form's first key — tooling that names a submission after its first field (e.g. the
	// direct-analysis overlay's seekName()) would otherwise label every form
	// "gdpr_pow_token".
	updateFormTokenFields : function (token) {
		if (!token) {
			return;
		}
		var forms = document.querySelectorAll('form');
		forms.forEach(function (form) {
			// Never inject into GET forms (search boxes etc.) — see isGetForm().
			if (gdpr_compliant_recaptcha.isGetForm(form)) {
				return;
			}
			var field = form.querySelector('input.gdpr_pow_token_field');
			if (!field) {
				field = document.createElement('input');
				field.type = 'hidden';
				field.classList.add('gdpr_pow_token_field');
				field.name = 'gdpr_pow_token';
				form.appendChild(field);
			}
			field.value = token;
		});
	},

	// Debounced (~1s) re-run of initCaptcha() after an intercepted non-plugin POST,
	// so the next submission has a fresh token (on top of the existing setInterval
	// renew). Debounced so a burst of Ajax POSTs doesn't fire a solve per request.
	scheduleRenew : function () {
		if (gdpr_compliant_recaptcha.renewDebounceTimer) {
			clearTimeout(gdpr_compliant_recaptcha.renewDebounceTimer);
		}
		gdpr_compliant_recaptcha.renewDebounceTimer = setTimeout(function () {
			gdpr_compliant_recaptcha.renewDebounceTimer = null;
			gdpr_compliant_recaptcha.initCaptcha();
		}, 1000);
	},

	// Function to handle fetch response
	handleFetchResponse: function (input, init) {
		// Store method and URL
		var method = (init && init.method) ? init.method.toUpperCase() : 'GET';
		var url = input;
		gdpr_compliant_recaptcha.originalFetches.forEach(overrideFunction => {
					overrideFunction.apply(this, arguments);
		});

		var isPluginCall = gdpr_compliant_recaptcha.isPluginCall(url, init && init.body);
		if (!isPluginCall && method === 'POST' && init && ('body' in init)) {
			init.body = gdpr_compliant_recaptcha.injectTokenIntoBody(init.body);
		}

		// Bind the original fetch function to the window object
		var originalFetchBound = gdpr_compliant_recaptcha.originalFetch.bind(window);
		try{
			// Call the original fetch method
			//return gdpr_compliant_recaptcha.originalFetch.apply(this, arguments).then(function (response) {
			return originalFetchBound(input, init).then(function (response) {
				var clonedResponse = response.clone();
				if (!isPluginCall && method === 'POST') {
					gdpr_compliant_recaptcha.scheduleRenew();
				}
				// Check for an error response
				if (response.ok && method === 'POST') {
					// Parse the response JSON
					return response.text().then(function (responseData) {
						var data = responseData;
						if (gdpr_compliant_recaptcha.isValidJson(responseData)) {
							data = JSON.parse(responseData);
						}
						// Check if the gdpr_error_message parameter is present
						if (data.data && data.data.gdpr_error_message) {
							gdpr_compliant_recaptcha.displayErrorMessage(data.data.gdpr_error_message);
							gdpr_compliant_recaptcha.abortController.abort();
							return Promise.reject(new Error('Request aborted'));
						}
						// Return the original response for non-error cases
						return clonedResponse;
					});
				}
				return clonedResponse;
			});
		} catch (error) {
			// Return a resolved promise in case of an error
			return Promise.resolve();
		}
	},

	// Full implementation of SHA265 hashing algorithm.
	sha256 : function( ascii ) {
		function rightRotate( value, amount ) {
			return ( value>>>amount ) | ( value<<(32 - amount ) );
		}

		var mathPow = Math.pow;
		var maxWord = mathPow( 2, 32 );
		var lengthProperty = 'length';

		// Used as a counter across the whole file
		var i, j;
		var result = '';

		var words = [];
		var asciiBitLength = ascii[ lengthProperty ] * 8;

		// Caching results is optional - remove/add slash from front of this line to toggle.
		// Initial hash value: first 32 bits of the fractional parts of the square roots of the first 8 primes
		// (we actually calculate the first 64, but extra values are just ignored).
		var hash = this.sha256.h = this.sha256.h || [];

		// Round constants: First 32 bits of the fractional parts of the cube roots of the first 64 primes.
		var k = this.sha256.k = this.sha256.k || [];
		var primeCounter = k[ lengthProperty ];

		var isComposite = {};
		for ( var candidate = 2; primeCounter < 64; candidate++ ) {
			if ( ! isComposite[ candidate ] ) {
				for ( i = 0; i < 313; i += candidate ) {
					isComposite[ i ] = candidate;
				}
				hash[ primeCounter ] = ( mathPow( candidate, 0.5 ) * maxWord ) | 0;
				k[ primeCounter++ ] = ( mathPow( candidate, 1 / 3 ) * maxWord ) | 0;
			}
		}

		// Append Ƈ' bit (plus zero padding).
		ascii += '\x80';

		// More zero padding
		while ( ascii[ lengthProperty ] % 64 - 56 ){
		ascii += '\x00';
		}

		for ( i = 0, max = ascii[ lengthProperty ]; i < max; i++ ) {
			j = ascii.charCodeAt( i );

			// ASCII check: only accept characters in range 0-255
			if ( j >> 8 ) {
			return;
			}
			words[ i >> 2 ] |= j << ( ( 3 - i ) % 4 ) * 8;
		}
		words[ words[ lengthProperty ] ] = ( ( asciiBitLength / maxWord ) | 0 );
		words[ words[ lengthProperty ] ] = ( asciiBitLength );

		// process each chunk
		for ( j = 0, max = words[ lengthProperty ]; j < max; ) {

			// The message is expanded into 64 words as part of the iteration
			var w = words.slice( j, j += 16 );
			var oldHash = hash;

			// This is now the undefinedworking hash, often labelled as variables a...g
			// (we have to truncate as well, otherwise extra entries at the end accumulate.
			hash = hash.slice( 0, 8 );

			for ( i = 0; i < 64; i++ ) {
				var i2 = i + j;

				// Expand the message into 64 words
				var w15 = w[ i - 15 ], w2 = w[ i - 2 ];

				// Iterate
				var a = hash[ 0 ], e = hash[ 4 ];
				var temp1 = hash[ 7 ]
					+ ( rightRotate( e, 6 ) ^ rightRotate( e, 11 ) ^ rightRotate( e, 25 ) ) // S1
					+ ( ( e&hash[ 5 ] ) ^ ( ( ~e ) &hash[ 6 ] ) ) // ch
					+ k[i]
					// Expand the message schedule if needed
					+ ( w[ i ] = ( i < 16 ) ? w[ i ] : (
							w[ i - 16 ]
							+ ( rightRotate( w15, 7 ) ^ rightRotate( w15, 18 ) ^ ( w15 >>> 3 ) ) // s0
							+ w[ i - 7 ]
							+ ( rightRotate( w2, 17 ) ^ rightRotate( w2, 19 ) ^ ( w2 >>> 10 ) ) // s1
						) | 0
					);

				// This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble:
				var temp2 = ( rightRotate( a, 2 ) ^ rightRotate( a, 13 ) ^ rightRotate( a, 22 ) ) // S0
					+ ( ( a&hash[ 1 ] )^( a&hash[ 2 ] )^( hash[ 1 ]&hash[ 2 ] ) ); // maj

					// We don't bother trimming off the extra ones,
					// they're harmless as long as we're truncating when we do the slice().
				hash = [ ( temp1 + temp2 )|0 ].concat( hash );
				hash[ 4 ] = ( hash[ 4 ] + temp1 ) | 0;
			}

			for ( i = 0; i < 8; i++ ) {
				hash[ i ] = ( hash[ i ] + oldHash[ i ] ) | 0;
			}
		}

		for ( i = 0; i < 8; i++ ) {
			for ( j = 3; j + 1; j-- ) {
				var b = ( hash[ i ]>>( j * 8 ) ) & 255;
				result += ( ( b < 16 ) ? 0 : '' ) + b.toString( 16 );
			}
		}
		return result;
	},

	// Replace with your desired hash function.
	hashFunc : function( x ) {
		return this.sha256( x );
	},

	// Async SHA-256 hex digest. Uses the native crypto.subtle implementation when
	// available (only ever exposed in a secure context — https or localhost —
	// which is why the feature-check also covers window.isSecureContext), which
	// is roughly 10x faster than the hand-rolled sha256() above. Falls back to
	// sha256() for http:// sites and old browsers; that implementation is kept
	// in this file for exactly that reason, do not remove it. Both paths MUST
	// produce the identical lower-case 64-char hex string the server
	// (ProofOfWork::hash_value(), plain sha256) expects — this only changes how
	// fast the client gets there, never the algorithm/result.
	hashHex : async function( str ) {
		if ( typeof window !== 'undefined'
			&& window.isSecureContext
			&& window.crypto
			&& window.crypto.subtle
			&& window.crypto.subtle.digest
		) {
			try {
				var encoded = new TextEncoder().encode( str );
				var digest = await window.crypto.subtle.digest( 'SHA-256', encoded );
				var bytes = new Uint8Array( digest );
				var hex = '';
				for ( var i = 0; i < bytes.length; i++ ) {
					hex += ( bytes[ i ] < 16 ? '0' : '' ) + bytes[ i ].toString( 16 );
				}
				return hex;
			} catch ( e ) {
				// Fall through to the hand-rolled implementation below.
			}
		}
		return this.hashFunc( str );
	},

	// Convert hex char to binary string.
	hexInBin : function( x ) {
		var ret = '';
		switch( x.toUpperCase() ) {
			case '0':
			return '0000';
			break;
			case '1':
			return '0001';
			break;
			case '2':
			return '0010';
			break;
			case '3':
			return '0011';
			break;
			case '4':
			return '0100';
			break;
			case '5':
			return '0101';
			break;
			case '6':
			return '0110';
			break;
			case '7':
			return '0111';
			break;
			case '8':
			return '1000';
			break;
			case '9':
			return '1001';
			break;
			case 'A':
			return '1010';
			break;
			case 'B':
			return '1011';
			break;
			case 'C':
			return '1100';
			break;
			case 'D':
			return '1101';
			break;
			case 'E':
			return '1110';
			break;
			case 'F':
			return '1111';
			break;
			default :
			return '0000';
		}
	},

	// Gets the leading number of bits from the string.
	extractBits : function( hexString, numBits ) {
		var bitString = '';
		var numChars = Math.ceil( numBits / 4 );
		for ( var i = 0; i < numChars; i++ ){
			bitString = bitString + '' + this.hexInBin( hexString.charAt( i ) );
		}

		bitString = bitString.substr( 0, numBits );
		return bitString;
	},

	// Check if a given nonce is a solution for this stamp and difficulty
	// the $difficulty number of leading bits must all be 0 to have a valid solution.
	// Async since hashHex() prefers crypto.subtle.digest() (Promise-based).
	checkNonce : async function( difficulty, stamp, nonce ) {
		var colHash = await this.hashHex( stamp + nonce );
		var checkBits = this.extractBits( colHash, difficulty );
		return ( checkBits == 0 );
	},

	sleep : function( ms ) {
		return new Promise( resolve => setTimeout( resolve, ms ) );
	},

	// Iterate through as many nonces as it takes to find one that gives us a solution hash at the target difficulty.
	findHash : async function() {
		var hashStamp = gdpr_compliant_recaptcha_stamp;
		// Difficulty travels with the freshly-fetched token (AP4 prep); fall back to
		// the page-load value from gdprPow for safety if a response ever omits it.
		var hashDifficulty = gdpr_compliant_recaptcha_difficulty || gdprPow.difficulty;

		var nonce = 1;

		while( ! ( await this.checkNonce( hashDifficulty, hashStamp, nonce ) ) ) {
			nonce++;
			if ( nonce % 10000 == 0 ) {
				let remaining = Math.round( ( Math.pow( 2, hashDifficulty ) - nonce ) / 10000 );
				// Don't peg the CPU and prevent the browser from rendering these updates
				//await this.sleep( 100 );
			}
		}
		gdpr_compliant_recaptcha_nonce = nonce;

		fetch(gdprPow.ajaxUrl, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			// No client-supplied IP is posted anymore: the server never trusted it, and
			// token validity does not depend on an address at all (see class-stamp-token.php).
			body: 'action=check_stamp' +
					'&hashStamp=' + encodeURIComponent(hashStamp) +
					'&hashDifficulty=' + encodeURIComponent(hashDifficulty) +
					'&hashNonce=' + encodeURIComponent(nonce)
		})
		.then(function (response) {
			// Read the check_stamp response body to detect a solve-time re-challenge.
			// window.fetch is wrapped by handleFetchResponse, which consumes the ORIGINAL
			// body via response.text() and hands us back a CLONE — so calling .json() on
			// THIS (returned/cloned) response is safe. Defensive: an empty / non-JSON body
			// (older server builds still answer with an empty wp_die()) falls through to
			// the legacy behaviour below (just remember the solved token). The server has
			// no distinct HTTP failure status for a rejected solve, so a genuinely rejected
			// solve simply yields no token row server-side and check_request() falls back
			// to the IP path — identical to no token at all.
			var rememberSolved = function () {
				gdpr_compliant_recaptcha_token = hashStamp;
				gdpr_compliant_recaptcha.updateFormTokenFields(hashStamp);
			};
			var handleParsed = function (data) {
				if (data && data.rechallenge === true && typeof data.stamp === 'string') {
					// Chain continues: adopt the chain token as the CURRENT submission
					// token immediately (a mid-chain submit then posts the chain token →
					// server uses the adaptive poll window) and keep computing without any
					// user interaction. findHash() is async, so this "recursion" runs in a
					// microtask — no synchronous stack growth however long the chain runs.
					gdpr_compliant_recaptcha_stamp = data.stamp;
					gdpr_compliant_recaptcha_token = data.stamp;
					if (data.difficulty) {
						gdpr_compliant_recaptcha_difficulty = data.difficulty;
					}
					gdpr_compliant_recaptcha.updateFormTokenFields(data.stamp);
					gdpr_compliant_recaptcha.findHash();
					return;
				}
				// {accepted:true} or anything else: remember the solved base token.
				rememberSolved();
			};
			try {
				if (response && typeof response.text === 'function') {
					return response.text().then(function (bodyText) {
						handleParsed(gdpr_compliant_recaptcha.parseJsonLoose(bodyText));
					}).catch(rememberSolved);
				}
			} catch (e) {
				// Fall through to the legacy behaviour below.
			}
			rememberSolved();
		});
		return true;
	},

	// Last resort when get_stamp is unreachable: solve the token that was embedded at
	// page-render time via wp_localize_script (gdprPow.stamp — already seeded into
	// gdpr_compliant_recaptcha_stamp at the top of this file). It is a fresh,
	// server-verifiable StampToken, so the PoW can still run even when the get_stamp
	// Ajax round-trip fails (a WAF blocking admin-ajax GETs, a stray PHP notice
	// polluting the JSON, a transient 5xx). On a CACHED page the embedded token is
	// stale → the server rejects it on check_stamp → no row, exactly as today, never
	// worse. Fail-closed is untouched: this only changes what the LEGITIMATE client
	// attempts, never a server-side check.
	solveWithLocalizedStamp : function () {
		if ( typeof gdpr_compliant_recaptcha_stamp === 'string' && gdpr_compliant_recaptcha_stamp ) {
			if ( ! gdpr_compliant_recaptcha_difficulty ) {
				gdpr_compliant_recaptcha_difficulty = gdprPow.difficulty;
			}
			gdpr_compliant_recaptcha.findHash();
		}
	},

	initCaptcha : function ( attempt ) {
		attempt = attempt || 0;
		// Cache-busted and no-store: the answer is a SINGLE-USE token, so a cached copy
		// served to a second visitor makes both share one token — and one token pays for
		// at most TOKEN_MAX_USES submissions (see cacheBuster()). A cached token still
		// verifies (validity no longer depends on the address), it just runs out. The
		// `_=` parameter keeps `action=get_stamp` followed by `&`, so isPluginCall()
		// still recognises this as a plugin call.
		fetch(gdprPow.ajaxUrl + '?action=get_stamp&_=' + gdpr_compliant_recaptcha.cacheBuster(), {
			method: 'GET',
			cache: 'no-store',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
		})
		.then(function (response) {
			// Read as text and parse tolerantly: response.json() would REJECT on any
			// noise before the JSON (a PHP notice under display_errors, a BOM, an HTML
			// error page from a WAF/5xx). With no .catch that rejection silently killed
			// the whole pipeline → no stamp ever computed → every submission flagged spam.
			return response.text();
		})
		.then(function (text) {
			var data = gdpr_compliant_recaptcha.parseJsonLoose(text);
			if (data && typeof data.stamp === 'string' && data.stamp) {
				gdpr_compliant_recaptcha_stamp = data.stamp;
				gdpr_compliant_recaptcha_difficulty = data.difficulty || gdprPow.difficulty;
				gdpr_compliant_recaptcha.findHash();
				return;
			}
			// Unusable body: retry ONCE after a short backoff (self-heals a transient
			// notice/5xx), then fall back to the render-time embedded token.
			gdpr_compliant_recaptcha.retryOrFallback(attempt, 'get_stamp returned an unusable body');
		})
		.catch(function () {
			// Network/abort failure: same bounded retry → embedded-token fallback.
			gdpr_compliant_recaptcha.retryOrFallback(attempt, 'get_stamp request failed');
		});
	},

	// One bounded retry, then the localized-stamp fallback. Bounded so a persistently
	// broken get_stamp cannot turn into a request storm (the setInterval renew already
	// re-tries on its own cadence).
	retryOrFallback : function ( attempt, reason ) {
		if ( attempt < 1 ) {
			setTimeout( function () {
				gdpr_compliant_recaptcha.initCaptcha( attempt + 1 );
			}, 1500 );
			return;
		}
		if ( typeof console !== 'undefined' && console.warn ) {
			console.warn( 'gdpr-recaptcha: ' + reason + '; falling back to the embedded token.' );
		}
		gdpr_compliant_recaptcha.solveWithLocalizedStamp();
	},

	// Function to display a nice-looking error message
	displayErrorMessage : function(message) {
		// Create a div for the error message
		var errorMessageElement = document.createElement('div');
		errorMessageElement.className = 'error-message';
		errorMessageElement.textContent = message;

		// Style the error message
		errorMessageElement.style.position = 'fixed';
		errorMessageElement.style.top = '50%';
		errorMessageElement.style.left = '50%';
		errorMessageElement.style.transform = 'translate(-50%, -50%)';
		errorMessageElement.style.background = '#ff3333';
		errorMessageElement.style.color = '#ffffff';
		errorMessageElement.style.padding = '15px';
		errorMessageElement.style.borderRadius = '10px';
		errorMessageElement.style.zIndex = '1000';

		// Append the error message to the body
		document.body.appendChild(errorMessageElement);

		// Remove the error message after a delay (e.g., 5 seconds)
		setTimeout(function () {
			errorMessageElement.remove();
		}, 5000);
	},

	addFirstStamp : function(e){
		if( ! gdpr_compliant_recaptcha.stampLoaded){
			gdpr_compliant_recaptcha.stampLoaded = true;
			gdpr_compliant_recaptcha.initCaptcha();
			// Best-effort password-field harvest (marks password fields so their values
			// are not stored in the inbox). Wrapped in try/catch so a malformed field
			// name or exotic third-party markup can never throw out of this init and
			// starve the fetch/XHR interception + renew installed below.
			try {
				let forms = document.querySelectorAll('form');
				forms.forEach(form => {
					// Skip GET forms — a hidden hashPWFields on one would leak into the
					// URL just like the token would (see isGetForm()).
					if (gdpr_compliant_recaptcha.isGetForm(form)) {
						return;
					}
					let passwordInputs = form.querySelectorAll("input[type='password']");
					let hashPWFields = [];
					passwordInputs.forEach(input => {
						hashPWFields.push(gdpr_compliant_recaptcha.fieldNameToNestedObject(input.getAttribute('name')));
					});

					if (hashPWFields.length !== 0) {
						let hashPWFieldsInput = document.createElement('input');
						hashPWFieldsInput.type = 'hidden';
						hashPWFieldsInput.classList.add('hashPWFields');
						hashPWFieldsInput.name = 'hashPWFields';
						hashPWFieldsInput.value = btoa(JSON.stringify(hashPWFields));
						form.prepend(hashPWFieldsInput);
					}
				});
			} catch (harvestErr) {
				if (typeof console !== 'undefined' && console.warn) {
					console.warn('gdpr-recaptcha: password-field harvest skipped', harvestErr);
				}
			}

			// Re-capture the CURRENT fetch/XHR right before wrapping them, instead of
			// relying on the load-time snapshot taken at the top of this file. A third-
			// party script may have installed its OWN fetch/XHR wrapper between page load
			// and this first user interaction; wrapping the current functions keeps that
			// wrapper in the delegation chain rather than stomping it. (window.fetch is
			// only replaced below, so at this point it is never our own wrapper yet — the
			// guard is belt-and-suspenders.)
			if (typeof window !== 'undefined' && typeof window.fetch === 'function' && window.fetch !== gdpr_compliant_recaptcha.handleFetchResponse) {
				gdpr_compliant_recaptcha.originalFetch = window.fetch;
			}
			if (typeof XMLHttpRequest !== 'undefined') {
				gdpr_compliant_recaptcha.originalXhrOpen = XMLHttpRequest.prototype.open;
				gdpr_compliant_recaptcha.originalXhrSend = XMLHttpRequest.prototype.send;
			}

			// Override open method to store method and URL
			XMLHttpRequest.prototype.open = function (method, url) {
				this._method = method;
				this._url = url;
				return gdpr_compliant_recaptcha.originalXhrOpen.apply(this, arguments);
			};

			// Override send method to set up onreadystatechange dynamically
			XMLHttpRequest.prototype.send = function (data) {
				var self = this;
				var isPluginCall = gdpr_compliant_recaptcha.isPluginCall(self._url, data);
				var isPost = self._method && self._method.toUpperCase() === 'POST';

				// Best-effort AP3 token injection, mirroring the fetch wrapper — never
				// for the plugin's own get_stamp/check_stamp calls.
				if (!isPluginCall && isPost) {
					data = gdpr_compliant_recaptcha.injectTokenIntoBody(data);
				}

				function handleReadyStateChange() {
					if (self.readyState === 4 && self._method === 'POST') {
						if (!isPluginCall) {
							gdpr_compliant_recaptcha.scheduleRenew();
						}
						// Check for an error response
						if (self.status >= 200 && self.status < 300) {
							var responseData = self.responseType === 'json' ? self.response : self.responseText;
							if(gdpr_compliant_recaptcha.isValidJson(responseData)){
								// Parse the response JSON
								responseData = JSON.parse(responseData);
							}
							// Check if the gdpr_error_message parameter is present
							if (!responseData.success && responseData.data && responseData.data.gdpr_error_message) {
								// Show an error message
								gdpr_compliant_recaptcha.displayErrorMessage(responseData.data.gdpr_error_message);
								gdpr_compliant_recaptcha.abortController.abort();
								return null;
							}
						}
					}
					// Call the original onreadystatechange function
					if (self._originalOnReadyStateChange) {
						self._originalOnReadyStateChange.apply(self, arguments);
					}
				}

				// Set up onreadystatechange dynamically
				if (!this._originalOnReadyStateChange) {
					this._originalOnReadyStateChange = this.onreadystatechange;
					this.onreadystatechange = handleReadyStateChange;
				}

				// Call each override function in order
				gdpr_compliant_recaptcha.originalXhrSends.forEach(overrideFunction => {
					overrideFunction.apply(this, arguments);
				});

				var result = gdpr_compliant_recaptcha.originalXhrSend.apply(this, [data]);
				if (result instanceof Promise){
					return result.then(function() {});
				}else{
					return result;
				}
			};

			// Override window.fetch globally
			window.fetch = gdpr_compliant_recaptcha.handleFetchResponse;

			// Submit-capture fallback (AP3): sets/refreshes the hidden gdpr_pow_token
			// field on the form being submitted, right before it is, covering forms
			// rendered/added to the DOM after this one-time init already ran its
			// per-form pass above (late-rendered builders, modals, ...).
			document.addEventListener('submit', function (e) {
				if (e.target && e.target.tagName === 'FORM') {
					gdpr_compliant_recaptcha.updateFormTokenFields(gdpr_compliant_recaptcha_token);
				}
			}, true);

			setInterval( gdpr_compliant_recaptcha.initCaptcha, gdpr_compliant_recaptcha.renewIntervalMs( gdprPow.timeout ) );
		}
	}
}
if ( typeof window !== 'undefined' && typeof document !== 'undefined' ) {
	window.addEventListener( 'load', function gdpr_compliant_recaptcha_load () {
		document.addEventListener( 'keydown', gdpr_compliant_recaptcha.addFirstStamp, { once : true } );
		document.addEventListener( 'mousemove', gdpr_compliant_recaptcha.addFirstStamp, { once : true } );
		document.addEventListener( 'scroll', gdpr_compliant_recaptcha.addFirstStamp, { once : true } );
		document.addEventListener( 'click', gdpr_compliant_recaptcha.addFirstStamp, { once : true } );
	} );
}

// Expose the pure, DOM-independent helpers for the Node-based regression tests
// (tests/js/, run via `node --test`). No effect in the browser: `module` is undefined
// there, so this block is skipped and the file stays a plain enqueued script.
if ( typeof module !== 'undefined' && module.exports ) {
	module.exports = {
		parseJsonLoose : gdpr_compliant_recaptcha.parseJsonLoose,
		fieldNameToNestedObject : gdpr_compliant_recaptcha.fieldNameToNestedObject,
		renewIntervalMs : gdpr_compliant_recaptcha.renewIntervalMs,
		isGetForm : gdpr_compliant_recaptcha.isGetForm,
		cacheBuster : gdpr_compliant_recaptcha.cacheBuster,
		isPluginCall : gdpr_compliant_recaptcha.isPluginCall
	};
}
