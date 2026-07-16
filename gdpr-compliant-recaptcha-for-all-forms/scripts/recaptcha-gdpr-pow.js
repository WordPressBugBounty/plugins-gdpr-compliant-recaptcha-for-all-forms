/**
 * Client-side hashcash proof-of-work + Ajax error-message interception.
 *
 * Enqueued (in the page <head>, not the footer) by Stamp::add_script_to_header().
 * Per-request/config values arrive via wp_localize_script as the global `gdprPow`
 * ( { stamp, clientIp, difficulty, ajaxUrl, timeout } ).
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
var gdpr_compliant_recaptcha_stamp = gdprPow.stamp;
var gdpr_compliant_recaptcha_ip = gdprPow.clientIp;
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
	originalFetch : window.fetch,
	abortController : new AbortController(),
	originalXhrOpen : XMLHttpRequest.prototype.open,
	originalXhrSend : XMLHttpRequest.prototype.send,

	// Function to check if a string is a valid JSON
	isValidJson : function( str ) {
		try {
			JSON.parse( str );
			return true;
		} catch ( error ) {
			return false;
		}
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

	// Append (once) / refresh a hidden gdpr_pow_token field on every form. Appended at
	// the END (not prepended like hashPWFields): the field must never become the form's
	// first key — tooling that names a submission after its first field (e.g. the
	// direct-analysis overlay's seekName()) would otherwise label every form
	// "gdpr_pow_token".
	updateFormTokenFields : function (token) {
		if (!token) {
			return;
		}
		var forms = document.querySelectorAll('form');
		forms.forEach(function (form) {
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
		var clientIP = gdpr_compliant_recaptcha_ip;
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
			body: 'action=check_stamp' +
					'&hashStamp=' + encodeURIComponent(hashStamp) +
					'&hashDifficulty=' + encodeURIComponent(hashDifficulty) +
					'&clientIP=' + encodeURIComponent(clientIP) +
					'&hashNonce=' + encodeURIComponent(nonce)
		})
		.then(function (response) {
			// The server has no distinct HTTP failure status for a rejected solve
			// (wp_die() still answers 200) — same as before AP3, this does not
			// distinguish accept vs. reject. Remembering the stamp as the current
			// submission token is a best-effort optimization: if the solve was in
			// fact rejected server-side, check_request()'s per-token poll simply
			// finds no row and falls back to the IP path, same as no token at all.
			gdpr_compliant_recaptcha_token = hashStamp;
			gdpr_compliant_recaptcha.updateFormTokenFields(hashStamp);
		});
		return true;
	},

	initCaptcha : function(){
		fetch(gdprPow.ajaxUrl + '?action=get_stamp', {
			method: 'GET',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
		})
		.then(function (response) {
			return response.json();
		})
		.then(function (response) {
			gdpr_compliant_recaptcha_stamp = response.stamp;
			gdpr_compliant_recaptcha_ip = response.client_ip;
			gdpr_compliant_recaptcha_difficulty = response.difficulty || gdprPow.difficulty;
			gdpr_compliant_recaptcha.findHash();
		});

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
			let forms = document.querySelectorAll('form');
			//This is important to mark password fields. They shall not be posted to the inbox
			function convertStringToNestedObject(str) {
				var keys = str.match(/[^\[\]]+|\[[^\[\]]+\]/g); // Extrahiere Wörter und eckige Klammern
				var obj = {};
				var tempObj = obj;

				for (var i = 0; i < keys.length; i++) {
					var key = keys[i];

					// Wenn die eckigen Klammern vorhanden sind
					if (key.startsWith('[') && key.endsWith(']')) {
						key = key.substring(1, key.length - 1); // Entferne eckige Klammern
					}

					tempObj[key] = (i === keys.length - 1) ? null : {};
					tempObj = tempObj[key];
				}

				return obj;
			}
			forms.forEach(form => {
				let passwordInputs = form.querySelectorAll("input[type='password']");
				let hashPWFields = [];
				passwordInputs.forEach(input => {
					hashPWFields.push(convertStringToNestedObject(input.getAttribute('name')));
				});
				
				if (hashPWFields.length !== 0) {
					let hashPWFieldsInput = document.createElement('input');
					hashPWFieldsInput.type = 'hidden';
					hashPWFieldsInput.classList.add('hashPWFields');
					hashPWFieldsInput.name = 'hashPWFields';
					hashPWFieldsInput.value = btoa(JSON.stringify(hashPWFields));//btoa(hashPWFields);
					form.prepend(hashPWFieldsInput);
				}
			});

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

				result = gdpr_compliant_recaptcha.originalXhrSend.apply(this, [data]);
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

			setInterval( gdpr_compliant_recaptcha.initCaptcha, gdprPow.timeout * 60000 );
		}
	}
}
window.addEventListener( 'load', function gdpr_compliant_recaptcha_load () {
	document.addEventListener( 'keydown', gdpr_compliant_recaptcha.addFirstStamp, { once : true } );
	document.addEventListener( 'mousemove', gdpr_compliant_recaptcha.addFirstStamp, { once : true } );
	document.addEventListener( 'scroll', gdpr_compliant_recaptcha.addFirstStamp, { once : true } );
	document.addEventListener( 'click', gdpr_compliant_recaptcha.addFirstStamp, { once : true } );
} );
