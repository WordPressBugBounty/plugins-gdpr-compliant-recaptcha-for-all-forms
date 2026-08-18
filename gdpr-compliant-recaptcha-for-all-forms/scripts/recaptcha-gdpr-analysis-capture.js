/**
 * Direct-analysis overlay: interception, transport and bootstrap.
 *
 * Part of the direct-analysis overlay, split out of recaptcha-gdpr-analysis.js
 * (Dateigroessen-Welle 3, PLAN-DATEIGROESSE.md — the file was 1625 lines). Pure move,
 * no behaviour change: the functions below are byte-identical to their former places in
 * the object literal, they are only attached to it from here.
 *
 * What lives here: the three capture paths (handleFormSubmission for classic form
 * submits, XMLHttpRequestSend/XMLHttpRequestOpen and windowFetch for ajax — the latter
 * two are pushed onto recaptcha-gdpr-pow.js's originalXhrSends/originalFetches), every
 * server round-trip (persistEntry, restoreEntries, getPatterns, savePatterns), the
 * post-capture refresh (refreshCoverageAndGuide) and the init routine
 * (initiateAnalysis) plus the window 'load' hook that starts it.
 *
 * Last link of the dependency chain on purpose: the 'load' listener registered at the
 * bottom must not run before every other module has attached its half of the object.
 *
 * Loaded by Analysis::add_javascript() with a wp_enqueue_script() dependency that
 * guarantees recaptcha-gdpr-analysis.js (which DECLARES the object) ran first — see the
 * chain documented in that file's header.
 */

Object.assign( gdpr_compliant_recaptcha_analysis, {
	/** Functions to intercept submit actions */
	handleFormSubmission : function(form) {
		//The function is either called from a trigger that is passing an event containing the form, or by the overwritten submit function passing the form directly
		if (form instanceof Event) {
			form = form.target;
		}

		// Get form data and convert it to JSON format. Runs for ALL forms now (no longer
		// gated on a HTTP/relative "action" attribute) — persistence happens server-side
		// via persistEntry(), so there is no action-URL left to mutate.
		const formData = new FormData(form);
		let formDataJSON = {};
		formData.forEach((value, key) => {
			if(key.includes('[')){
				formDataJSON = gdpr_compliant_recaptcha_analysis.mergeNestedArrays(formDataJSON, gdpr_compliant_recaptcha_analysis.convertStringToJsonObject(key, value));
			}else{
				formDataJSON[key] = value;
			}
		});

		// Add input fields of type "submit" to formDataJSON
		const submitButtons = form.querySelectorAll('input[type="submit"][name], button[type="submit"][name]');
		submitButtons.forEach(submitButton => {
			if(submitButton.name.includes('[')){
				formDataJSON = gdpr_compliant_recaptcha_analysis.mergeNestedArrays(formDataJSON, gdpr_compliant_recaptcha_analysis.convertStringToJsonObject(submitButton.name, submitButton.value));
			}else{
				formDataJSON[submitButton.name] = submitButton.value;
			}
		});
		formDataJSON = gdpr_compliant_recaptcha_analysis.stripPasswordFields(formDataJSON, form);
		formDataJSON = gdpr_compliant_recaptcha_analysis.stripPluginFields(formDataJSON);
		// A form CAN target a REST route directly (its action attribute), even though
		// most captured submissions here are classic non-REST POSTs.
		const route = gdpr_compliant_recaptcha_analysis.extractRestRoute(form.getAttribute('action') || '');
		const entry = gdpr_compliant_recaptcha_analysis.updateJSONObject(formDataJSON, true, false, false, route);
		// The page is about to navigate away — persist via sendBeacon so the request
		// survives unload (fetch keepalive fallback inside persistEntry()).
		gdpr_compliant_recaptcha_analysis.persistEntry(entry, true);
		gdpr_compliant_recaptcha_analysis.refreshCoverageAndGuide(entry);
	},
	/** Persist a single captured/updated entry server-side (admin-ajax action
	 * `gdpr_analysis_store`, see Analysis::store_analysis_entry()) so it survives page
	 * navigation without any client-side storage. Only the single updated entry is sent
	 * — not the whole jsonArray.
	 *
	 * @param entry     The jsonArray item to persist (as returned by updateJSONObject()).
	 *                  No-op if falsy (e.g. the assign=true restore path never persists).
	 * @param useBeacon True in the submit path, where the page is about to navigate away:
	 *                  uses navigator.sendBeacon (falls back to fetch+keepalive) and
	 *                  fires immediately. False in the ajax-capture paths, where a plain
	 *                  debounced fetch is used instead (no unload risk, but ajax calls
	 *                  can burst).
	 */
	persistEntry : function(entry, useBeacon) {
		if (!entry) {
			return;
		}
		const name = entry.name;
		const send = function() {
			const formData = new FormData();
			formData.append('action', 'gdpr_analysis_store');
			formData.append('_ajax_nonce', gdprAnalysis.storeNonce);
			formData.append('payload', JSON.stringify(entry));

			if (useBeacon && navigator.sendBeacon) {
				navigator.sendBeacon(gdprAnalysis.ajaxUrl, formData);
			} else {
				// .bind(window): native fetch requires `this === window` (illegal
				// invocation otherwise) — mirrors originalFetchBound in
				// recaptcha-gdpr-pow.js's handleFetchResponse. Calling the captured
				// original (not the global window.fetch) also avoids re-entering our own
				// windowFetch ajax-capture interceptor with this very request.
				gdpr_compliant_recaptcha_analysis.originalFetch.bind(window)(gdprAnalysis.ajaxUrl, {
					method: 'POST',
					body: formData,
					keepalive: true,
				}).catch(function() {});
			}
		};

		if (useBeacon) {
			send();
		} else {
			// Debounce per entry name so a burst of ajax calls for the same submission
			// type doesn't spam admin-ajax.php with one request each.
			if (gdpr_compliant_recaptcha_analysis.persistDebounceTimers[name]) {
				clearTimeout(gdpr_compliant_recaptcha_analysis.persistDebounceTimers[name]);
			}
			gdpr_compliant_recaptcha_analysis.persistDebounceTimers[name] = setTimeout(function() {
				delete gdpr_compliant_recaptcha_analysis.persistDebounceTimers[name];
				send();
			}, 500);
		}
	},
	/** Fetch every direct-analysis entry the current admin captured recently (admin-ajax
	 * action `gdpr_analysis_restore`, see Analysis::restore_analysis_entries()) and
	 * rehydrate the overlay with them.
	 *
	 * Reuses updateJSONObject()'s existing assign=true branch — the same code path the
	 * old URL-parameter restore used (`updateJSONObject(wholeArray, false, false, true)`
	 * replaces jsonArray outright and renders one accordion element per entry). That
	 * keeps the accordion rendering byte-for-byte identical to the previous behaviour;
	 * the only change is where the array comes from (fetched entries instead of a
	 * base64 URL parameter).
	 *
	 * @param callback Called once restore has finished (success, failure, or no entries).
	 */
	restoreEntries : function(callback) {
		const formData = new FormData();
		formData.append('action', 'gdpr_analysis_restore');
		formData.append('_ajax_nonce', gdprAnalysis.storeNonce);

		// .bind(window): see the identical note in persistEntry() above.
		gdpr_compliant_recaptcha_analysis.originalFetch.bind(window)(gdprAnalysis.ajaxUrl, {
			method: 'POST',
			body: formData,
		})
		.then(function(response) { return response.json(); })
		.then(function(response) {
			if (response && response.success && response.data && Array.isArray(response.data.entries)) {
				const restoredArray = response.data.entries
					.map(function(item) { return item.payload; })
					.filter(function(payload) { return payload && typeof payload === 'object'; })
					.map(function(payload) {
						// Coverage must be re-evaluated against the CURRENT patterns/
						// actions, never trusted from the stored payload: checkPatterns()
						// only ever flips found to true, so a stale stored found=true
						// would show "Covered" forever — even after the admin removed
						// the pattern/action from the scope in the meantime.
						payload.found = false;
						payload.checked = false;
						return payload;
					});
				if (restoredArray.length) {
					gdpr_compliant_recaptcha_analysis.updateJSONObject(restoredArray, false, false, true);
					// Rendering above re-ran checkPatterns() on the reset entries. If any
					// restored submission is (now) uncovered, its render already set the
					// guide to 'captured'; otherwise explain the restored entries in the
					// armed state instead of the default "submit a form" prompt.
					var anyUncovered = gdpr_compliant_recaptcha_analysis.jsonArray.some(function(entry) {
						return entry && entry.submission && !entry.found;
					});
					if (!anyUncovered) {
						gdpr_compliant_recaptcha_analysis.setGuideState('armed', { restoredCount: restoredArray.length });
					}
				}
			}
		})
		.catch(function() {})
		.finally(function() {
			callback();
		});
	},
	/** Re-fetch patterns/actions (picks up background scope changes — e.g. the admin removing
	 * a pattern/action in another tab) and re-derive coverage for one entry right after it was
	 * captured/updated, then explicitly (re-)decide the guide state for it:
	 *  - now uncovered (submission && !found): show 'captured' for this entry, whether or not
	 *    it was covered before — this is what surfaces the "still flagged after a background
	 *    scope change" case the live-coverage fix targets.
	 *  - now covered, and the guide's last 'captured' state was for THIS SAME entry: transition
	 *    back to 'armed' (don't stay stuck pointing at an entry that no longer needs review).
	 *    Any other current guide state (saved/error/captured for a different entry) is left
	 *    untouched.
	 *
	 * Called from all three capture paths (handleFormSubmission, XMLHttpRequestSend,
	 * windowFetch) right after persistEntry().
	 */
	refreshCoverageAndGuide : function(entry) {
		if (!entry) {
			return;
		}
		gdpr_compliant_recaptcha_analysis.getPatterns(function() {
			var key = gdpr_compliant_recaptcha_analysis.jsonArray.indexOf(entry);
			if (key === -1) {
				return;
			}
			gdpr_compliant_recaptcha_analysis.createAkkordeonElements(key, true);
			var refreshed = gdpr_compliant_recaptcha_analysis.jsonArray[key];
			if (refreshed.submission && !refreshed.found) {
				gdpr_compliant_recaptcha_analysis.setGuideState('captured', { name: refreshed.name, akkordeonId: key });
			} else if (
				gdpr_compliant_recaptcha_analysis.guideState === 'captured'
				&& String(gdpr_compliant_recaptcha_analysis.lastCapturedAkkordeonId) === String(key)
			) {
				gdpr_compliant_recaptcha_analysis.setGuideState('armed');
			}
		});
	},
	savePatterns: function(key) {
		const params = new URLSearchParams();
		var name = gdpr_compliant_recaptcha_analysis.jsonArray[key]['name'];
		var wp_ajax = gdpr_compliant_recaptcha_analysis.jsonArray[key]['wp_ajax'];
		var err = false;
		if(!wp_ajax){
			var elements = document.getElementsByClassName('gdpr-key-check-' + key);
			var elements_values = document.getElementsByClassName("gdpr-value-check-" + key);
			var patternArray = {};
			if (elements.length > 0) {
				// Hier kannst du mit den gefundenen Elementen arbeiten';
				for (var i = 0; i < elements.length; i++) {
					var element = elements[i];
					if(element.checked){                            
						var peer = document.getElementById(element.getAttribute("peer"));
						if(peer.checked){
							gdpr_compliant_recaptcha_analysis.insertIntoNestedObject(patternArray, element.value, peer.value);
						}else{
							gdpr_compliant_recaptcha_analysis.insertIntoNestedObject(patternArray, element.value, null);
						}
					}
				}
			}
			var arrayKeys = Object.keys(patternArray);
			if (arrayKeys.length > 0) {
				params.append('key', JSON.stringify(patternArray));
				params.append('standard', false);
			}else{
				gdpr_compliant_recaptcha_analysis.setGuideState('error', { message: gdprAnalysis.i18n.chooseAttributes });
				err = true;
				function blinkElement(element, times, speed) {
					var count = 0;
					var interval = setInterval(function () {
						element.style.visibility = (element.style.visibility === 'hidden') ? 'visible' : 'hidden';

						if (++count === times * 2) {
							clearInterval(interval);
						}
					}, speed);
				}
				// Iterate through the elements and set the background color to red
				for (var i = 0; i < elements.length; i++) {
					blinkElement(elements[i], 2, 500);
					elements[i].style.boxShadow = "0 0 10px lightcoral";
				}
				for (var i = 0; i < elements_values.length; i++) {
					blinkElement(elements_values[i], 2, 500);
					elements_values[i].style.boxShadow = "0 0 10px lightcoral";
				}
			}
		}else{
			params.append('key', name);
			params.append('standard', true);
		}
		if(!err){
			// CSRF token — verified server-side via check_ajax_referer(STORE_NONCE_ACTION).
			params.append('_ajax_nonce', gdprAnalysis.storeNonce);
			gdpr_compliant_recaptcha_analysis.showSpinner();
			fetch(gdprAnalysis.ajaxUrl + '?action=save_pattern_frontend', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded'
				},
				body: params.toString() // Include the parameters in the request body
			})
			.then(response => {
				gdpr_compliant_recaptcha_analysis.hideSpinner();
				if (!response.ok) {
					// Check for non-200 status codes
					throw new Error(`HTTP error! Status: ${response.status} | ${response.error_message}`);
				}
				return response.json();
			})
			.then(response => {
				if(response.data.error_message){
					gdpr_compliant_recaptcha_analysis.setGuideState('error', { message: response.data.error_message });
				}else{
					gdpr_compliant_recaptcha_analysis.getPatterns(function(){
						gdpr_compliant_recaptcha_analysis.createAkkordeonElements(key, true);
					});
					gdpr_compliant_recaptcha_analysis.setGuideState('saved', { type: wp_ajax ? 'action' : 'pattern' });
				}
			});
		}
	},
	/**Ajax-Call to get patterns and actions for submission type recognition */
	getPatterns : function(callback){
		fetch(gdprAnalysis.ajaxUrl + '?action=get_patterns&_ajax_nonce=' + encodeURIComponent(gdprAnalysis.storeNonce), {
			method: 'GET',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
		})
		.then(response => response.json())
		.then(response => {
			gdpr_compliant_recaptcha_analysis.patterns = response.patterns;
			for (const key in gdpr_compliant_recaptcha_analysis.patterns) {
				gdpr_compliant_recaptcha_analysis.patterns[key] = JSON.parse(gdpr_compliant_recaptcha_analysis.patterns[key]);
			}
			gdpr_compliant_recaptcha_analysis.actions = response.actions;
			gdpr_compliant_recaptcha_analysis.routes = response.routes;
			gdpr_compliant_recaptcha_analysis.checkPatterns();
			callback();
		});
	},
	//Function to overwrite XMLHttpRequests.send
	XMLHttpRequestSend : function(data){
		// Hier kannst du den ausgehenden Request-Body (data) bearbeiten oder loggen
		if (this._method === 'POST') {
			var jsonData = gdpr_compliant_recaptcha_analysis.formToJSON(data);
			if (gdpr_compliant_recaptcha_analysis.isOwnPluginAction(jsonData)) {
				return;
			}
			jsonData = gdpr_compliant_recaptcha_analysis.stripPluginFields(gdpr_compliant_recaptcha_analysis.stripPasswordFields(jsonData));
			var submission = false;
			var ajax = true;
			if (data && data instanceof FormData) {
				submission = true;
			}
			// this._url: set by recaptcha-gdpr-pow.js's XMLHttpRequest.prototype.open
			// override, which calls this function via originalXhrSends.forEach(fn.apply(this, ...)).
			var route = gdpr_compliant_recaptcha_analysis.extractRestRoute(this._url);
			const entry = gdpr_compliant_recaptcha_analysis.updateJSONObject(jsonData, submission, ajax, false, route);
			gdpr_compliant_recaptcha_analysis.persistEntry(entry, false);
			gdpr_compliant_recaptcha_analysis.refreshCoverageAndGuide(entry);
		}
		//return gdpr_compliant_recaptcha_analysis.originalXhrSend.apply(this, arguments);
	},
	//Function to overwrite XMLHttpRequests.open
	XMLHttpRequestOpen : function(method, url){
		this._method = method;
		this._url = url;
		return gdpr_compliant_recaptcha_analysis.originalXhrOpen.apply(this, arguments);
	},
	//Function to overwrite window.fetch
	windowFetch : function(input, init) {
		// Hier kannst du die URL und Optionen des ausgehenden Requests bearbeiten oder loggen
		if (init && init.method && init.method.toUpperCase() === 'POST' && init.body) {
			var jsonData = gdpr_compliant_recaptcha_analysis.formToJSON(init.body);
			if (gdpr_compliant_recaptcha_analysis.isOwnPluginAction(jsonData)) {
				return;
			}
			jsonData = gdpr_compliant_recaptcha_analysis.stripPluginFields(gdpr_compliant_recaptcha_analysis.stripPasswordFields(jsonData));
			var submission = false;
			var ajax = true;
			if (init.body && init.body instanceof FormData) {
				submission = true;
			}
			// input is normally a plain URL string here (see handleFetchResponse()'s
			// `var url = input`), but fetch() also allows a Request object — read its
			// .url in that case rather than stringifying the object itself.
			var requestUrl = (input && typeof input === 'object' && 'url' in input) ? input.url : input;
			var route = gdpr_compliant_recaptcha_analysis.extractRestRoute(requestUrl);
			const entry = gdpr_compliant_recaptcha_analysis.updateJSONObject(jsonData, submission, ajax, false, route);
			gdpr_compliant_recaptcha_analysis.persistEntry(entry, false);
			gdpr_compliant_recaptcha_analysis.refreshCoverageAndGuide(entry);
		}
		//return gdpr_compliant_recaptcha_analysis.originalFetch.apply(this, arguments);
	},
	//Function to initiate the analysis on the load page event
	initiateAnalysis : function(){

		// Create blocking overlay div
		var blockingOverlay = document.createElement('div');
		blockingOverlay.id = 'blockingOverlay';
		document.body.appendChild(blockingOverlay);

		// Create spinner div
		var divElement = document.createElement('div');
		divElement.className = 'centered-spinner';
		divElement.setAttribute('hidden', true);

		const logoImage = document.createElement("div");
		logoImage.classList.add("logoImageLarge");

		var centerElement = document.createElement('center');
		var strongElement = document.createElement('strong');
		strongElement.textContent = gdprAnalysis.i18n.loading;

		var brElement1 = document.createElement('br');
		var brElement2 = document.createElement('br');

		var imgElement = document.createElement('img');
		imgElement.src = '/wp-includes/js/tinymce/skins/lightgray/img/loader.gif';
		imgElement.alt = 'Description of the image';

		// Append elements to their respective parents
		centerElement.appendChild(logoImage);
		centerElement.appendChild(strongElement);
		centerElement.appendChild(brElement1);
		centerElement.appendChild(brElement2);
		centerElement.appendChild(imgElement);

		divElement.appendChild(centerElement);
		document.body.appendChild(divElement);

		gdpr_compliant_recaptcha_analysis.showSpinner(gdprAnalysis.i18n.initiating);

		gdpr_compliant_recaptcha_analysis.getPatterns(function(){
			// Attach event listeners for submits to all forms
			const pageForms = document.querySelectorAll('form');
			pageForms.forEach(form => {
				form.addEventListener('submit', gdpr_compliant_recaptcha_analysis.handleFormSubmission, false);
			});
			pageForms.forEach(form => {
				form.submit = function() {
					gdpr_compliant_recaptcha_analysis.handleFormSubmission(this);
					// Call the original submit method to submit the form
					HTMLFormElement.prototype.submit.call(this);
				};
			});

			// Overwrite standard XMLHttpRequest functions open and send to intercept post requests that use XMLHttpRequest
			async function pruefeVariable(callback) {
				let versuche = 0;
			
				while (versuche < 5) {
					if (typeof gdpr_compliant_recaptcha !== 'undefined') {
						callback();
						return; // Die Funktion beenden, da die Variable existiert
					} else {
						versuche++;
						if(versuche < 5){
							await warte(1000);
						}
					}
				}
			}
			function warte(ms) {
				return new Promise(resolve => setTimeout(resolve, ms));
			}

			pruefeVariable(function(){
				//XMLHttpRequest.prototype.open = gdpr_compliant_recaptcha_analysis.XMLHttpRequestOpen;
				//XMLHttpRequest.prototype.send = gdpr_compliant_recaptcha_analysis.XMLHttpRequestSend;
				gdpr_compliant_recaptcha.originalXhrSends.push(gdpr_compliant_recaptcha_analysis.XMLHttpRequestSend);
				// Overwrite standard fetch function to intercept post requests that use fetch
				//window.fetch = gdpr_compliant_recaptcha_analysis.windowFetch;
				gdpr_compliant_recaptcha.originalFetches.push(gdpr_compliant_recaptcha_analysis.windowFetch);
			});

			// Rehydrate previously captured submissions from the server (survives page
			// navigation without any client-side storage — see restoreEntries()).

			// The analysis window (header + guide strip) is created immediately here, even
			// with zero captured entries yet, instead of lazily on first capture - see
			// ensureAnalysisWindow(). createAkkordeonElements() also calls it (idempotent)
			// so a capture racing ahead of this point still gets a window.
			gdpr_compliant_recaptcha_analysis.ensureAnalysisWindow();

			gdpr_compliant_recaptcha_analysis.restoreEntries(function(){
				gdpr_compliant_recaptcha_analysis.hideBlockingOverlay();
				gdpr_compliant_recaptcha_analysis.hideSpinner();
				// Only fall back to the default armed prompt if the restore pass didn't
				// already set a more specific state (captured for an uncovered restored
				// entry, or armed-with-restoredCount) — an unconditional reset here
				// would clobber it.
				if (gdpr_compliant_recaptcha_analysis.guideState === 'armed' && !(gdpr_compliant_recaptcha_analysis.guideCtx || {}).restoredCount) {
					gdpr_compliant_recaptcha_analysis.setGuideState('armed');
				}
			});
		});
	},
} );

if ( typeof window !== 'undefined' ) {
	window.addEventListener( 'load', gdpr_compliant_recaptcha_analysis.initiateAnalysis);
}
