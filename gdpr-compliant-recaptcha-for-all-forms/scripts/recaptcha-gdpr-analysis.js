/**
 * Direct-analysis-mode frontend overlay: lets an admin capture not-yet-covered form
 * submissions and add recognition patterns/actions live from the page.
 *
 * Enqueued + localized by Analysis::add_javascript() as the global `gdprAnalysis`
 * ( { ajaxUrl, storeNonce, i18n:{…} } ). Only loaded when POW_DIRECT_ANALYSIS_MODE is on
 * and the current user can manage_options. Object literal `gdpr_compliant_recaptcha_analysis`.
 *
 * Persistence: captured entries no longer survive page navigation via a client-side
 * mechanism (no cookies/localStorage/URL-parameters — Art. 5(3) ePrivacy stays out of
 * scope for this admin-only overlay). Instead, every captured/updated entry is
 * persisted server-side via persistEntry()
 * (admin-ajax action `gdpr_analysis_store`, see Analysis::store_analysis_entry()) and
 * re-fetched on load via restoreEntries() (`gdpr_analysis_restore`).
 */
var gdpr_compliant_recaptcha_analysis = {
	idCounter : 0,
	jsonArray : [],
	patterns : [],
	actions : [],
	currentName : '',
	persistDebounceTimers : {},
	originalXhrOpen : XMLHttpRequest.prototype.open,
	originalXhrSend : XMLHttpRequest.prototype.send,
	originalFetch : window.fetch,//.bind(window),
	/** Remove the plugin's OWN injected fields from a captured submission before it is
	 * analyzed/persisted. Security-relevant, not cosmetic: a recognition pattern saved
	 * from a capture that includes e.g. `gdpr_pow_token` would only match POSTs that
	 * CARRY the token — a bot simply omitting the field would fall out of the pattern
	 * and thus out of the spam check entirely. Plugin-injected fields must never become
	 * part of a pattern (they are also useless as a display name — seekName() would
	 * otherwise label form entries "gdpr_pow_token").
	 */
	stripPluginFields : function(jsonData) {
		if (jsonData && typeof jsonData === 'object') {
			delete jsonData['gdpr_pow_token'];
			delete jsonData['hashPWFields'];
		}
		return jsonData;
	},
	/** Delete the value at the given key path (array of segments) from a nested object. */
	removeByPath : function(obj, segments) {
		if (!obj || typeof obj !== 'object' || !segments || !segments.length) {
			return;
		}
		if (segments.length === 1) {
			delete obj[segments[0]];
			return;
		}
		gdpr_compliant_recaptcha_analysis.removeByPath(obj[segments[0]], segments.slice(1));
	},
	/** The plugin's OWN ajax actions. Client-side twin of the server's
	 * excluded_actions_for_analysis (Stamp::save_for_analysis): the PoW client posts
	 * get_stamp/check_stamp through the very fetch/XHR interceptors this overlay
	 * installs — without this guard the plugin's own traffic shows up as a capturable
	 * "form" (and saving it as an action would make the spam check monitor itself).
	 */
	isOwnPluginAction : function(jsonData) {
		return !!jsonData && typeof jsonData === 'object'
			&& ['get_stamp', 'check_stamp', 'gdpr_analysis_store', 'gdpr_analysis_restore', 'save_pattern_frontend'].includes(jsonData.action);
	},
	/** Name heuristic for password-carrying fields (fallback when no type info exists). */
	isPasswordKey : function(key) {
		const k = String(key).toLowerCase();
		return k.includes('password') || k.includes('passwort') || /^(pwd|passwd|pass|pass1|pass2|user_pass)$/.test(k);
	},
	/** Remove password field VALUES from a captured submission before it is persisted.
	 * Security-relevant: analysis entries are stored server-side and readable by every
	 * admin — without this, one admin logging in (or a user submitting a password form)
	 * while direct-analysis mode is active would leak the cleartext password to all
	 * other admins. Three layers, most authoritative first:
	 *  1. The plugin's own hashPWFields marker (recaptcha-gdpr-pow.js injects it into
	 *     every form at init, listing the form's input[type=password] names) — it
	 *     travels inside the serialized body, so it also covers the XHR/fetch paths.
	 *  2. A live DOM check on the form (form-capture path only).
	 *  3. A key-name heuristic — covers dynamically added forms (which never got the
	 *     marker) and hand-built ajax bodies. A false positive only costs one field in
	 *     an analysis capture; a false negative would leak a password.
	 * Must run BEFORE stripPluginFields(), which deletes the hashPWFields marker.
	 */
	stripPasswordFields : function(jsonData, form) {
		if (!jsonData || typeof jsonData !== 'object') {
			return jsonData;
		}
		if (typeof jsonData['hashPWFields'] === 'string') {
			try {
				JSON.parse(atob(jsonData['hashPWFields'])).forEach(nested => {
					const segments = [];
					let node = nested;
					while (node && typeof node === 'object') {
						const key = Object.keys(node)[0];
						if (key === undefined) {
							break;
						}
						segments.push(key);
						node = node[key];
					}
					gdpr_compliant_recaptcha_analysis.removeByPath(jsonData, segments);
				});
			} catch (e) {
				// Malformed marker — layers 2/3 below still apply.
			}
		}
		if (form && form.querySelectorAll) {
			form.querySelectorAll('input[type="password"][name]').forEach(input => {
				gdpr_compliant_recaptcha_analysis.removeByPath(jsonData, input.getAttribute('name').match(/[^\[\]]+/g) || []);
			});
		}
		(function walk(obj) {
			if (!obj || typeof obj !== 'object') {
				return;
			}
			Object.keys(obj).forEach(key => {
				if (gdpr_compliant_recaptcha_analysis.isPasswordKey(key)) {
					delete obj[key];
				} else {
					walk(obj[key]);
				}
			});
		})(jsonData);
		return jsonData;
	},
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
		const entry = gdpr_compliant_recaptcha_analysis.updateJSONObject(formDataJSON, true);
		// The page is about to navigate away — persist via sendBeacon so the request
		// survives unload (fetch keepalive fallback inside persistEntry()).
		gdpr_compliant_recaptcha_analysis.persistEntry(entry, true);
		gdpr_compliant_recaptcha_analysis.refreshCoverageAndGuide(entry);
	},
	findMissingElements : function(obj1, obj2) {
		const diff = {};
		for (const key in obj2) {
			if (obj2.hasOwnProperty(key)) {
				if (!obj1.hasOwnProperty(key)) {
					diff[key] = obj2[key];
				} else if (typeof obj2[key] === 'object' && obj2[key] !== null) {
					const nestedDiff = gdpr_compliant_recaptcha_analysis.findMissingElements(obj1[key], obj2[key]);
					if (Object.keys(nestedDiff).length > 0) {
						diff[key] = nestedDiff;
					}
				}
			}
		}
		return diff;
	},
	recursiveComparison: function(obj1, obj2, ignoreNull) {
		for (const key in obj1) {
			if (obj1.hasOwnProperty(key)) {
				if (!obj2.hasOwnProperty(key)) {
					return false;
				}
				if (typeof obj1[key] === 'object' && obj1[key] !== null) {
					if (!gdpr_compliant_recaptcha_analysis.recursiveComparison(obj1[key], obj2[key])) {
						return false;
					}
				} else {
					if(!(ignoreNull && (obj1[key] === null || obj1[key] === undefined))){
						if (obj1[key] !== obj2[key]) {
							return false;
						}
					}
				}
			}
		}
		return true;
	},
	//Checks whether a JSON object 1 is comletely inherited in an JSON object 2 and if so, in addition results a JSON that contains the diff
	compareJSONObjects : function(obj1, obj2, ignoreNull = false) {
		const areEqual = gdpr_compliant_recaptcha_analysis.recursiveComparison(obj1, obj2, ignoreNull);
		let missingElements = {};
		if( areEqual )
			missingElements = gdpr_compliant_recaptcha_analysis.findMissingElements(obj1, obj2);

		return { result: areEqual, json: obj1, diff: missingElements };
	},
	/**Retrieves a probable useful name for a given JSON the represents the payload of an ajax-call in WordPress */
	seekName : function(jsonObject){
		if( 'action' in jsonObject)
			return jsonObject['action'];
		else
			return Object.keys(jsonObject)[0];
	},
	//Updating the array of JSON objects
	updateJSONObject : function (newJsonObject, submission = false, ajax = false, assign = false) {
		let name = gdpr_compliant_recaptcha_analysis.seekName(newJsonObject);
		let found = false;
		let wp_ajax = ajax && newJsonObject.hasOwnProperty('action') ? true : false;
		// Tracks the entry that was created/updated by this call, so callers (the submit
		// and ajax-capture paths) can hand it to persistEntry(). Stays null for the
		// assign=true restore path — those entries are already persisted server-side and
		// must not be written back.
		let resultEntry = null;
		//Check whether the field already exists. If so update the field
		for (const key in gdpr_compliant_recaptcha_analysis.jsonArray) {
			let result = null;
			let post = false;
			let diff = null;
			if( gdpr_compliant_recaptcha_analysis.jsonArray[key]['name'] == name
				|| gdpr_compliant_recaptcha_analysis.recursiveComparison(newJsonObject, gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'])
				|| gdpr_compliant_recaptcha_analysis.recursiveComparison(gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'], newJsonObject)
			){
				found = true;
				if(gdpr_compliant_recaptcha_analysis.jsonArray[key]['name'] !== name && ajax){
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['name'] = name;
				}
				//Check whether either the existing field, or the new field is a post and update it respectively
				if(!ajax && gdpr_compliant_recaptcha_analysis.jsonArray[key]['ajax']){
					diff = gdpr_compliant_recaptcha_analysis.findMissingElements(newJsonObject, gdpr_compliant_recaptcha_analysis.jsonArray[key]['json']);
					post = true;
				}else if(ajax && !gdpr_compliant_recaptcha_analysis.jsonArray[key]['ajax']){
					diff = gdpr_compliant_recaptcha_analysis.findMissingElements(gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'], newJsonObject);
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'] = newJsonObject;
					post = true;
				}
				//Update other fields if posts was found either way round, otherwise update all fields
				if(post){
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['diff'] = diff;
					if(submission)
						gdpr_compliant_recaptcha_analysis.jsonArray[key]['submission'] = submission;
					if(ajax)
						gdpr_compliant_recaptcha_analysis.jsonArray[key]['ajax'] = ajax;
					if(wp_ajax)
						gdpr_compliant_recaptcha_analysis.jsonArray[key]['wp_ajax'] = wp_ajax;
				}else{
					diff = gdpr_compliant_recaptcha_analysis.findMissingElements(gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'], newJsonObject);
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['diff'] = diff;
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'] = newJsonObject;
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['submission'] = submission;
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['ajax'] = ajax;
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['wp_ajax'] = wp_ajax;
				}

				gdpr_compliant_recaptcha_analysis.createAkkordeonElements (key, true);
				resultEntry = gdpr_compliant_recaptcha_analysis.jsonArray[key];
				break;
			}
		}
		if(!found){
			if(assign){
				gdpr_compliant_recaptcha_analysis.jsonArray = newJsonObject;
				var keys = Object.keys(gdpr_compliant_recaptcha_analysis.jsonArray);
				// Loop through the keys using forEach
				keys.forEach(function(key) {
					gdpr_compliant_recaptcha_analysis.createAkkordeonElements (key);
				});
			}else{
				gdpr_compliant_recaptcha_analysis.jsonArray.push({
						json: newJsonObject, // jsonData object
						diff: {}, // Additional meta information
						checked: false,
						found: false,
						saved: false,
						submission: submission,
						ajax : ajax,
						wp_ajax: wp_ajax,
						name: name,
				});
				var keys = Object.keys(gdpr_compliant_recaptcha_analysis.jsonArray);
				var lastKey = keys[keys.length - 1];
				gdpr_compliant_recaptcha_analysis.createAkkordeonElements (lastKey);
				resultEntry = gdpr_compliant_recaptcha_analysis.jsonArray[lastKey];
			}
		}
		return resultEntry;
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
	/** Derives coverage (jsonArray[key].found) fresh against the currently loaded
	 * patterns/actions on every call — NOT a one-shot "check once, cache forever": a
	 * pattern/action removed in the background (e.g. by the admin editing scope in another
	 * tab) must make a previously-covered entry show as uncovered again on the next call,
	 * which a stale cached found=true would hide. Called both from createAkkordeonElements()
	 * (render-time) and refreshCoverageAndGuide() (after each capture, following a fresh
	 * getPatterns() fetch). The `checked` field on entries is no longer consulted here (kept
	 * on the objects, but unused) — every entry is always re-derived.
	 */
	checkPatterns : function(){
		for (const key in gdpr_compliant_recaptcha_analysis.jsonArray) {
			if (gdpr_compliant_recaptcha_analysis.jsonArray.hasOwnProperty(key)) {
				const currentJson = gdpr_compliant_recaptcha_analysis.jsonArray[key]['json'];
				gdpr_compliant_recaptcha_analysis.jsonArray[key]['found'] = false;
				// Compare the 'json' attribute of currentJson with each comparisonJson
				for (const patternKey in gdpr_compliant_recaptcha_analysis.patterns) {
					const currentPattern = gdpr_compliant_recaptcha_analysis.patterns[patternKey];
					if (gdpr_compliant_recaptcha_analysis.compareJSONObjects(currentPattern, currentJson, true)['result']) {
						// Do something if they are equal
						gdpr_compliant_recaptcha_analysis.jsonArray[key]['found'] = true;
						break; // Exit the loop once a match is found
					}
				}
				// Compare the "ation"-attribute inside the 'json' attribute of currentJson with each comparisonJson
				if (
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['json']['action']
					&& gdpr_compliant_recaptcha_analysis.actions
					&& gdpr_compliant_recaptcha_analysis.actions.length
					&& gdpr_compliant_recaptcha_analysis.actions.includes(gdpr_compliant_recaptcha_analysis.jsonArray[key]['json']['action'])
				){
					gdpr_compliant_recaptcha_analysis.jsonArray[key]['found'] = true;
				}
			}
		}
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
	insertIntoNestedObject: function (existingObject, inputString, value) {
		// String in ein Array aufteilen
		var keys = inputString.split("->");
		
		// Aktuelles Objekt auf das bestehende Objekt setzen
		var currentObject = existingObject;

		// Iteriere durch die Schlüssel und erstelle das verschachtelte assoziative Array
		for (var i = 0; i < keys.length; i++) {
			var key = keys[i];
			if (i === keys.length - 1) {
				// Wenn wir den letzten Schlüssel erreicht haben, setze den Wert
				currentObject[key] = value;
			} else {
				// Andernfalls erstelle ein neues leeres Objekt, wenn der Schlüssel noch nicht existiert
				if (!currentObject[key]) {
					currentObject[key] = {};
				}
				currentObject = currentObject[key];
			}
		}
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
		fetch(gdprAnalysis.ajaxUrl + '?action=get_patterns', {
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
			gdpr_compliant_recaptcha_analysis.checkPatterns();
			callback();
		});
	},
	// Function to convert a nested name of an HTML element into a JSON object
	convertStringToJsonObject : function(inputString, value) {
		var keys = inputString.split(/\]\[|\[|\]/).filter(function(key) {
			return key.length > 0;
		});
		var result = {};

		keys.reduce(function(obj, key, index, array) {
			obj[key] = index === array.length - 1 ? value : {};
			return obj[key];
		}, result);

		return result;
	},
	// Merging nested objects
	deepMerge : function(target, source) {
		for (const key in source) {
			if (source.hasOwnProperty(key)) {
				if (typeof source[key] === 'object' && source[key] !== null) {
					if (!target[key]) {
						target[key] = Array.isArray(source[key]) ? [] : {};
					}
					gdpr_compliant_recaptcha_analysis.deepMerge(target[key], source[key]);
				} else {
					target[key] = source[key];
				}
			}
		}
		return target;
	},
	// Merging nested and flat objects
	mergeNestedArrays : function(arr1, arr2) {
		let mergedArray;

		if (Array.isArray(arr1)) {
			mergedArray = [...arr1, ...arr2];
		} else if (typeof arr1 === 'object' && arr1 !== null) {
			mergedArray = Array.isArray(arr2) ? [...arr2] : [arr2];
			for (const key in arr1) {
				if (arr1.hasOwnProperty(key)) {
					if( typeof arr1[key] !== 'object' ){
						mergedArray.push({ [key]: arr1[key] });
					}else{
						mergedArray.push({ [key]: gdpr_compliant_recaptcha_analysis.deepMerge({}, arr1[key]) });
					}
				}
			}
		} else {
			mergedArray = Array.isArray(arr2) ? [...arr2] : [arr2];
		}
		return mergedArray.reduce((merged, obj) => {
			gdpr_compliant_recaptcha_analysis.deepMerge(merged, obj);
			return merged;
		}, {});
	},
	//Converts form data to a JSON
	formToJSON : function(data){
		var jsonData;
		if (data instanceof FormData) {
			// If data is a FormData object, convert it to JSON
			jsonData = {};
			data.forEach(function(value, key) {
				if(key.includes('[')){
					jsonData = gdpr_compliant_recaptcha_analysis.mergeNestedArrays(jsonData, gdpr_compliant_recaptcha_analysis.convertStringToJsonObject(key, value));
				}else{
					jsonData[key] = value;
				}
			});
		} else if (typeof data === 'string') {
			// If data is a string, try to parse it as JSON
			try {
				jsonData = JSON.parse(data);
			} catch (error) {
				// If parsing fails, treat it as URL-encoded string
				jsonData = {};
				data.split('&').forEach(function(pair) {
					pair = pair.split('=');
					jsonData[pair[0]] = decodeURIComponent(pair[1] || '');
				});
			}
		} else if (typeof data === 'object') {
			// If data is already an object, keep it as is
			jsonData = data;
		}
		return jsonData;
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
			const entry = gdpr_compliant_recaptcha_analysis.updateJSONObject(jsonData, submission, ajax);
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
			const entry = gdpr_compliant_recaptcha_analysis.updateJSONObject(jsonData, submission, ajax);
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
	//This function creates a form out of a nested json array
	createFormForNestedObject : function(obj, parentKey = null, form, id, wp_ajax, diff=false) {
		if(!parentKey && !diff){
			var tableHeadings = null;

			if(!wp_ajax)
				tableHeadings = [
					gdprAnalysis.i18n.choosePattern, 
					gdprAnalysis.i18n.key,
					gdprAnalysis.i18n.choosePattern,
					gdprAnalysis.i18n.key
				];
			else
				tableHeadings = [
					gdprAnalysis.i18n.key,
					gdprAnalysis.i18n.value
				];
	
			// Erstelle die Kopfspalte der Tabelle
			const thead = document.createElement("thead");
			const headingRow = document.createElement("tr");
		
			tableHeadings.forEach(headingText => {
				const th = document.createElement("th");
				th.textContent = headingText;
				th.style.border = "1px solid #ddd";
				th.style.padding = "8px";
				th.style.textAlign = "left";
				headingRow.appendChild(th);
			});
		
			thead.appendChild(headingRow);
			form.appendChild(thead);
		}
	
		for (const key in obj) {
			if (obj.hasOwnProperty(key)) {
				const fullPath = parentKey ? `${parentKey}_${key}` : key;
				const value = obj[key];
	
				// Nur Eingabefelder für einfache Werte erstellen, nicht für verschachtelte Objekte
				if (typeof value !== "object" || value === null) {
					if(diff){
						var diff_element = document.getElementsByClassName('row-'+fullPath);
						diff_element[0].classList.add('hiddenInput');
					}else{
						// Erstelle eine Zeile in der Tabelle
						const row = document.createElement("tr");
						row.classList.add('row-'+fullPath);
						if(!wp_ajax){
							var hiddenInputs = document.querySelectorAll('input[name="'+fullPath+'"][type="hidden"], button[name="'+fullPath+'"], input[name="'+fullPath+'"][type="submit"]');
							if(hiddenInputs.length)
								row.classList.add('hiddenInput');

							// 1. Spalte: Checkbox für den Key
							const keyCheckboxCell = document.createElement("td");
							keyCheckboxCell.style.border = "1px solid #ddd";
							keyCheckboxCell.style.padding = "8px";
							const keyCheckbox = document.createElement("input");
							keyCheckbox.type = "checkbox";
							keyCheckbox.classList.add('gdpr-key-check-' + id);
							keyCheckbox.setAttribute('peer', `value_check_${fullPath}` + id);
							keyCheckbox.id = `key_check_${fullPath}` + id;
							keyCheckbox.name = `key_check_${fullPath}` + id;
							keyCheckbox.value = fullPath;
							keyCheckbox.onchange = function() {
								var valueCheckbox = document.getElementById('value_check_' + fullPath + id);
								if(valueCheckbox.checked)
									valueCheckbox.checked = this.checked;
							};
							keyCheckboxCell.appendChild(keyCheckbox);
							row.appendChild(keyCheckboxCell);
						}
		
						// 2. Spalte: Eingabefeld für den Key
						const keyInputCell = document.createElement("td");
						keyInputCell.style.border = "1px solid #ddd";
						keyInputCell.style.padding = "8px";
						const keyInput = document.createElement("input");
						keyInput.type = "text";
						keyInput.id = `key_input_${fullPath}` + id;
						keyInput.name = `key_input_${fullPath}` + id;
						keyInput.value = fullPath;
						keyInput.readOnly = true; 
						keyInputCell.appendChild(keyInput);
						row.appendChild(keyInputCell);
						
						if(!wp_ajax){
							// 3. Spalte: Checkbox für den Wert
							const valueCheckboxCell = document.createElement("td");
							valueCheckboxCell.style.border = "1px solid #ddd";
							valueCheckboxCell.style.padding = "8px";
							const valueCheckbox = document.createElement("input");
							valueCheckbox.type = "checkbox";
							valueCheckbox.classList.add('gdpr-value-check-' + id);
							valueCheckbox.setAttribute('peer', `key_check_${fullPath}` + id);
							valueCheckbox.id = `value_check_${fullPath}` + id;
							valueCheckbox.name = `value_check_${fullPath}` + id;
							valueCheckbox.value = value;
							valueCheckbox.onchange = function() {
								var keyCheckbox = document.getElementById('key_check_' + fullPath + id);
								if(!keyCheckbox.checked)
									keyCheckbox.checked = this.checked;
							};
							valueCheckboxCell.appendChild(valueCheckbox);
							row.appendChild(valueCheckboxCell);
						}
		
						// 4. Spalte: Eingabefeld für den Wert
						const valueInputCell = document.createElement("td");
						valueInputCell.style.border = "1px solid #ddd";
						valueInputCell.style.padding = "8px";
						const valueInput = document.createElement("input");
						valueInput.type = "text";
						valueInput.id = `value_input_${fullPath}` + id;
						valueInput.name = `value_input_${fullPath}` + id;
						valueInput.value = value;
						valueInput.readOnly = true; 
						valueInputCell.appendChild(valueInput);
						row.appendChild(valueInputCell);
		
						// Füge die Zeile der Tabelle hinzu
						form.appendChild(row);
					}
				}
	
				// Wenn es sich um ein verschachteltes Objekt handelt, rufe die Funktion rekursiv auf
				if (typeof value === "object" && value !== null) {
					gdpr_compliant_recaptcha_analysis.createFormForNestedObject(value, fullPath, form, id, wp_ajax, diff);
				}
			}
		}
	},

	/** Lazily create (or return the existing) analysis window shell: outer container,
	 * header, guide strip (#gdpr-guide-bar - see renderGuide()), and body. Called both from
	 * initiateAnalysis() (so the window - including the guide strip - exists immediately at
	 * init, even before any entry was captured) and from createAkkordeonElements() (so a
	 * capture racing ahead of that init call still gets a window). Idempotent: a second call
	 * is a cheap no-op beyond returning the existing body element.
	 */
	ensureAnalysisWindow : function() {
		var gdprContainerBody = document.getElementById("gdpr-analysis-containerbody");
		if (gdprContainerBody) {
			return gdprContainerBody;
		}

		// Single fixed, top-centered element (no nested fixed-in-fixed wrapper — see
		// the comment on #gdpr-analysis-container in style_analysis.css for why).
		var outerContainer = document.createElement("div");
		outerContainer.id = "gdpr-analysis-container";
		document.body.appendChild(outerContainer);
		outerContainer.offsetWidth;
		outerContainer.style.opacity = "1";

		// Header + guide strip live together in a sticky wrapper so both stay visible
		// while the accordion body scrolls underneath them (see #gdpr-analysis-sticky in
		// style_analysis.css).
		var stickyWrap = document.createElement("div");
		stickyWrap.id = "gdpr-analysis-sticky";
		outerContainer.appendChild(stickyWrap);

		var gdprContainerHeader = document.createElement("div");
		gdprContainerHeader.id = "gdpr-analysis-containerheader";
		stickyWrap.appendChild(gdprContainerHeader);

		var headerTitle = document.createElement("div");
		headerTitle.classList.add("gdpr-header-title");
		headerTitle.textContent = gdprAnalysis.i18n.windowTitle;
		gdprContainerHeader.appendChild(headerTitle);

		var headerLogo = document.createElement("div");
		headerLogo.classList.add("logoImage");
		gdprContainerHeader.appendChild(headerLogo);

		// Guide strip: directly after the header, inside the sticky wrapper - filled by
		// renderGuide() (invoked below for the initial 'armed' render).
		var guideBar = document.createElement("div");
		guideBar.id = "gdpr-guide-bar";
		stickyWrap.appendChild(guideBar);

		gdprContainerBody = document.createElement("div");
		gdprContainerBody.id = "gdpr-analysis-containerbody";
		outerContainer.appendChild(gdprContainerBody);

		// Make the window draggable via its header (desktop only — see dragElement()).
		gdpr_compliant_recaptcha_analysis.dragElement(outerContainer);

		// Render the guide strip immediately so an empty window right after init isn't
		// blank; reflects whatever guideState/guideCtx already hold (default 'armed').
		gdpr_compliant_recaptcha_analysis.renderGuide();

		return gdprContainerBody;
	},
	//This function creates the elements containing a form for each json
	createAkkordeonElements : function(id, update = false){
		gdpr_compliant_recaptcha_analysis.checkPatterns();
		var akkordeonEinheit = null;
		var found = gdpr_compliant_recaptcha_analysis.jsonArray[id]['found'];
		var submission = gdpr_compliant_recaptcha_analysis.jsonArray[id]['submission'];
		var wp_ajax = gdpr_compliant_recaptcha_analysis.jsonArray[id]['wp_ajax'];
		var name = gdpr_compliant_recaptcha_analysis.jsonArray[id]['name'];
		var ajax = gdpr_compliant_recaptcha_analysis.jsonArray[id]['ajax'];
		var diff = null;
		if(gdpr_compliant_recaptcha_analysis.jsonArray[id]['diff'])
			diff = gdpr_compliant_recaptcha_analysis.jsonArray[id]['diff'];
		var json = gdpr_compliant_recaptcha_analysis.jsonArray[id]['json'];
		if(update){
			var gdprContainerOld = document.getElementById('gdprContainer_' + id);
			if (gdprContainerOld) 
				gdprContainerOld.remove();
		}
		var gdprContainerBody = gdpr_compliant_recaptcha_analysis.ensureAnalysisWindow();
		const gdprContainer = document.createElement("div");
		gdprContainer.id = 'gdprContainer_' + id;
		gdprContainer.classList.add("gdprContainer");
		gdprContainer.style.padding = "10px";
		gdprContainer.style.width = "100%";
		gdprContainerBody.appendChild(gdprContainer);

		const akkordeonButton = document.createElement("akkordeonButton");
		akkordeonButton.classList.add("akkordeonButton");
		var statusIcon = '';
		var notCovered = false;

		if( submission && !found ){
			akkordeonButton.classList.add("hiddenInput");
			statusIcon = '❗';
			notCovered = true;
		}else if( submission && found ){
			akkordeonButton.classList.add("coveredSubmissionType");
			statusIcon = '✔️';
		}else{
			akkordeonButton.classList.add("ordinarySubmissionType");
		}
		if(notCovered && !update){
			gdpr_compliant_recaptcha_analysis.setGuideState('captured', { name: name, akkordeonId: id });
		}
		akkordeonButton.id = "akkordeonButton_" + id;
		akkordeonButton.setAttribute("peer", "akkordeonEinheit_" + id);

		// Built via createElement/textContent (not innerHTML) — `name` originates from a
		// captured form submission and must never be interpreted as HTML.
		const akkordeonRow = document.createElement("div");
		akkordeonRow.classList.add("gdpr-akkordeon-row");

		if(statusIcon){
			const statusIconEl = document.createElement("span");
			statusIconEl.classList.add("gdpr-status-icon");
			statusIconEl.textContent = statusIcon;
			akkordeonRow.appendChild(statusIconEl);
		}

		const nameEl = document.createElement("strong");
		nameEl.classList.add("gdpr-entry-name");
		nameEl.textContent = name;
		nameEl.title = name;
		akkordeonRow.appendChild(nameEl);

		const badgesEl = document.createElement("span");
		badgesEl.classList.add("gdpr-badges");
		if(submission){
			const coverBadge = document.createElement("span");
			coverBadge.classList.add("gdpr-badge", found ? "gdpr-badge-covered" : "gdpr-badge-not-covered");
			coverBadge.textContent = found ? gdprAnalysis.i18n.covered : gdprAnalysis.i18n.notCovered;
			badgesEl.appendChild(coverBadge);
		}
		if(ajax){
			const ajaxBadge = document.createElement("span");
			ajaxBadge.classList.add("gdpr-badge", "gdpr-badge-neutral");
			ajaxBadge.textContent = gdprAnalysis.i18n.ajax;
			badgesEl.appendChild(ajaxBadge);
		}
		if(submission){
			const submissionBadge = document.createElement("span");
			submissionBadge.classList.add("gdpr-badge", "gdpr-badge-neutral");
			submissionBadge.textContent = gdprAnalysis.i18n.submission;
			badgesEl.appendChild(submissionBadge);
		}
		akkordeonRow.appendChild(badgesEl);

		akkordeonButton.appendChild(akkordeonRow);
		akkordeonButton.style.opacity = "0";
		akkordeonButton.style.transition = "opacity 1s ease-in-out";
		gdprContainer.appendChild(akkordeonButton);
		akkordeonButton.offsetWidth;
		akkordeonButton.style.opacity = "1";
		
		akkordeonEinheit = document.createElement("div");
		akkordeonEinheit.classList.add("akkordeonEinheit");
		akkordeonEinheit.id = "akkordeonEinheit_" + id;
		akkordeonEinheit.style.display = "none";
		gdprContainer.appendChild(akkordeonEinheit);
		
		var akkordeon = document.getElementById("akkordeonButton_" + id);
		akkordeon.addEventListener("click", function() {
			this.classList.toggle("akkordeonButtonAktiv");
			var akkordeonEinheit = document.getElementById(this.getAttribute("peer"));
			akkordeonEinheit.style.display = akkordeonEinheit.style.display === "block" ? "none" : "block";
		});

		// Micro-hint for not-yet-covered entries, replacing the old recommendAction/
		// recommendPattern popup text — shown inline above the form on every render (not
		// just on first capture, unlike the guide bar's one-shot 'captured' toast).
		if(notCovered){
			const akkordeonHint = document.createElement("div");
			akkordeonHint.classList.add("gdpr-akkordeon-hint");
			akkordeonHint.textContent = wp_ajax ? gdprAnalysis.i18n.guideHintAction : gdprAnalysis.i18n.guideHintPattern;
			akkordeonEinheit.appendChild(akkordeonHint);
		}

		// Dynamisches Erzeugen des Formulars im Div-Element
		const gdprForm = document.createElement("form");
		gdprForm.id = "gdpr-analysis-form-" + id;
		akkordeonEinheit.appendChild(gdprForm);
		
		var buttonBefore = document.createElement('button');
		buttonBefore.classList.add('gdprSaveButton');
		if(wp_ajax){
			buttonBefore.textContent = gdprAnalysis.i18n.saveAction;
			buttonBefore.onclick = function () {
				gdpr_compliant_recaptcha_analysis.savePatterns(id);
			};
		}else{
			buttonBefore.textContent = gdprAnalysis.i18n.savePattern;
			buttonBefore.onclick = function () {
				gdpr_compliant_recaptcha_analysis.savePatterns(id);
			};
		}
		gdprForm.appendChild(buttonBefore);

		if(!wp_ajax){
			const hintColoredFields = document.createElement("div");
			hintColoredFields.classList.add("hiddenInput");
			hintColoredFields.innerHTML = gdprAnalysis.i18n.techFields;
			gdprForm.appendChild(hintColoredFields);
		}

		// Dynamisches Erzeugen der Tabelle im Formular
		const gdprTable = document.createElement("table");
		gdprTable.id = "gdpr-analysis-table-" + id;
		gdprTable.style.width = "100%";
		gdprTable.style.borderCollapse = "collapse";
		gdprTable.style.marginTop = "10px";
		gdprForm.appendChild(gdprTable);

		var buttonAfter = document.createElement('button');
		buttonAfter.classList.add('gdprSaveButton');
		if(wp_ajax){
			buttonAfter.textContent = gdprAnalysis.i18n.saveAction;
			buttonAfter.onclick = function () {
				gdpr_compliant_recaptcha_analysis.savePatterns(id);
			};
		}else{
			buttonAfter.textContent = gdprAnalysis.i18n.savePattern;
			buttonAfter.onclick = function () {
				gdpr_compliant_recaptcha_analysis.savePatterns(id);
			};
		}
		gdprForm.appendChild(buttonAfter);

		gdprForm.addEventListener('submit', function(event) {
			event.preventDefault();
		});

		gdpr_compliant_recaptcha_analysis.createFormForNestedObject(json, null, gdprTable, id, wp_ajax);
		// Funktion aufrufen, um das Formular zu erstellen
		if(diff && !wp_ajax){
			gdpr_compliant_recaptcha_analysis.createFormForNestedObject(diff, null, gdprTable, id, wp_ajax, true);
		}
		// Dragging is wired once, at window-creation time, in ensureAnalysisWindow() - the
		// window element itself isn't recreated on every accordion render.
	},
	dragElement : function(elmnt){
		// Disabled on small screens: no free-floating drag on mobile (matches the CSS
		// resize:none media query for #gdpr-analysis-container).
		if (window.matchMedia && window.matchMedia('(max-width: 640px)').matches) {
			return;
		}
		var pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;
		if (document.getElementById(elmnt.id + "header")) {
		/* if present, the header is where you move the DIV from:*/
		document.getElementById(elmnt.id + "header").onmousedown = dragMouseDown;
		} else {
		/* otherwise, move the DIV from anywhere inside the DIV:*/
		elmnt.onmousedown = dragMouseDown;
		}
	
		function dragMouseDown(e) {
		e = e || window.event;
		e.preventDefault();
		// The element is initially centered via CSS (left:50% + transform:translateX(-50%),
		// see #gdpr-analysis-container). Freeze its current on-screen position as explicit
		// px left/top and drop the transform *before* the first drag delta is applied —
		// otherwise offsetLeft (unaffected by transform) wouldn't match the visual position
		// and the box would jump sideways by half its width the moment dragging starts.
		var rect = elmnt.getBoundingClientRect();
		elmnt.style.transform = 'none';
		elmnt.style.left = rect.left + 'px';
		elmnt.style.top = rect.top + 'px';
		// get the mouse cursor position at startup:
		pos3 = e.clientX;
		pos4 = e.clientY;
		document.onmouseup = closeDragElement;
		// call a function whenever the cursor moves:
		document.onmousemove = elementDrag;
		}
	
		function elementDrag(e) {
		e = e || window.event;
		e.preventDefault();
		// calculate the new cursor position:
		pos1 = pos3 - e.clientX;
		pos2 = pos4 - e.clientY;
		pos3 = e.clientX;
		pos4 = e.clientY;
		// set the element's new position:
		elmnt.style.top = (elmnt.offsetTop - pos2) + "px";
		elmnt.style.left = (elmnt.offsetLeft - pos1) + "px";
		}
	
		function closeDragElement() {
		/* stop moving when mouse button is released:*/
		document.onmouseup = null;
		document.onmousemove = null;
		}      
	},
	/** Guide strip state machine (#gdpr-guide-bar), replacing the old stacking
	 * showInfo()/showSuccess()/showAlert() popups. Lives INSIDE the analysis window (sticky
	 * strip directly below the header - see ensureAnalysisWindow()), not as a standalone
	 * viewport-corner element. One element, replaced (not stacked) on every state change.
	 */
	guideState : 'armed',
	guideCtx : {},
	// Tracks the akkordeonId the guide last showed 'captured' for, so
	// refreshCoverageAndGuide() only auto-reverts to 'armed' when the entry that JUST became
	// covered is the one the guide is currently pointing at (not some unrelated entry).
	lastCapturedAkkordeonId : null,
	guideSavedTimer : null,

	/** Set the guide bar to a new state (armed|captured|saved|error) with optional context:
	 *  - captured: { name, akkordeonId } — akkordeonId enables the "Review entry" button.
	 *  - saved:    { type: 'pattern'|'action' }
	 *  - error:    { message }
	 * Auto-reverts to 'armed' ~4s after 'saved'.
	 */
	setGuideState : function(state, ctx) {
		gdpr_compliant_recaptcha_analysis.guideState = state;
		gdpr_compliant_recaptcha_analysis.guideCtx = ctx || {};
		if (state === 'captured') {
			gdpr_compliant_recaptcha_analysis.lastCapturedAkkordeonId =
				(ctx && ctx.akkordeonId !== undefined) ? ctx.akkordeonId : null;
		}
		if (gdpr_compliant_recaptcha_analysis.guideSavedTimer) {
			clearTimeout(gdpr_compliant_recaptcha_analysis.guideSavedTimer);
			gdpr_compliant_recaptcha_analysis.guideSavedTimer = null;
		}
		if (state === 'saved') {
			gdpr_compliant_recaptcha_analysis.guideSavedTimer = setTimeout(function() {
				gdpr_compliant_recaptcha_analysis.setGuideState('armed');
			}, 4000);
		}
		gdpr_compliant_recaptcha_analysis.renderGuide();
	},

	/** (Re)render the guide strip from the current guideState/guideCtx into #gdpr-guide-bar.
	 * The strip element itself lives inside the analysis window (ensureAnalysisWindow()); if
	 * the window hasn't been created yet (e.g. setGuideState() called very early), this
	 * creates it first so there's always somewhere to render into.
	 */
	renderGuide : function() {
		var state = gdpr_compliant_recaptcha_analysis.guideState;
		var ctx = gdpr_compliant_recaptcha_analysis.guideCtx;
		var bar = document.getElementById('gdpr-guide-bar');
		if (!bar) {
			gdpr_compliant_recaptcha_analysis.ensureAnalysisWindow();
			bar = document.getElementById('gdpr-guide-bar');
		}
		bar.className = 'gdpr-guide-state-' + state;
		bar.innerHTML = '';

		var panel = document.createElement('div');
		panel.className = 'gdpr-guide-panel';

		var icon = document.createElement('div');
		icon.className = 'gdpr-guide-icon';
		if (state === 'armed') {
			icon.classList.add('gdpr-guide-pulse-dot');
		} else if (state === 'saved') {
			icon.textContent = '✓';
		} else if (state === 'error') {
			icon.textContent = '✖';
		} else if (state === 'captured') {
			icon.textContent = '❗';
		}

		var textWrap = document.createElement('div');
		textWrap.className = 'gdpr-guide-text';

		var title = document.createElement('div');
		title.className = 'gdpr-guide-title';
		var subtitle = document.createElement('div');
		subtitle.className = 'gdpr-guide-subtitle';

		var actionBtn = null;

		if (state === 'armed') {
			title.textContent = gdprAnalysis.i18n.guideArmedTitle;
			// After a server-side restore of earlier captures (all of them covered),
			// explain why entries are already listed although nothing was submitted
			// on this page view — plain "submit a form" would look buggy.
			subtitle.textContent = ctx.restoredCount
				? gdprAnalysis.i18n.guideRestoredSubtitle.replace('%d', ctx.restoredCount)
				: gdprAnalysis.i18n.guideArmedSubtitle;
		} else if (state === 'captured') {
			title.textContent = gdprAnalysis.i18n.guideCapturedTitle.replace('%s', ctx.name || '');
			subtitle.textContent = gdprAnalysis.i18n.guideCapturedSubtitle;
			if (ctx.akkordeonId !== undefined && ctx.akkordeonId !== null) {
				actionBtn = document.createElement('button');
				actionBtn.type = 'button';
				actionBtn.className = 'gdpr-guide-action';
				actionBtn.textContent = gdprAnalysis.i18n.guideReviewEntry;
				actionBtn.addEventListener('click', function() {
					gdpr_compliant_recaptcha_analysis.reviewEntry(ctx.akkordeonId);
				});
			}
		} else if (state === 'saved') {
			title.textContent = ctx.type === 'action' ? gdprAnalysis.i18n.guideActionSaved : gdprAnalysis.i18n.guidePatternSaved;
			subtitle.textContent = gdprAnalysis.i18n.guideSavedSubtitle;
		} else if (state === 'error') {
			title.textContent = ctx.message || '';
		}

		textWrap.appendChild(title);
		if (subtitle.textContent) {
			textWrap.appendChild(subtitle);
		}

		panel.appendChild(icon);
		panel.appendChild(textWrap);

		if (state !== 'error') {
			var dots = document.createElement('div');
			dots.className = 'gdpr-guide-dots';
			var filled = state === 'armed' ? 1 : (state === 'captured' ? 2 : 3);
			for (var i = 0; i < 3; i++) {
				var dot = document.createElement('span');
				dot.className = 'gdpr-guide-dot' + (i < filled ? ' gdpr-guide-dot-active' : '');
				dots.appendChild(dot);
			}
			panel.appendChild(dots);
		}

		if (actionBtn) {
			panel.appendChild(actionBtn);
		}

		bar.appendChild(panel);
	},

	/** "Review entry" action from the guide bar's captured state: scroll the analysis
	 * window to the given accordion entry, open it if collapsed, and briefly highlight it.
	 */
	reviewEntry : function(id) {
		var button = document.getElementById('akkordeonButton_' + id);
		if (!button) {
			return;
		}
		var unit = document.getElementById(button.getAttribute('peer'));
		if (unit && unit.style.display !== 'block') {
			button.classList.add('akkordeonButtonAktiv');
			unit.style.display = 'block';
		}
		button.scrollIntoView({ behavior: 'smooth', block: 'center' });
		button.classList.add('gdpr-highlight');
		setTimeout(function() {
			button.classList.remove('gdpr-highlight');
		}, 1500);
	},

	showSpinner : function(message=gdprAnalysis.i18n.loading) {
		var spinner = document.querySelector('.centered-spinner');
		var strongElement = document.querySelector('.centered-spinner center strong');
		strongElement.textContent = message;
		spinner.removeAttribute('hidden'); // Remove the hidden attribute
	},

	hideSpinner : function() {
		var spinner = document.querySelector('.centered-spinner');
		spinner.setAttribute('hidden', true);
	},

	hideBlockingOverlay : function(){
		var blockingOverlay = document.getElementById('blockingOverlay');
		blockingOverlay.setAttribute('hidden', true);
	},
}

window.addEventListener( 'load', gdpr_compliant_recaptcha_analysis.initiateAnalysis);
