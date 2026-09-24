/**
 * Admin message-management UI: the one-click actions (list/pattern save, block value,
 * monitor route, gibberish toggle, treat-as-credential).
 *
 * Split out of recaptcha-gdpr-messages.js (PLAN-OFFENE-PUNKTE.md V4) once that file hit
 * its line-count ceiling. Enqueued right after it, with a dependency on it, by
 * Message_Page::render_message_page() — so this file loads as a classic script in the
 * SAME global scope as recaptcha-gdpr-messages.js and can use its globals directly:
 * `gdprMsg` (localized by wp_localize_script on the FIRST script; see
 * trait-message-script-data.php), plus showSpinner/hideSpinner/showAlert/showSuccess and
 * collectFilters(), all defined there.
 *
 * NOTE: the functions here are called by name from inline on* handlers in the
 * server-rendered per-row HTML (saveListParameter/savePattern/blockValue/monitorRoute/
 * toggleGibberishField/treatAsCredential), so they MUST stay global — do not wrap in an
 * IIFE/module.
 */

function saveListParameter(e, listKey, buttonId, hide = false) {
	e.preventDefault();
	var xhr = new XMLHttpRequest();
	xhr.open("POST", gdprMsg.ajaxUrl, true);
	xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

	xhr.onload = function() {
		if (xhr.status === 200) {
			var response = JSON.parse(xhr.responseText);
			if (response.success == 1) {
				//if(hide){
				document.querySelector("#results").innerHTML = response.result;
				document.querySelector(".paginator").innerHTML = response.paginator;

				var akkordeon = document.getElementsByClassName("akkordeonButton");
				for (var i = 0; i < akkordeon.length; i++) {
					akkordeon[i].addEventListener("click", function() {
						this.classList.toggle("akkordeonButtonAktiv");
						var akkordeonEinheit = this.nextElementSibling;
						if (akkordeonEinheit.style.display === "block") {
						akkordeonEinheit.style.display = "none";
						} else {
						akkordeonEinheit.style.display = "block";
						}
					});
					akkordeon[i].addEventListener("click", function() {
						var id = this.id.split("_")[1];
						getDetail(id);
					}, { once: true });
				}
				showSuccess(gdprMsg.i18n.actionAdded);
				/*}else{
					document.getElementById(buttonId).style.display = "none";
					showSuccess(response.data.message);
				}*/
			} else {
				showAlert(response.error_message);
			}
		}
		hideSpinner();
	};
	var search = document.querySelector('.messageSearch').value;
	showSpinner()
	xhr.send(
		"action=save_list_parameter" +
		"&messageType=" + gdprMsg.messageType +
		"&listKey=" + encodeURIComponent(listKey) +
		"&hide=" + hide +
		"&security_nonce=" + gdprMsg.nonces.saveList +
		"&search=" + encodeURIComponent(search) +
		"&search_nonce=" + gdprMsg.nonces.search +
		collectFilters()
	);
}

function insertIntoNestedObject(existingObject, inputString, value) {
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
}

function savePattern(e, messageID, buttonId, hide = false) {
	e.preventDefault();
	var elements = document.getElementsByClassName("check_return_attribute_" + messageID);
	var elements_values = document.getElementsByClassName("check_return_value_" + messageID);
	var patternArray = {};
	if (elements.length > 0) {
		// Hier kannst du mit den gefundenen Elementen arbeiten';
		for (var i = 0; i < elements.length; i++) {
			var element = elements[i];
			if(element.checked){                            
				var peer = document.getElementById(element.getAttribute("peer"));
				if(peer.checked){
					insertIntoNestedObject(patternArray, element.value, peer.value);
				}else{
					insertIntoNestedObject(patternArray, element.value, null);
				}
			}
		}
	}
	var arrayKeys = Object.keys(patternArray);
	if (arrayKeys.length > 0) {
		var xhr = new XMLHttpRequest();
		xhr.open("POST", gdprMsg.ajaxUrl, true);
		xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

		xhr.onload = function() {
			if (xhr.status === 200) {
				var response = JSON.parse(xhr.responseText);
				if (response.success == 1) {
					//if(hide){
					document.querySelector("#results").innerHTML = response.result;
					document.querySelector(".paginator").innerHTML = response.paginator;

					var akkordeon = document.getElementsByClassName("akkordeonButton");
					for (var i = 0; i < akkordeon.length; i++) {
						akkordeon[i].addEventListener("click", function() {
							this.classList.toggle("akkordeonButtonAktiv");
							var akkordeonEinheit = this.nextElementSibling;
							if (akkordeonEinheit.style.display === "block") {
							akkordeonEinheit.style.display = "none";
							} else {
							akkordeonEinheit.style.display = "block";
							}
						});
						akkordeon[i].addEventListener("click", function() {
							var id = this.id.split("_")[1];
							getDetail(id);
						}, { once: true });
					}
					showSuccess(gdprMsg.i18n.patternSaved);
					/*}else{
						// Den Button ausblenden
						document.getElementById(buttonId).style.display = "none";
						showSuccess(response.data.message);
					}*/
				} else {
					// Fehler beim Speichern
					showAlert(response.data.error_message);
				}
			}
			hideSpinner();
		};
		var search = document.querySelector('.messageSearch').value;
		showSpinner();
		xhr.send(
			"action=save_pattern" +
			"&messageType=" + gdprMsg.messageType +
			"&key=" + encodeURIComponent(JSON.stringify(patternArray)) +
			"&hide=" + hide +
			"&security_nonce=" + gdprMsg.nonces.savePattern +
			"&search=" + encodeURIComponent(search) +
			"&search_nonce=" + gdprMsg.nonces.search +
			collectFilters()
		);
	}else{
		showAlert(gdprMsg.i18n.choosePattern);
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
}

// One-click "Block this sender"/"Block this domain" (BACKLOG baustein 2). Global,
// invoked from the inline onclick in the per-detail-row HTML. The server extracts
// the final email/domain again and enforces the self-DoS guard.
function blockValue(button) {
	var kind = button.getAttribute('data-kind');
	var value = button.getAttribute('data-value');
	// "Block this sender's domain" is broader than the other kinds — one click
	// blocks every current and future sender address at that domain, not just this
	// one message. Confirm before sending; the other kinds stay confirm-free.
	if (kind === 'sender_domain') {
		var atIndex = value.lastIndexOf('@');
		var domain = atIndex !== -1 ? value.substring(atIndex + 1) : value;
		if (!window.confirm(gdprMsg.i18n.confirmSenderDomain.replace('%s', domain))) {
			return;
		}
	}
	showSpinner();
	var xhr = new XMLHttpRequest();
	xhr.open('POST', gdprMsg.ajaxUrl, true);
	xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
	xhr.onload = function () {
		hideSpinner();
		var response = {};
		try {
			response = JSON.parse(xhr.responseText);
		} catch (e) {
			response = {};
		}
		if (xhr.status === 200 && response.success) {
			button.disabled = true;
			showSuccess((response.data && response.data.message) || gdprMsg.i18n.blocked);
		} else {
			showAlert((response.data && response.data.error_message) || gdprMsg.i18n.blockFailed);
		}
	};
	xhr.send(
		'action=gdpr_block_value' +
		'&messageType=' + encodeURIComponent(gdprMsg.messageType) +
		'&kind=' + encodeURIComponent(kind) +
		'&value=' + encodeURIComponent(value) +
		'&security_nonce=' + encodeURIComponent(gdprMsg.nonces.blockValue)
	);
}

// One-click "Monitor this route" (REST_ROUTES_PLAN.md AP5). Global, invoked from the
// inline onclick on the REST-route line above the detail table. The server appends the
// route to POW_REST_ROUTES, running it through the SAME self-lockout guard as the
// settings textarea (RestRoute::reject_self_lockout_lines()) — see
// Message_Page::monitor_route_callback().
function monitorRoute(button) {
	var route = button.getAttribute('data-route');
	showSpinner();
	var xhr = new XMLHttpRequest();
	xhr.open('POST', gdprMsg.ajaxUrl, true);
	xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
	xhr.onload = function () {
		hideSpinner();
		var response = {};
		try {
			response = JSON.parse(xhr.responseText);
		} catch (e) {
			response = {};
		}
		if (xhr.status === 200 && response.success) {
			button.disabled = true;
			showSuccess((response.data && response.data.message) || gdprMsg.i18n.routeMonitored);
		} else {
			showAlert((response.data && response.data.error_message) || gdprMsg.i18n.monitorFailed);
		}
	};
	xhr.send(
		'action=gdpr_monitor_route' +
		'&messageType=' + encodeURIComponent(gdprMsg.messageType) +
		'&route=' + encodeURIComponent(route) +
		'&security_nonce=' + encodeURIComponent(gdprMsg.nonces.monitorRoute)
	);
}

// Per-field gibberish toggle. Since 6.0.0 gibberish detection only ever looks at the
// fields listed for this form's signature, so this button both adds and removes — the
// case that usually brings someone here is "stop checking this one". The server refuses
// password-like names and re-checks the capability and nonce; see
// Message_Gibberish::gibberish_field_callback().
function toggleGibberishField(button) {
	var remove = button.getAttribute('data-selected') === '1';
	showSpinner();
	var xhr = new XMLHttpRequest();
	xhr.open('POST', gdprMsg.ajaxUrl, true);
	xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
	xhr.onload = function () {
		hideSpinner();
		var response = {};
		try {
			response = JSON.parse(xhr.responseText);
		} catch (e) {
			response = {};
		}
		if (xhr.status === 200 && response.success) {
			var nowSelected = response.data && response.data.selected === 1;
			button.setAttribute('data-selected', nowSelected ? '1' : '0');
			button.classList.toggle('is-selected', nowSelected);
			button.textContent = nowSelected ? gdprMsg.i18n.gibberishOn : gdprMsg.i18n.gibberishOff;
			showSuccess((response.data && response.data.message) || '');
		} else {
			showAlert((response.data && response.data.error_message) || gdprMsg.i18n.gibberishFailed);
		}
	};
	xhr.send(
		'action=gdpr_gibberish_field' +
		'&messageType=' + encodeURIComponent(gdprMsg.messageType) +
		'&field=' + encodeURIComponent(button.getAttribute('data-field')) +
		'&kind=' + encodeURIComponent(button.getAttribute('data-kind')) +
		'&signature=' + encodeURIComponent(button.getAttribute('data-signature')) +
		'&remove=' + (remove ? '1' : '0') +
		'&security_nonce=' + encodeURIComponent(gdprMsg.nonces.gibberish)
	);
}

// One-click "Treat as credential field": the rescue path of the learned
// credential-field list, for a password that is already readable in the inbox.
// Confirmed first, because it is irreversible for messages already received —
// the value is replaced in place, here and everywhere else. The server decides
// the field name again from the attribute path and refuses the names its own
// diagnostics depend on (see Credential_Learning::ajax_treat_as_credential()).
function treatAsCredential(button) {
	if (!window.confirm(gdprMsg.i18n.credentialAsk)) {
		return;
	}
	var attribute = button.getAttribute('data-attribute');
	var messageId = button.getAttribute('data-message');
	showSpinner();
	var xhr = new XMLHttpRequest();
	xhr.open('POST', gdprMsg.ajaxUrl, true);
	xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
	xhr.onload = function () {
		hideSpinner();
		var response = {};
		try {
			response = JSON.parse(xhr.responseText);
		} catch (e) {
			response = {};
		}
		if (xhr.status === 200 && response.success) {
			// Replace the cell's text with the stored replacement, so the admin sees
			// the effect instead of having to reload to believe it.
			var cell = button.parentNode;
			if (cell && response.data && response.data.value) {
				cell.textContent = response.data.value;
			}
			showSuccess((response.data && response.data.message) || gdprMsg.i18n.credentialSaved);
		} else {
			showAlert((response.data && response.data.error_message) || gdprMsg.i18n.credentialFailed);
		}
	};
	xhr.send(
		'action=gdpr_credential_field' +
		'&messageType=' + encodeURIComponent(gdprMsg.messageType) +
		'&messageID=' + encodeURIComponent(messageId) +
		'&attribute=' + encodeURIComponent(attribute) +
		'&security_nonce=' + encodeURIComponent(gdprMsg.nonces.credential)
	);
}
