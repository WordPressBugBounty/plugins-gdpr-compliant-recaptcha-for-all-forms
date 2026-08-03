/**
 * Admin message-management UI: inbox / spam / trash / analysis pages.
 *
 * Enqueued (footer) + localized by Message_Page::render_message_page() as the global
 * `gdprMsg` ( { ajaxUrl, messageType, nonces:{search,saveList,savePattern}, i18n:{...} } ).
 *
 * NOTE: the functions here are called by name from inline on* handlers in the
 * server-rendered per-row HTML (moveMessage/deleteSingleMessage/savePattern/…), so they
 * MUST stay global — do not wrap in an IIFE/module.
 */

function showSpinner() {
	var spinner = document.querySelector('.centered-spinner');
	spinner.removeAttribute('hidden'); // Remove the hidden attribute
}

function hideSpinner() {
	var spinner = document.querySelector('.centered-spinner');
	spinner.setAttribute('hidden', true); // Set the hidden attribute
}

function showAlert(message) {
			var alertDiv = document.createElement('div');
			alertDiv.className = 'centered-alert';
			alertDiv.textContent = message;

			document.body.appendChild(alertDiv);

			setTimeout(function () {
				document.body.removeChild(alertDiv);
			}, 5000); // Adjust the timeout value as needed
}

function showSuccess(message) {
			var alertDiv = document.createElement('div');
			alertDiv.className = 'centered-success';
			alertDiv.textContent = message;

			document.body.appendChild(alertDiv);

			setTimeout(function () {
				document.body.removeChild(alertDiv);
			}, 5000); // Adjust the timeout value as needed
}

document.addEventListener('DOMContentLoaded', function () {
	messageSearch(1);
	document.querySelector('.messageSearch').addEventListener('keyup', function() {
		messageSearch(1);
	});
	document.querySelector('.check_messages').addEventListener('click', function() {
		var checkboxes = document.querySelectorAll('.check_message');
		for (var i = 0; i < checkboxes.length; i++) {
			checkboxes[i].checked = this.checked;
		}
	});
});

function messageSearch( page ) {
	var search = document.querySelector('.messageSearch').value;
	var listedActions = document.querySelector('#listedActions') && document.querySelector('#listedActions').checked ? '&listedActions=' + document.querySelector('#listedActions').checked : '';
	var listedPatterns = document.querySelector('#listedPatterns') && document.querySelector('#listedPatterns').checked ? '&listedPatterns=' + document.querySelector('#listedPatterns').checked : '';
	var whitelistedSites = document.querySelector('#whitelistedSites') && document.querySelector('#whitelistedSites').checked ? '&whitelistedSites=' + document.querySelector('#whitelistedSites').checked : '';
	var whitelistedIPs = document.querySelector('#whitelistedIPs') && document.querySelector('#whitelistedIPs').checked ? '&whitelistedIPs=' + document.querySelector('#whitelistedIPs').checked : '';
	var hiddenActions = document.querySelector('#hiddenActions') && document.querySelector('#hiddenActions').checked ? '&hiddenActions=' + document.querySelector('#hiddenActions').checked : '';
	var hiddenPatterns = document.querySelector('#hiddenPatterns') && document.querySelector('#hiddenPatterns').checked ? '&hiddenPatterns=' + document.querySelector('#hiddenPatterns').checked : '';
	showSpinner();
	fetch(gdprMsg.ajaxUrl, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded'
		},
		body: `action=render_messages&page=${page}&search=${encodeURIComponent(search)}&messageType=${gdprMsg.messageType}&search_nonce=${gdprMsg.nonces.search}${listedActions}${listedPatterns}${whitelistedSites}${whitelistedIPs}${hiddenActions}${hiddenPatterns}`
	})
	.then(response => response.json())
	.then(function(response) {
		if( response.success == 1 ) {
			document.querySelector('#results').innerHTML = response.result;
			document.querySelector('.paginator').innerHTML = response.paginator;
			var akkordeon = document.getElementsByClassName( 'akkordeonButton' );
			for (var x = 0; x < akkordeon.length; x++) {
				akkordeon[x].addEventListener( 'click', function() {
					this.classList.toggle( 'akkordeonButtonAktiv' );
					var akkordeonEinheit = this.nextElementSibling;
					if ( akkordeonEinheit.style.display === 'block' ) {
						akkordeonEinheit.style.display = 'none';
					} else {
						akkordeonEinheit.style.display = 'block';
					}
				});
				akkordeon[x].addEventListener( 'click', function() {
					var id = this.id.split( '_' )[ 1 ];
					getDetail(id);
				}, { once: true } );
			}
		} else {
			showAlert(response.error_message);
			location.reload();
		}
		hideSpinner();
	});
}

/**
 * Highlight every case-insensitive occurrence of `needle` inside the direct text
 * nodes of `element`. User-controlled submission values must NEVER be routed through
 * innerHTML here: the server escapes them (esc_attr), but reading element.textContent
 * decodes that escaping again, so `innerHTML = textContent.replace(...)` reintroduces
 * a stored XSS (a captured `<img onerror>` would execute in the admin's session).
 * Building the highlight with createTextNode/textContent keeps everything inert, and
 * only text nodes are touched so element children (e.g. the Block-sender/-domain
 * buttons in the value cell) survive. `needle` is guaranteed non-empty by the caller,
 * which also avoids the previous `new RegExp(search)` throwing on regex metacharacters.
 */
function highlightTextNodes(element, needle) {
	Array.prototype.slice.call(element.childNodes).forEach(function (node) {
		if (node.nodeType !== 3) {
			return;
		}
		var text = node.nodeValue;
		var lower = text.toLowerCase();
		var idx = lower.indexOf(needle);
		if (idx === -1) {
			return;
		}
		var frag = document.createDocumentFragment();
		var from = 0;
		while (idx !== -1) {
			frag.appendChild(document.createTextNode(text.slice(from, idx)));
			var mark = document.createElement("span");
			mark.style.backgroundColor = "yellow";
			mark.textContent = text.slice(idx, idx + needle.length);
			frag.appendChild(mark);
			from = idx + needle.length;
			idx = lower.indexOf(needle, from);
		}
		frag.appendChild(document.createTextNode(text.slice(from)));
		element.replaceChild(frag, node);
	});
}

function getDetail(id) {
	var search = document.querySelector('.messageSearch').value;
	showSpinner();
	fetch(gdprMsg.ajaxUrl, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded'
		},
		body: `action=render_message&messageType=${ gdprMsg.messageType }&messageID=${ id }&message_nonce=${ document.querySelector(`#messageNonce${ id }`).value }`
	})
	.then(response => response.json())
	.then(function (response) {
		if (response.success === 1) {
			const elements = document.createRange().createContextualFragment(response.result);
			const needle = search ? search.toLowerCase() : "";
			if (needle) {
				elements.querySelectorAll(".returnAttribute").forEach(function (element) {
					highlightTextNodes(element, needle);
				});
			}
			document.querySelector("#messageDetails" + id).innerHTML = "";
			document.querySelector("#messageDetails" + id).appendChild(elements);
		} else {
			showAlert(response.error_message);
			location.reload();
		}
		hideSpinner();
	});
}

function doDeleteAll( e ){
	e.preventDefault();
	var confirmed = confirm(gdprMsg.i18n.confirmDeleteAll);

	// If the user clicked "Yes", process the form
	if (confirmed) {
		var search = document.querySelector('.messageSearch').value;
		deleteMessage( null, search );
	}
}

function doMessageAction( e ){
	e.preventDefault();
	if ( document.querySelector('#messageAction').value !== 'bulk' ) {
		var search = document.querySelector('.messageSearch').value;
		var messageAction = document.querySelector('#messageAction').value;
		var form = messageAction.split('_')[0];
		var changeType = messageAction.split('_')[1];
		if (form == 'deleteForm') {
			deleteMessages( form, search );
		} else {
			moveMessages( changeType, form, search );
		}
	}
}

function moveMessages( changeType, form, search ){

	let check_message = document.querySelectorAll('.check_message:checked');

	let messages = Array.from(check_message).map(el => {
		let id = el.id.split('_')[2];
		let formFinal = document.querySelector('#' + form + id);
		let serialized = Array.from(new FormData(formFinal)).map(kv => kv.join("=")).join("&");
		return serialized;
	});

	document.querySelectorAll('.check_messages').forEach(function(el) {
		el.checked = false;
	});

	if( messages.length > 0 ){
		changeMessageType( messages, changeType, search );
	}
}

function moveMessage( e, form, messageID, changeType ){
	e.preventDefault();
	var search = document.querySelector('.messageSearch').value;
	var messages = [];

	const formFinal = document.querySelector('#' + form + messageID);
	const formData = new FormData(formFinal);
	let serialized = "";
	for (const [key, value] of formData.entries()) {
		serialized += key + "=" + value + "&";
	}
	serialized = serialized.slice(0, -1);

	messages.push( serialized );
	changeMessageType( messages, changeType, search );
}

function changeMessageType( messages, changeType, search ) {

	if (document.readyState === 'complete') {
		var xhr = new XMLHttpRequest();
		xhr.open('POST', gdprMsg.ajaxUrl, true);
		xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
		
		xhr.onreadystatechange = function() {
			if (this.readyState === XMLHttpRequest.DONE && this.status === 200) {
				var response = JSON.parse(this.responseText);
				if (response.success === 1) {
					document.querySelector('#results').innerHTML = response.result;
					document.querySelector('.paginator').innerHTML = response.paginator;
					var akkordeon = document.getElementsByClassName('akkordeonButton');
					for (var x = 0; x < akkordeon.length; x++) {
						akkordeon[x].addEventListener('click', function() {
							this.classList.toggle('akkordeonButtonAktiv');
							var akkordeonEinheit = this.nextElementSibling;
							if (akkordeonEinheit.style.display === 'block') {
							akkordeonEinheit.style.display = 'none';
							} else {
							akkordeonEinheit.style.display = 'block';
							}
						});
						akkordeon[x].addEventListener('click', function() {
							var id = this.id.split('_')[1];
							getDetail(id);
						}, { once: true });
					}
					showSuccess(gdprMsg.i18n.moved);
				} else {
					showAlert(response.error_message);
				}
				hideSpinner();
			}
		};
		var listedActions = document.querySelector('#listedActions') && document.querySelector('#listedActions').checked ? '&listedActions=' + document.querySelector('#listedActions').checked : '';
		var listedPatterns = document.querySelector('#listedPatterns') && document.querySelector('#listedPatterns').checked ? '&listedPatterns=' + document.querySelector('#listedPatterns').checked : '';
		var whitelistedSites = document.querySelector('#whitelistedSites') && document.querySelector('#whitelistedSites').checked ? '&whitelistedSites=' + document.querySelector('#whitelistedSites').checked : '';
		var whitelistedIPs = document.querySelector('#whitelistedIPs') && document.querySelector('#whitelistedIPs').checked ? '&whitelistedIPs=' + document.querySelector('#whitelistedIPs').checked : '';
		var hiddenActions = document.querySelector('#hiddenActions') && document.querySelector('#hiddenActions').checked ? '&hiddenActions=' + document.querySelector('#hiddenActions').checked : '';
		var hiddenPatterns = document.querySelector('#hiddenPatterns') && document.querySelector('#hiddenPatterns').checked ? '&hiddenPatterns=' + document.querySelector('#hiddenPatterns').checked : '';
		showSpinner();
		xhr.send(
			"action=change_message_type" +
			"&messageType=" + gdprMsg.messageType +
			"&changeType=" + changeType +
			"&messages=" + encodeURIComponent(JSON.stringify(messages)) +
			"&search=" + encodeURIComponent(search) +
			"&search_nonce=" + gdprMsg.nonces.search +
			listedActions +
			listedPatterns +
			whitelistedSites +
			whitelistedIPs +
			hiddenActions +
			hiddenPatterns
		);
	}

}

function deleteMessages( form, search ){

	let check_message = document.querySelectorAll('.check_message:checked');

	let messages = Array.from(check_message).map(el => {
		let id = el.id.split('_')[2];
		let formFinal = document.querySelector('#' + form + id);
		let serialized = Array.from(new FormData(formFinal)).map(kv => kv.join("=")).join("&");
		return serialized;
	});

	document.querySelectorAll('.check_messages').forEach(function(el) {
		el.checked = false;
	});
	
	if( messages.length > 0 ){
		deleteMessage( messages, search );
	}
}

function deleteSingleMessage( e, form, messageID ){
	e.preventDefault();
	var search = document.querySelector('.messageSearch').value;
	var messages = [];


	const formFinal = document.querySelector('#' + form + messageID);
	const formData = new FormData(formFinal);
	let serialized = "";
	for (const [key, value] of formData.entries()) {
		serialized += key + "=" + value + "&";
	}
	serialized = serialized.slice(0, -1);

	messages.push( serialized );

	deleteMessage( messages, search );
}

function deleteMessage( messages, search ) {

	if (document.readyState === 'complete') {
		var xhr = new XMLHttpRequest();
		xhr.open("POST", gdprMsg.ajaxUrl);
		xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

		xhr.onload = function() {
			if (xhr.status === 200) {
				var response = JSON.parse(xhr.responseText);
				if (response.success == 1) {
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
					showSuccess(gdprMsg.i18n.deleted);
				} else {
					showAlert(response.error_message);
				}
			}
			hideSpinner();
		};
		var listedActions = document.querySelector('#listedActions') && document.querySelector('#listedActions').checked ? '&listedActions=' + document.querySelector('#listedActions').checked : '';
		var listedPatterns = document.querySelector('#listedPatterns') && document.querySelector('#listedPatterns').checked ? '&listedPatterns=' + document.querySelector('#listedPatterns').checked : '';
		var whitelistedSites = document.querySelector('#whitelistedSites') && document.querySelector('#whitelistedSites').checked ? '&whitelistedSites=' + document.querySelector('#whitelistedSites').checked : '';
		var whitelistedIPs = document.querySelector('#whitelistedIPs') && document.querySelector('#whitelistedIPs').checked ? '&whitelistedIPs=' + document.querySelector('#whitelistedIPs').checked : '';
		var hiddenActions = document.querySelector('#hiddenActions') && document.querySelector('#hiddenActions').checked ? '&hiddenActions=' + document.querySelector('#hiddenActions').checked : '';
		var hiddenPatterns = document.querySelector('#hiddenPatterns') && document.querySelector('#hiddenPatterns').checked ? '&hiddenPatterns=' + document.querySelector('#hiddenPatterns').checked : '';
		showSpinner();
		xhr.send(
			"action=delete_message" +
			"&messageType=" + gdprMsg.messageType +
			"&messages=" + encodeURIComponent(JSON.stringify(messages)) +
			"&search=" + encodeURIComponent(search) +
			"&search_nonce=" + gdprMsg.nonces.search +
			listedActions +
			listedPatterns +
			whitelistedSites +
			whitelistedIPs +
			hiddenActions +
			hiddenPatterns
		);
	}

}

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
	var listedActions = document.querySelector('#listedActions') && document.querySelector('#listedActions').checked ? '&listedActions=' + document.querySelector('#listedActions').checked : '';
	var listedPatterns = document.querySelector('#listedPatterns') && document.querySelector('#listedPatterns').checked ? '&listedPatterns=' + document.querySelector('#listedPatterns').checked : '';
	var whitelistedSites = document.querySelector('#whitelistedSites') && document.querySelector('#whitelistedSites').checked ? '&whitelistedSites=' + document.querySelector('#whitelistedSites').checked : '';
	var whitelistedIPs = document.querySelector('#whitelistedIPs') && document.querySelector('#whitelistedIPs').checked ? '&whitelistedIPs=' + document.querySelector('#whitelistedIPs').checked : '';
	var hiddenActions = document.querySelector('#hiddenActions') && document.querySelector('#hiddenActions').checked ? '&hiddenActions=' + document.querySelector('#hiddenActions').checked : '';
	var hiddenPatterns = document.querySelector('#hiddenPatterns') && document.querySelector('#hiddenPatterns').checked ? '&hiddenPatterns=' + document.querySelector('#hiddenPatterns').checked : '';
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
		listedActions +
		listedPatterns +
		whitelistedSites +
		whitelistedIPs +
		hiddenActions +
		hiddenPatterns
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
		var listedActions = document.querySelector('#listedActions') && document.querySelector('#listedActions').checked ? '&listedActions=' + document.querySelector('#listedActions').checked : '';
		var listedPatterns = document.querySelector('#listedPatterns') && document.querySelector('#listedPatterns').checked ? '&listedPatterns=' + document.querySelector('#listedPatterns').checked : '';
		var whitelistedSites = document.querySelector('#whitelistedSites') && document.querySelector('#whitelistedSites').checked ? '&whitelistedSites=' + document.querySelector('#whitelistedSites').checked : '';
		var whitelistedIPs = document.querySelector('#whitelistedIPs') && document.querySelector('#whitelistedIPs').checked ? '&whitelistedIPs=' + document.querySelector('#whitelistedIPs').checked : '';
		var hiddenActions = document.querySelector('#hiddenActions') && document.querySelector('#hiddenActions').checked ? '&hiddenActions=' + document.querySelector('#hiddenActions').checked : '';
		var hiddenPatterns = document.querySelector('#hiddenPatterns') && document.querySelector('#hiddenPatterns').checked ? '&hiddenPatterns=' + document.querySelector('#hiddenPatterns').checked : '';
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
			listedActions +
			listedPatterns +
			whitelistedSites +
			whitelistedIPs +
			hiddenActions +
			hiddenPatterns
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

