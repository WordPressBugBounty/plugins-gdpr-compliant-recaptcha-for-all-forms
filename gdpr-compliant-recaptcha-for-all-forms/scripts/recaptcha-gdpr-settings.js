/**
 * GDPR-Compliant ReCaptcha — settings page behaviour.
 * Counterpart: Settings_Menu::options_page() (plugin/includes/class-settings-menu.php),
 * which renders the full markup server-side (status strip, pill tabs, tab panels, option
 * rows with a help popover). This script only wires up two purely client-side interactions
 * on top of that markup — no DOM restructuring, no drag/burger-menu leftovers:
 *
 *   1. Tab switching: toggle the `hidden` attribute on .gdpr-tab-panel sections and the
 *      `is-active` class on .gdpr-pill-tab buttons, and keep the hidden
 *      #gdpr-settings-selection input in sync so the active tab survives a form submit
 *      (read server-side in options_page()).
 *   2. Help popovers: toggle the `hidden` attribute + `aria-expanded` on the matching
 *      .gdpr-help-popover, closing others on open, on outside click, and on Escape.
 */
(function () {
	'use strict';

	document.addEventListener('DOMContentLoaded', function () {
		// The pill nav sits OUTSIDE the form (sibling before it), so scope to the
		// page wrap, not the form.
		var wrap = document.querySelector('.gdpr-settings-wrap');
		if (!wrap) {
			return;
		}

		initTabs(wrap);
		initHelpPopovers(wrap);
	});

	/**
	 * Tab switching. The server renders the initially active tab (panel not hidden, pill
	 * with .is-active) — no click is triggered on load.
	 */
	function initTabs(wrap) {
		var tabs = wrap.querySelectorAll('.gdpr-pill-tab');
		var selectionInput = document.getElementById('gdpr-settings-selection');
		if (!tabs.length) {
			return;
		}

		tabs.forEach(function (tab) {
			tab.addEventListener('click', function () {
				var target = tab.getAttribute('data-tab-target');
				if (!target) {
					return;
				}

				var panel = document.getElementById(target);
				if (!panel) {
					return;
				}

				wrap.querySelectorAll('.gdpr-tab-panel').forEach(function (section) {
					section.hidden = true;
				});
				panel.hidden = false;

				tabs.forEach(function (otherTab) {
					otherTab.classList.remove('is-active');
				});
				tab.classList.add('is-active');

				if (selectionInput) {
					selectionInput.value = target;
				}
			});
		});
	}

	/**
	 * Help popovers, anchored to their .gdpr-help-toggle button via aria-controls.
	 */
	function initHelpPopovers(wrap) {
		var toggles = wrap.querySelectorAll('.gdpr-help-toggle');
		if (!toggles.length) {
			return;
		}

		function closeAll(except) {
			toggles.forEach(function (toggle) {
				if (toggle === except) {
					return;
				}
				var popover = document.getElementById(toggle.getAttribute('aria-controls'));
				if (popover) {
					popover.hidden = true;
				}
				toggle.setAttribute('aria-expanded', 'false');
			});
		}

		toggles.forEach(function (toggle) {
			var popover = document.getElementById(toggle.getAttribute('aria-controls'));
			if (!popover) {
				return;
			}

			toggle.addEventListener('click', function (event) {
				event.stopPropagation();
				var isOpen = toggle.getAttribute('aria-expanded') === 'true';

				closeAll(toggle);

				popover.hidden = isOpen;
				toggle.setAttribute('aria-expanded', isOpen ? 'false' : 'true');
			});
		});

		document.addEventListener('click', function (event) {
			if (event.target.closest('.gdpr-option-control')) {
				return;
			}
			closeAll();
		});

		document.addEventListener('keydown', function (event) {
			if (event.key !== 'Escape') {
				return;
			}

			var openToggle = null;
			toggles.forEach(function (toggle) {
				if (toggle.getAttribute('aria-expanded') === 'true') {
					openToggle = toggle;
				}
			});

			if (!openToggle) {
				return;
			}

			closeAll();
			openToggle.focus();
		});
	}
})();
