<?php
/**
 * The shipped risk-class seed lines — data only, with the evidence for each line.
 *
 * Read exclusively through Risk_Signatures (the logic lives there; this file is the
 * catalog, which grows by one block per verified product). Verification standard and
 * product verdicts: PLAN-RISIKOKLASSE.md; area doc: handbuch/detection.md.
 *
 * @package gdpr-compliant-recaptcha-for-all-forms
 */

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/detection.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.
// Aenderst du das Verhalten hier, gehoert die Beschreibung in die Bereichsdatei oben,
// nicht in den Index.

/**
 * One entry per seed line. Every line was checked against the product's own source:
 * the handler exists and is anonymous, the frontend really sends this, the product's
 * backend does not (lockout counter-check), and the product's LOGIN request does not
 * match (a login must reach wp_authenticate_user exactly once).
 */
final class Risk_Catalog {

	/**
	 * @return array<int, array{gate: string, product: string, class: string, kind: string, line: string}>
	 */
	public static function entries(): array {
		return array(
			// *** WooCommerce — the Checkout BLOCK (Store API) ***
			// "Place order" is `POST /wc/store/v1/checkout`, sent directly, never batched by
			// the client (WooCommerce 11.1.2, assets/js/data/shared-controls.ts:129-136;
			// checkout-processor.ts:293-299), permission_callback __return_true. The
			// automatic draft save on the SAME route travels as POST + X-HTTP-Method-
			// Override: PUT (checkout/thunks.ts:173-177) and is not judged since
			// RestRoute::effective_method() — without that this line would spend token
			// uses every 1.5 s. The operator's backend sends no POST to wc/store/v1/*.
			// NAMED GAP: the batch route accepts checkout as a sub-request server-side
			// (StoreApi/Routes/V1/Checkout.php:144) — see handbuch/detection.md.
			// The classic checkout (`wc-ajax=checkout`) is NOT here: it blocks since long
			// before this class and stays that way (PLAN-RISIKOKLASSE.md, point 6).
			array(
				'gate'    => 'woocommerce/woocommerce.php',
				'product' => 'WooCommerce (Checkout block)',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ROUTE,
				'line'    => 'wc/store/v1/checkout',
			),

			// *** BuddyPress 14.5.2 — registration (non-ajax page POST) ***
			// bp_core_screen_signup on bp_screens needs isset($_POST['signup_submit'])
			// (bp-members/screens/register.php:70, 307); the field is the submit button's
			// name (legacy members/register.php:364, nouveau includes/functions.php:1311-1316).
			// Not in any admin view. BuddyPress has no login of its own.
			// NOT the REST route buddypress/v1/signup: no BuddyPress frontend sends to it,
			// so no token would ever reach it — only a foreign app would, and armed, that
			// app would be locked out (same abort rule as Simply Schedule).
			array(
				'gate'    => 'buddypress/bp-loader.php',
				'product' => 'BuddyPress',
				'class'   => Risk_Signatures::REGISTRATION,
				'kind'    => Risk_Signatures::KIND_PATTERN,
				'line'    => '{"signup_submit":null}',
			),

			// *** WP-Members 3.5.7 — registration ***
			// Hidden fields a=register (class-wp-members-forms.php:1414-1416) and the nonce
			// _wpmem_register_nonce (:1510-1511), read on template_redirect
			// (class-wp-members.php:637, 877, 940-942). Both keys pinned: profile edits send
			// a=update + _wpmem_update_nonce, the login a=login (wp_signon, :112) — neither
			// matches. Auto-login after registration uses wp_set_auth_cookie (no second
			// wp_authenticate_user). No a=register in the admin area.
			array(
				'gate'    => 'wp-members/wp-members.php',
				'product' => 'WP-Members',
				'class'   => Risk_Signatures::REGISTRATION,
				'kind'    => Risk_Signatures::KIND_PATTERN,
				'line'    => '{"a":"register","_wpmem_register_nonce":null}',
			),

			// *** ProfilePress 4.17.5 ***
			// Ajax signup: wp_ajax_nopriv_pp_ajax_signup (AjaxHandler.php:27), FormData via
			// $.post in the page (assets/js/frontend.js:247-266). The two patterns are the
			// non-ajax fallbacks (ajax mode off, RegisterScripts.php:68, or no FormData):
			// signup_form_id + reg_submit (RegistrationFormTag.php:105,
			// FieldsShortcodeCallback.php:1131, handler FormProcessor.php:186 on `wp`) and
			// the tabbed widget's tabbed_reg_submit (TabbedWidget.php:39). Checkout:
			// ppress_process_checkout, FormData (CheckoutController.php:35, checkout.js:431).
			// The login (pp_ajax_login / login_submit) matches none; auto-login is
			// wp_set_auth_cookie (Autologin.php:44).
			array(
				'gate'    => 'wp-user-avatar/wp-user-avatar.php',
				'product' => 'ProfilePress',
				'class'   => Risk_Signatures::REGISTRATION,
				'kind'    => Risk_Signatures::KIND_ACTION,
				'line'    => 'pp_ajax_signup',
			),
			array(
				'gate'    => 'wp-user-avatar/wp-user-avatar.php',
				'product' => 'ProfilePress',
				'class'   => Risk_Signatures::REGISTRATION,
				'kind'    => Risk_Signatures::KIND_PATTERN,
				'line'    => '{"signup_form_id":null,"reg_submit":null}',
			),
			array(
				'gate'    => 'wp-user-avatar/wp-user-avatar.php',
				'product' => 'ProfilePress',
				'class'   => Risk_Signatures::REGISTRATION,
				'kind'    => Risk_Signatures::KIND_PATTERN,
				'line'    => '{"tabbed_reg_submit":null}',
			),
			array(
				'gate'    => 'wp-user-avatar/wp-user-avatar.php',
				'product' => 'ProfilePress',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ACTION,
				'line'    => 'ppress_process_checkout',
			),

			// *** Easy Digital Downloads 3.7.1 — checkout, ajax and REST steps only ***
			// edd_process_checkout (process-purchase.php:67-68; the client appends it to the
			// serialized form, edd-ajax.entry.js:414); Stripe: edds_process_purchase_form
			// (compat.php:166-167, form.js:181), edds_create_and_complete_order
			// (payment-elements-actions.php:55-56), edds_prb_ajax_process_checkout
			// (payment-request/ajax.php:179-180); Square charges the card in
			// edd_square_process_checkout_form (Gateways/Square/Gateway.php:122,
			// square.js:293); PayPal: edd_capture_paypal_order (paypal/checkout-actions.php:715
			// — its order-creation call carries no action, the ajax gate never sees it);
			// REST, JSON via fetch in the page: edd/v3/unbranded-card/create
			// (UnbrandedCard.php:59-63, unbrandedcard.js:176-184), edd/v3/fastlane/
			// process-payment (Fastlane.php:58-62, fastlane.js:195-202). None in any admin
			// view. Ajax: our login hook is not registered there, so an in-flow login is
			// judged once.
			// DELIBERATELY NOT {"edd_action":"purchase"} and {"edd_action":"user_register"}:
			// both are non-ajax and can log the buyer in with wp_signon
			// (process-purchase.php:616, 742-764; users/register.php:~191) — the login would
			// be judged twice and spend a token use (PLAN-RISIKOKLASSE.md, double-evaluation
			// rule). Named gap: a checkout without JavaScript is not in the class.
			array(
				'gate'    => 'easy-digital-downloads/easy-digital-downloads.php',
				'product' => 'Easy Digital Downloads',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ACTION,
				'line'    => 'edd_process_checkout',
			),
			array(
				'gate'    => 'easy-digital-downloads/easy-digital-downloads.php',
				'product' => 'Easy Digital Downloads',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ACTION,
				'line'    => 'edds_process_purchase_form',
			),
			array(
				'gate'    => 'easy-digital-downloads/easy-digital-downloads.php',
				'product' => 'Easy Digital Downloads',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ACTION,
				'line'    => 'edds_create_and_complete_order',
			),
			array(
				'gate'    => 'easy-digital-downloads/easy-digital-downloads.php',
				'product' => 'Easy Digital Downloads',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ACTION,
				'line'    => 'edds_prb_ajax_process_checkout',
			),
			array(
				'gate'    => 'easy-digital-downloads/easy-digital-downloads.php',
				'product' => 'Easy Digital Downloads',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ACTION,
				'line'    => 'edd_square_process_checkout_form',
			),
			array(
				'gate'    => 'easy-digital-downloads/easy-digital-downloads.php',
				'product' => 'Easy Digital Downloads',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ACTION,
				'line'    => 'edd_capture_paypal_order',
			),
			array(
				'gate'    => 'easy-digital-downloads/easy-digital-downloads.php',
				'product' => 'Easy Digital Downloads',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ROUTE,
				'line'    => 'edd/v3/unbranded-card/create',
			),
			array(
				'gate'    => 'easy-digital-downloads/easy-digital-downloads.php',
				'product' => 'Easy Digital Downloads',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ROUTE,
				'line'    => 'edd/v3/fastlane/process-payment',
			),

			// *** Amelia — booking (verified 2026-09-24, PLAN-RISIKOKLASSE.md) ***
			// Rule line: `call` travels as a GET parameter, so it is top-level readable. The
			// returnUrl pin CARRIES the line: the backend books packages and event attendees
			// through the same call=/bookings but never sets returnUrl — without the pin the
			// line would lock the operator out. Client: axios (XHR), token injected.
			array(
				'gate'    => 'ameliabooking/ameliabooking.php',
				'product' => 'Amelia (booking)',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ACTION,
				'line'    => '{"action":"wpamelia_api","call":"/bookings","returnUrl":null}',
			),

			// *** Bookly — booking (verified 2026-09-24) ***
			// bookly_save_appointment; the backend dialog sends bookly_save_appointment_form,
			// a different name, and the action list compares exactly. NAMED LIMITS: name and
			// e-mail travel on bookly_session_save, not here; bookly_ai_checkout is a second
			// booking path this line does not cover. Gate file main.php (tags/28.3).
			array(
				'gate'    => 'bookly-responsive-appointment-booking-tool/main.php',
				'product' => 'Bookly (booking)',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ACTION,
				'line'    => 'bookly_save_appointment',
			),

			// *** CartFlows 3.2.1 — the checkout page's ajax LOGIN ***
			// wp_ajax_nopriv_wcf_woocommerce_login only (class-cartflows-checkout-ajax.php:55);
			// nonce, then wp_signon with no rate limit (:260-291) — a password endpoint that
			// bypasses the wp-login.php protection. Client: urlencoded email/password/
			// security via $.ajax (checkout-template.js:731-741). Ajax, so judged once. The
			// order itself rides wc-ajax=checkout (already blocking). Filed under CHECKOUT:
			// a false block locks a buyer out at the checkout, and there is no login switch.
			array(
				'gate'    => 'cartflows/cartflows.php',
				'product' => 'CartFlows (checkout login)',
				'class'   => Risk_Signatures::CHECKOUT,
				'kind'    => Risk_Signatures::KIND_ACTION,
				'line'    => 'wcf_woocommerce_login',
			),
		);
	}
}
