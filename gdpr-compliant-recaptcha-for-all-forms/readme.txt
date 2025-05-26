=== Anti-spam, Spam protection, ReCaptcha for all forms and GDPR-compliant ===
Contributors: MatthiasNordwig
Tags: anti-spam, antispam, recaptcha, captcha, spam-protection
Requires at least: 4.8+
Tested up to: 6.8
Stable tag: 4.1.1
Requires PHP: 5.6
License: GPLv3
License URI: http://www.gnu.org/licenses/gpl-3.0.html
Donate link: https://paypal.me/MatthiasNordwig

Anti-spam - CAPTCHA that protects all forms against spam and brute-force. Invisible and GDPR-compliant.


== Description ==

Protect all your forms and logins against spam and brute-force attacks. The plugin is invisible and compliant to GDPR (RGPD, DSGVO). 
It has a lot of options on the one hand and comes with a well balanced default configuration. Thus it starts working very well, as soon as it is activated.

== Setup Guide ==

[vimeo https://player.vimeo.com/video/905897718]

== Key features ==
* Blocks spam on all(!) public forms, comments and logins
* Invisible. No user-input required
* Still receive 100 percent of the real requests
* Compliant to GDPR (respectively DSGVO, RGPD)
* The Plugin is for free
* No tracking, no cookies, no sessions
* No external ressources
* Easy to use
* SEO-friendly
* Only necessary code
* Optionally messages can be flagged instead of blocking them

== Examples Wordpress ==
* Login Form
* Registration Form
* Password Reset Form
* Comments Form

== Examples WooCommerce ==
* Checkout
* Login Form
* Registration Form
* Password Reset Form
* Comments form
* Product Evaluation Form

== Examples other Plugins ==
* Elementor Pro Forms, Contact Form 7, Fluent Forms, Jetpack Forms, Divi Forms, WPForms, Forminator, Thrive Architect & Thrive Apprentice, Gravity Forms, Formidable Forms, Mailchimp for WordPress Forms, BuddyPress Registration Form, bbPress Create Topic & Reply Forms, Ultimate Member Forms, wpDiscuz Custom Comments Form, Easy Digital Downloads Forms, Paid Memberships Pro Forms, MemberPress Forms, WP-Members Forms, WP User Frontend Forms, CheckoutWC & Flux Checkout, Ninja Forms, Everest Forms, Formidable Forms, WS Forms, Quform, Otter Blocks, Typeform, NEX-Forms, Bit Form, Form Maker, Funnelforms, Mailjet, Jotform, Page Builder, Metform, Calculated Fields Form, JetFormBuilder, weForms, Responsive Contact Form Builder, Zoho Forms, Smart Forms, Kali Forms, Happyforms, ApplyOnline, Subscribe Forms, FormCraft, Advanced Forms, CRM Perks Forms, Tripetto, Formstack, BuddyForms, vcita, Easy Form Builder, SimpleForm

== Thank you! ==
I hope you enjoy using the CAPTCHA plugin! If you are happy with it, I would be glad to get your review and probably a coffee too.

== Installation ==
1. Watch the setup video
2. Install & activate the plugin via the WordPress Plugins page
3. Check if all forms are correctly recognized by the spam protection system 
4. Manually add missing actions/patterns for any unrecognized forms using direct analysis mode
5. (Optional) Adjust settings to block, flag, or save spam submissions

== Frequently Asked Questions ==
= Submissions are incorrectly treated as spam =
1. The problem occasionally occurs right after installation due to caching. In such cases, the necessary JavaScript for proof-of-work isn't loaded as intended. To resolve this, clear the cache on your webserver (WordPress caching is typically managed by plugins, which offer an option to clear the cache) and in your browser.
2. JavaScript might crash due to incompatibility between this plugin and another one you're using. If you notice this, please report it to me. I usually address such issues within the same day. Additionally, it's crucial to ensure that JavaScript is functioning correctly on all your pages, even without this plugin. In most browsers, you can identify JavaScript errors by pressing F12 on your page and navigating to the console. Here, you can observe what's happening on your page.
= Neither messages, nore spam is shown in the inbox =
1. Activate the **Analysis mode 🔍**, 
2. Submit the form and look for the message that has been saved for the new submission in the <strong>Analytic Box</strong>
3. Open the message and enhance the scope of the spam to this type of message
4. If the message doesn't appear here, or is already in scope, please give me a note
= Problems with Borlabs Script Blocker =
When you use the Borlabs Script Blocker to scan for JavaScripts, the scan doesn't work properly, as it doesn't show any JavaScripts. Just deactivate this plugin for the scan and activate it again after the scan.
= Can't get my problems fixed =
1. Important messages could be shown in browser console (F12) on problematic page
2. Whenever you post something to the support forum, try to hand over all details
3. If the recaptcha doesn't work on any form, give me a notice and I will try to fix that

= How to disable this plugin? =
* Use standard WordPress plugins page for deactivation and deletion of the plugin
* When deactivating the plugin you will be asked for the reason. If you face any problems I would be glad if you report to it me as detailed as possible. Usually I will fix them quickly. If you give me contcat details, I may inform you as soon as it is fixed.

== Changelog ==
= 4.1.1 =
* Improved Pattern recognition
* Solved: Warning for usage of empty keys
= 4.1 =
* Fail2Ban-Support added
* Problems with Thrive Comments and json-based submissions fixed
= 4.0 =
* The automatic mode has been removed. From now on, all form types require manual configuration of associated patterns and actions to ensure the spam protection functions correctly.
* During plugin installation, the appropriate actions and patterns for major form builders will be automatically added to the scope—provided the respective form builder is installed.
* Adding new form types to the spam protection, which are not yet included by default, can still be done via the analysis mode or direct analysis mode.
* If important patterns or actions are missing, I appreciate any feedback and suggestions for improvements.
* This update ensures targeted spam protection configuration while still allowing automatic detection of widely used form builders.
= 3.8.1 =
* Fixed: Erroneous error handling for file-uploads (i.e. Fancy Product Designer)
= 3.8 =
* Fixed: Problems with IP-Forwarding and load-balancing led to always false-positives
= 3.7.3 =
* SQL-Bug during installation routine fixed
= 3.7.2 =
* Optimized symbols in the settings menu
= 3.7.1 =
* Fixed: Bug with empty field "Skip fields from saving"
= 3.7 =
* Highly recommended security feature "Skip fields from saving" on the tab "Saving Messages" on the plugins options page added. This feature is intended to exclude fields (i.e. password fields) from beeing saved with messages. Background: The plugin is identifying password fields on the form and skips them from beeing saved already. But in the case of the event that JavaScript is crashing, the identification process may fail and thus the password will be saved nevertheless. Therefore this option shall be used to define password fields manually that shall be skipped from saving.
= 3.6.10 =
* Fixed: Bug with hiding the menu in initial state of the settings menu
= 3.6.9 =
* Fixed: Bug with the new feature to stop logging logins
= 3.6.8 =
* New feature: The admin area is turned to red as long as the simulation mode is on
* New feature: The messages inbox can be hidden, by setting its position to -1
* New feature: The logging of login-messages can be switched off
= 3.6.7 =
* Fixed: Variables that where not initialized caused warnings on higher debug-levels
= 3.6.6 =
* Problem with forminator and possibly other form builders too fixed: Bots where able to bypassed the pattern matching and thus the spam check too.
= 3.6.5 =
* Fixed: A dedicated spam-check for WordPRess-standard-requests was introduced, in order to treat them differently from other post-requests. It turned out that some spam showed up after the last release. This should not happen anymore
= 3.6.4 =
* Fixed: In v.3.5.5 the plugin was changed to apply the spam check always on WordPress standard submissions such as comments. Even in explicit mode. This behaviour is changed now, in a way that even for WordPress standard submission types patterns have to match, before they are checked for spam.
* This means: If you are using WordPress standard submission-types such as comments and posts, from now on you need to add the respective patterns for them, as for any other type of submission, in order to make the spam check work for them.
= 3.6.3 =
* Fixed Bug with Inboxes
= 3.6.2 =
* Improved performance administration area and inboxes
* Bug with empty pages for inboxes solved
= 3.6.1 =
* Loading error for Direct Analysis Mode fixed
= 3.6 =
* "Direct analysis mode" introduced: This mode allows easier administration of the explicit mode, as froms and submission-types now now can be added directly and life from the forms
* Settings page devided into tabs