=== Invisible Anti-Spam & CAPTCHA — reCAPTCHA Alternative for All Forms ===
Contributors: MatthiasNordwig
Tags: anti-spam, spam, captcha, recaptcha, spam-protection
Requires at least: 4.8
Tested up to: 7.0
Stable tag: 5.3.1
Requires PHP: 7.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Donate link: https://paypal.me/MatthiasNordwig

Invisible spam protection for every form, login and checkout. No puzzles, no checkboxes, no lost visitors — a CAPTCHA your users never see.

== Description ==

**Spam protection your visitors never see.** No image grids, no "I'm not a robot" checkbox, no puzzles, nothing to click. Your visitors just hit *Send* — while their browser silently solves a tiny cryptographic challenge (proof-of-work) in a few milliseconds. Real humans never notice. Mass-spam bots either fail the challenge or have to burn so much computing power per message that spamming your site stops being worth it.

**Every form, out of the box.** WordPress logins, registrations and comments, WooCommerce checkout and reviews, and virtually every form plugin — Contact Form 7, Elementor Pro Forms, WPForms, Gravity Forms, Ninja Forms, Fluent Forms, Formidable and dozens more (full list below). One plugin protects all of them, and the most popular builders are detected and configured automatically on activation.

= Truly universal — not a list of integrations =

Most anti-spam tools protect only the form plugins they ship an integration for. If your builder is not on their list — or you use a hand-coded form, a theme's built-in form, or three different builders on one site — you are on your own.

This plugin works differently: it recognizes submissions by their **signature** — the characteristic fields and actions of the request itself — instead of hooking into specific form plugins. That is why it covers *any* form:

* **Popular builders** are recognized automatically: their signatures ship with the plugin and are pre-configured on activation.
* **Everything else** — custom-coded forms, exotic builders, legacy themes — you teach the spam check yourself in under a minute: turn on direct analysis mode, submit the form once, click *save*. Done. No code, no waiting for the developer to add your builder.

And because no integration code is involved, nothing breaks when your form builder updates.

In practice that solves two everyday problems:

* **Real sites mix.** A typical site has comments, a contact form from one builder, a newsletter signup from another, WooCommerce reviews — protecting each with its own anti-spam solution means more plugins, more settings pages, more things that can conflict. Here, one plugin covers the whole site.
* **Designers and agencies standardize.** If you build sites for clients, you can install the same proven plugin on every project — no matter which form stack the client uses (or switches to later). One tool to know, one place to look when something needs attention.

= Why "invisible" wins =

Every CAPTCHA interaction costs you real visitors: an extra click here, an unreadable image there, "select all traffic lights" on a phone screen — and the contact request or sale is gone. This plugin flips the deal: instead of making *humans* prove themselves, it makes the *device* pay. The visitor's browser proves it is a real, JavaScript-running client by doing a moment of invisible computation. Zero friction for people, real costs for bots.

= Self-contained and featherweight =

Everything runs on your own web server — there is no external service in the loop. That is not just a privacy nicety, it is an operational one:

* **Nothing external can fail.** No third-party API whose outage, rate limit or latency silently breaks your forms. Your spam protection is exactly as available as your site.
* **Nothing external slows you down.** No remote scripts, no extra DNS lookups or connections — your PageSpeed and Core Web Vitals stay untouched.
* **Tiny footprint.** A few kilobytes of JavaScript and lean server code; runs fine on shared hosting, staging environments and even intranets without internet access.

= Why not just use ... =

* **Google reCAPTCHA, hCaptcha or Turnstile?** They require an account and API keys, load scripts from external servers (hello, consent banners) and still challenge real users when in doubt. This plugin needs no keys, makes no external requests and never challenges anyone.
* **Akismet?** Sends the content of every submission to an external service for analysis, and commercial sites need a subscription. Here, everything stays on your own server.
* **Honeypot fields and time checks?** Modern bots skip honeypots routinely, and browser autofill loves to fill them by accident. Proof-of-work attacks the economics of spam instead of playing hide-and-seek.

And they all share one structural limit: they protect the forms they ship an integration for. This plugin protects the forms *you actually have* (see "Truly universal" above).

= Key features =

* **Invisible** — zero user interaction, ever
* **Protects everything**: logins, registrations, comments, WooCommerce, every form builder — even hand-coded custom forms
* **No account, no API keys, no external services** — install and you are done
* **Brute-force protection** for logins, with optional Fail2Ban log support
* **Adaptive under-attack mode**: the challenge automatically gets harder for everyone while a spam wave is running, and relaxes afterwards
* **Your choice per site**: block spam, deliver it flagged, or just collect it in a spam inbox and watch
* **Teach it live**: unrecognized custom form? Direct analysis mode adds it with one click, straight from the live page
* **Lightweight**: a few KB of JavaScript, no render-blocking, no layout shift
* **Privacy-friendly by design**: no cookies, no sessions, no tracking, no data leaves your server, IP addresses are only stored as hashes — GDPR/DSGVO/RGPD-friendly without a consent banner
* **Free**

= Setup Guide =

[vimeo https://player.vimeo.com/video/905897718]

= Works with =

**WordPress:** Login, Registration, Password Reset, Comments

**WooCommerce:** Checkout, Login, Registration, Password Reset, Comments, Product Reviews

**Form and page builders:** Elementor Pro Forms, Contact Form 7, Fluent Forms, Jetpack Forms, Divi Forms, WPForms, Forminator, Thrive Architect & Thrive Apprentice, Gravity Forms, Formidable Forms, Mailchimp for WordPress Forms, BuddyPress Registration Form, bbPress Create Topic & Reply Forms, Ultimate Member Forms, wpDiscuz Custom Comments Form, Easy Digital Downloads Forms, Paid Memberships Pro Forms, MemberPress Forms, WP-Members Forms, WP User Frontend Forms, CheckoutWC & Flux Checkout, Ninja Forms, Everest Forms, WS Forms, Quform, Otter Blocks, Typeform, NEX-Forms, Bit Form, Form Maker, Funnelforms, Mailjet, Jotform, Page Builder, Metform, Calculated Fields Form, JetFormBuilder, weForms, Responsive Contact Form Builder, Zoho Forms, Smart Forms, Kali Forms, Happyforms, ApplyOnline, Subscribe Forms, FormCraft, Advanced Forms, CRM Perks Forms, Tripetto, Formstack, BuddyForms, vcita, Easy Form Builder, SimpleForm

Anything not on the list can be added in minutes with the built-in analysis modes — no code required.

== Installation ==

1. Install & activate the plugin via the WordPress Plugins page — protection starts immediately with balanced defaults, and popular form builders are configured automatically
2. Watch the short setup video (see above) to understand the message inbox and the analysis modes
3. After a few days, check the message inbox: real submissions arrive as messages, spam lands in the spam folder
4. Using a custom or exotic form that was not recognized? Turn on **direct analysis mode** and add it with one click, straight from the live form
5. (Optional) Decide how to treat spam: block it, deliver it flagged, or just collect it

== Frequently Asked Questions ==

= Does it actually work? =
Yes. For the kind of spam that plagues almost every site — automated, mass-sent — the typical experience after activation is that it simply stops: every message now costs the sender real computing power, which breaks the economics of sending thousands of them. That result has held up across years of production use. And the protection is actively maintained: when a new generation of protocol-aware bots learned to reuse a solved challenge across many submissions, version 5.0 closed that route with single-use, signed tokens. For the rare rest — targeted spam written by humans — the flag-and-inbox workflow keeps you in control instead of promising magic.

= Will my visitors notice anything? =
No. There is nothing to see, click or solve. The proof-of-work runs in the background while the visitor fills in the form and is typically finished in milliseconds — long before they hit *Send*.

= Do I need an account or API keys? =
No. Unlike reCAPTCHA, hCaptcha or Turnstile there is no external service involved — no keys, no registration, no third-party scripts, no rate limits.

= Will it slow down my site? =
No. The plugin ships a few kilobytes of JavaScript, loads no external resources and causes no layout shift. The computation happens on the visitor's device in the background; the server-side check is a single fast lookup.

= Does it work with caching plugins? =
Yes. The challenge token is fetched via Ajax at runtime, so fully cached pages stay protected. One thing to know: right after installing or updating, clear your page cache once so the plugin's JavaScript is included everywhere.

= Which forms are supported? =
All public forms — including hand-coded and custom ones. The plugin recognizes submissions by their signature (the request's characteristic fields and actions) instead of integrating with specific form plugins, so it is not limited to a fixed list. WordPress core, WooCommerce and the several dozen builders listed above come pre-configured; any other form is added without code in under a minute via direct analysis mode: submit it once, click save.

= What data is stored? Is it GDPR compliant? =
Everything stays on your server: no cookies, no sessions, no tracking, no external requests. IP addresses are only stored as SHA-256 hashes, and password fields are never stored with saved messages. That means no consent banner is needed for the spam protection — friendly to GDPR (DSGVO, RGPD) and similar privacy laws.

= Does it protect WooCommerce? =
Yes: checkout, login, registration, password reset, comments and product reviews are covered out of the box.

= What spam does it stop — and what not? =
Every submission has to pay for itself with a small proof-of-work computation. This makes mass spam economically expensive and silently filters out low-effort bots — the vast majority of spam. Like any anti-spam solution (including CAPTCHAs), it cannot fully prevent targeted, low-volume spam sent by a determined human or a bot that invests real computing power per message; for those rare cases, use the flag-instead-of-block option and the spam inbox to keep an eye on what comes through.

= Submissions are incorrectly treated as spam =
1. Right after installation this is usually a caching issue: the proof-of-work JavaScript is not yet included in cached pages. Clear the cache on your webserver (or caching plugin) and in your browser.
2. JavaScript might crash due to an incompatibility with another plugin. Press F12 on the affected page and check the browser console for errors — and please report the issue in the support forum; such reports are usually addressed within a day.

= Neither messages nor spam show up in the inbox =
1. Activate the **Analysis mode**
2. Submit the affected form and look for the captured entry in the **Analytic Box**
3. Open the entry and add it to the protection scope
4. If the submission does not appear there either, please post in the support forum

= After updating, (almost) every submission is flagged as spam =
The protection works by having the visitor's browser silently solve a small puzzle before a form is submitted. If that puzzle is never solved, a genuine submission looks exactly like a bot, so it gets flagged. Right after an update there are three common reasons for this, all quick to rule out:

1. **Stale server code / OPcache.** The update changed the database schema, but your server may still be running the previous version's PHP code from its OPcache — the two no longer match. Flush the OPcache (restart PHP-FPM, or use your host's "Flush OPcache" button), then clear any page/object cache. 5.1 also tries to do this automatically on update, but some hosts still need it done once by hand.
2. **A cached page serving the old script.** If a full-page cache is serving pre-update HTML, browsers load the previous version's script against the new server. Purge your page cache (and CDN) once after updating.
3. **A reverse proxy / CDN without Trusted Proxies set.** If your site sits behind Cloudflare, a load balancer or similar and the plugin sees the proxy's IP instead of the visitor's, the check cannot line up. Set your proxy's address under Settings → Trusted proxies.

To confirm which one it is: open the affected page, press F12 → Console, and look for a warning from "gdpr-recaptcha"; on the Network tab, check that the `get_stamp` request returns clean JSON (no PHP notice/HTML before it). Sharing that in the support forum pins it down immediately.

= Problems with Borlabs Script Blocker =
When you use the Borlabs Script Blocker to scan for JavaScript, the scan does not work properly while this plugin is active. Deactivate this plugin for the scan and reactivate it afterwards.

= Still stuck? =
1. Check the browser console (F12) on the problematic page for messages
2. Post in the support forum with as many details as possible — issues are usually fixed quickly
3. If the protection does not work on a specific form, a short note with the form plugin's name is enough to get it looked at

== Screenshots ==

1. Settings at a glance: protection status strip, topic tabs and short explanations with built-in help for every option
2. The message inbox: real submissions and spam side by side — open any message to see exactly which fields were submitted
3. Direct analysis mode: teach the spam check a new form with one click, straight from the live page
4. Every option explained in place — no documentation hunting

== Upgrade Notice ==
= 5.3.1 =
Maintenance release — see the changelog for details.
= 5.3.0 =
Maintenance release — see the changelog for details.
= 5.2.1 =
Maintenance release — see the changelog for details.
= 5.2.0 =
Maintenance release — see the changelog for details.

= 5.1.1 =
Security release. Fixes three reported vulnerabilities (SQL injection and stored XSS in the admin message views) plus related access-control hardening. Update recommended for all sites.

= 5.1 =
Recommended for everyone. Stronger spam protection (gibberish detection, repeat-sender lock, adaptive re-challenge) and a fix for sites that flagged every submission. If forms misbehave right after updating, flush OPcache and any page/object cache once.

= 5.0 =
Major release: proof-of-work is now bound to single-use signed tokens (much stronger against replay bots), adaptive under-attack difficulty, redesigned settings page, live direct-analysis guide, and several security hardenings. Requires PHP 7.1+.

== Changelog ==
= 5.3.1 =
* Added: Spectra forms are now protected automatically, with no manual setup required.
* Fixed: form builders that submit via URLSearchParams no longer drop the proof-of-work token.
* Fixed: token injection now detects request bodies created inside iframes.
= 5.3.0 =
* New: SureForms and JetFormBuilder are now recognised out of the box.
* The analysis mode shows the REST route for entries captured with the live overlay too, not just for logged ones.
* The analysis mode now records and shows the REST route of a submission, with one click to start monitoring it.
* Fix: default detection for WS Form, Everest Forms, and Otter Blocks never matched — now corrected.
* New: REST routes are now a third way to scope the spam check, covering WS Form and Otter Blocks out of the box.
* Hardening: exemptions from the spam and login checks are now server-side only; the 'Apply on REST-API' option is gone.
* Note: an over-broad field pattern (like just "email") can now match admin screens too; keep patterns form-specific.
* New: status bar and dashboard show how many solved puzzles came back from another address than they were issued to.
* Privacy: nothing derived from the visitor address is in the page source, and the challenge answer carries a fingerprint.
* Hardening: only X-Forwarded-For is still evaluated, and only behind a trusted proxy; four spoofable headers are ignored.
* Fix: a cache, proxy pool or IPv4/IPv6 dual stack no longer flags every submission as spam; puzzles are address-free.
* Blocked messages now name the actual cause, not just the kind of block.
* Fix: submissions are no longer rejected while the site is under attack and an older cached token is solved
* Fix: the token request is no longer served from a page or CDN cache, which could make every submission look like spam
* New: confirm a password field the plugin does not recognise, and its values are redacted, in old messages too.
* Security: password field values could be stored with a submission in some cases; they are now always redacted.
* Security: existing stored entries are cleaned up once after the update.
= 5.2.1 =
* Fix: a difficulty above 20 made every submission spam — the server issued challenges its own check rejected.
= 5.2.0 =
* Spam messages now show why they were blocked, plus a health counter for submissions without a proof-of-work stamp.
= 5.1.1 =
Security release. Fixes the three reported vulnerabilities and, after a full internal review, several related hardenings across the message-management area.
* Security (SQL injection): admin-defined spam-analysis patterns are now escaped before they are interpolated into the LIKE conditions of the message queries. Closes an authenticated (Editor+) SQL injection via the pattern key/value (CVE-2026-16094, CVE-2026-16146).
* Security (stored XSS): the form "action" value shown on the Spam/Messages admin pages is now JavaScript-escaped inside the inline submit handlers, not only HTML-attribute-escaped, so a quote in a captured action can no longer break out into script (CVE-2026-16145). A second highlighting sink in the detail view that re-decoded escaped values is now built via DOM text nodes, so captured content can never execute there either.
* Security (access control / CSRF): every message action — viewing, moving, deleting (including "delete all") and saving patterns / action lists — now verifies its nonce before acting and requires the manage_options capability. Previously the "delete all" path ran without a verified nonce or capability, and the whole message area was reachable with edit_pages. NOTE: managing captured messages is now limited to administrators.
* Security (log injection): the Fail2Ban integration now strictly sanitises the login name and strips line breaks, so a crafted login can no longer forge log lines / ban arbitrary IPs; it also logs the validated client IP instead of the raw remote address.
* Hardening: consistent unslashing/sanitising of admin-AJAX input; guards against malformed unauthenticated requests that could raise PHP errors on the spam-check path; and, on multisite, the Fail2Ban log path can only be set by super admins (with path-traversal rejected).
= 5.1 =
This release brings stronger anti-spam layers to every site, alongside important reliability fixes.
* New: gibberish detection — obvious keyboard-mash and random-string submissions are recognised and filtered, language-neutrally, while legitimate codes (VAT ids, serials, order numbers, product names) are left untouched.
* New: repeat-sender ("echo") lock — once a message is classified as spam, its core values (sender, linked domain, phone, long-text hash) are briefly remembered as one-way hashes with a short lifetime, so the same sender is caught again on any form and any IP. It can be switched off, and its remembered values reset, on the settings page; registered users' and admins' addresses are excluded so an injected spam mail can never lock them out of login or password reset.
* New: an adaptive solve-time re-challenge makes implausibly fast (likely non-browser) solves pay more, without ever hard-blocking a genuine visitor.
* New: form builders you activate AFTER installing the plugin are now covered automatically (previously only builders present at install time were). A one-time notice lets you review and confirm any that were already active but not yet covered — your own custom entries, and anything you removed, are never touched.
* Fix: on a small number of sites, every submission could be flagged as spam. The browser-side puzzle is now resilient — a stray PHP notice, a byte-order mark or a proxy error page in the get_stamp response no longer aborts it, and if the request cannot be made at all it falls back to the token already embedded in the page.
* Fix: a password field without a name attribute could abort the script's setup on some themes/builders; hardened so it can no longer break token injection into Ajax form submissions.
* Fix: the challenge-renew timer is now clamped to a sane minimum, so an empty/zero "Time Window" option can no longer cause rapid background requests to admin-ajax.
* Fix: the invisible token is no longer added to GET forms (e.g. a theme's search box), so searching no longer appends a long "gdpr_pow_token=..." to the URL. POST forms are unaffected and stay protected.
* Compatibility: a third-party script that wraps fetch/XHR before the visitor first interacts is no longer overwritten by the plugin.
* Hardening: after an update the plugin proactively invalidates the PHP OPcache for its own files, reducing the chance of old code running against the new database schema. On some hosts an OPcache flush / PHP-FPM restart may still be needed once — see the FAQ.
= 5.0 =
* Major anti-spam hardening against protocol-aware bots: every proof-of-work is now bound to a single-use, HMAC-signed token per submission (replay of one solved challenge no longer works), with a per-token and per-IP usage limit
* Forwarded-For/Client-IP headers are only trusted behind a configurable trusted-proxy list (new option) — closes IP-spoofing of the whitelist
* Adaptive difficulty with an automatic site-wide "under-attack mode" (new option): the puzzle gets harder for everyone while a spam wave is running; no per-visitor data involved
* Proof-of-work now uses the browser's native crypto engine where available (about 10x faster), with a fallback for older browsers and http-only sites
* Faster spam-check path: worker no longer sleeps up to 5 seconds under a spam flood
* Redesigned settings page: status strip, topic tabs, short descriptions with progressive-disclosure help on every option
* Reworked direct analysis mode: persistent guide bar with live coverage instead of stacked popups, entries persist server-side
* Security: password fields are never stored in captured submissions — neither in the classic analysis inbox nor in direct-analysis entries
* Security: CSRF protection (nonce) added to the direct-analysis pattern-save endpoint
* Security: SQL statements consistently use prepared placeholders; full WordPress coding-standards pass across the whole codebase
* Recognition patterns can no longer accidentally match on the plugin's own injected fields
* All option texts are now translatable via the WordPress.org community catalog (translate.wordpress.org)
* Requires PHP 7.1 or newer (was effectively required before, now declared honestly)
= 4.1.2 =
* CSRF vulnerability fixed
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
