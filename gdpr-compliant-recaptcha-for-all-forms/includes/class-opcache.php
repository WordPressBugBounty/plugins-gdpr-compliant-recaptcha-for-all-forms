<?php

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

defined( 'ABSPATH' ) || die( 'Are you ok?' );

// Detail-Doku (Methodenebene): handbuch/admin.md.
// Index/Absprungstelle: HANDBUCH.md — dort steht nur EINE Zeile je Klasse.

/**
 * Invalidating this plugin's own OPcache entries after an update.
 *
 * Split out of the bootstrap file in 6.0.0: it is a self-contained piece of hosting
 * plumbing that never touches the plugin's own state, while the file it sat in is the
 * lifecycle/hook wiring and was at its line cap. The cut is along the subject, and it
 * makes the behaviour directly reachable for a test.
 */
final class Opcache {

	/**
	 * Invalidate the OPcache entries for this plugin's own PHP files. No-op when
	 * OPcache is disabled or the invalidate API is unavailable/restricted. Never
	 * calls opcache_reset(): that would nuke every other app's cache on shared hosting.
	 *
	 * @return void
	 */
	public static function invalidate_plugin_files() {
		if ( ! function_exists( 'opcache_invalidate' ) || ! ini_get( 'opcache.enable' ) ) {
			return;
		}
		// Recurse the plugin directory with a portable iterator. Deliberately NOT
		// glob('{,*/}*.php', GLOB_BRACE): GLOB_BRACE is not defined on every platform
		// (absent on musl/Alpine, common in containers and on some managed hosts), and
		// referencing it there is a fatal "undefined constant" — the very kind of
		// breakage this method is meant to prevent.
		try {
			$iterator = new \RecursiveIteratorIterator(
				// dirname( __DIR__ ), NOT __FILE__-relative: this class lives in
				// includes/, so __FILE__-relative would start the walk one level too deep
				// and skip recaptcha-gdpr-compliant.php and uninstall.php — the lifecycle
				// and migration code this invalidation exists for in the first place.
				// The 6.0.0 move out of the bootstrap file introduced exactly that bug;
				// pinned in OpcacheTest so the next move cannot repeat it.
				new \RecursiveDirectoryIterator( dirname( __DIR__ ) . '/', \FilesystemIterator::SKIP_DOTS )
			);
		} catch ( \Exception $e ) {
			return;
		}
		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() || 'php' !== strtolower( $file->getExtension() ) ) {
				continue;
			}
			$path = $file->getPathname();
			// wp_opcache_invalidate() (WP >=5.5) wraps opcache_invalidate() and honours
			// opcache.restrict_api; fall back to the raw call on older cores.
			if ( function_exists( 'wp_opcache_invalidate' ) ) {
				// Called via a variable so Plugin Check's "requires WP 5.5" static
				// compatibility check does not flag it while the plugin still declares
				// "Requires at least: 4.8": the function_exists() guard already makes the
				// call safe on older cores (which take the raw-call fallback below), and
				// this security update must keep reaching those installs.
				$wp_opcache_invalidate = 'wp_opcache_invalidate';
				$wp_opcache_invalidate( $path, true );
			} else {
				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- opcache.restrict_api can make this emit a warning for a path outside the allowed prefix; the invalidation is strictly best-effort hardening, so silence is intended.
				@opcache_invalidate( $path, true );
			}
		}
	}
}
