// Firefox Zero user.js
// rev20230111
 
// Privacy & Local Storage
user_pref("browser.bookmarks.max_backups", 0); // No bookmarks backup
user_pref("browser.cache.disk.enable", false); // Disable disk cache
user_pref("browser.cache.offline.enable", false); // Disable offline cache
user_pref("browser.messaging-system.whatsNewPanel.enabled", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);
user_pref("browser.newtabpage.activity-stream.discoverystream.enabled", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.highlights", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
user_pref("browser.newtabpage.activity-stream.showSearch", false);
user_pref("browser.newtabpage.enabled", false); // Disable newtab page
user_pref("browser.privatebrowsing.autostart", true); // Always private mode
user_pref("browser.sessionstore.max_tabs_undo", 0); // No tab restore
user_pref("browser.startup.homepage", "about:blank"); // Blank startup
user_pref("browser.topsites.contile.enabled", false);
user_pref("signon.autofillForms", false);
user_pref("signon.rememberSignons", false); // No passwords
user_pref("startup.homepage_welcome_url", "");

// Search Bar Results
user_pref("browser.search.suggest.enabled", false); // Disable search suggestions
user_pref("browser.search.update", false); // Disable search engine changes
user_pref("browser.urlbar.maxRichResults", 0);
user_pref("browser.urlbar.speculativeConnect.enabled", false); // Disable autocomplete URLs

// Network Configuration
user_pref("browser.region.network.url", "");
user_pref("captivedetect.canonicalURL", "");
user_pref("dom.security.https_only_mode", true); // HTTPS-only mode
user_pref("network.captive-portal-service.enabled", false); // Disable captive portal
user_pref("network.connectivity-service.enabled", false);
user_pref("network.cookie.cookieBehavior", 1); // Block 3p cookies
user_pref("network.dns.disablePrefetch", true); // Disable DNS prefetching
user_pref("network.http.referer.XOriginPolicy", 1); // Block 3p referers
user_pref("network.predictor.enabled", false); // Disable predictor
user_pref("network.prefetch-next", false); // Disable link prefetching
user_pref("network.trr.mode", 3); // DNS-over-HTTPS
user_pref("network.trr.uri", "https://dns.nextdns.io");

// Device Fingerprinting
user_pref("beacon.enabled", false); // Disable beacon
user_pref("device.sensors.enabled", false); // Disable sensors
user_pref("dom.battery.enabled", false); // Disable battery status
user_pref("dom.event.clipboardevents.enabled", false); // Disable clipboard events
user_pref("dom.gamepad.enabled", false); // Disable USB devices
user_pref("dom.push.enabled", false); // Disable push service
user_pref("dom.webnotifications.enabled", false); // Disable desktop notifications
user_pref("geo.enabled", false); // Disable geolocation
user_pref("geo.provider.network.url", "");
//user_pref("gfx.canvas.max-size", 0); // Disable canvas
user_pref("media.navigator.enabled", false); // Disable mic and camera
user_pref("media.peerconnection.enabled", false); // Disable WebRTC
user_pref("media.webspeech.synth.enabled", false); // Disable speech synthesis
user_pref("privacy.firstparty.isolate", true); // Restrict data to domain level
user_pref("webgl.disabled", true); // Disable WebGL

// Telemetry & Shield
user_pref("app.normandy.api_url", "");
user_pref("app.normandy.enabled", false); // Disable shield telemetry
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false); // Disable all technical data
user_pref("datareporting.policy.firstRunURL", "");
user_pref("toolkit.telemetry.server", "");
user_pref("toolkit.telemetry.unified", false); // Disable Fx telemetry

// Add-ons Behavior
user_pref("extensions.blocklist.enabled", false); // Disable blocklist
user_pref("extensions.getAddons.cache.enabled", false);
user_pref("extensions.getAddons.discovery.api_url", "");
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false); // Disable add-ons recommendations
user_pref("extensions.systemAddon.update.enabled", false); // Disable system add-ons updates
user_pref("extensions.systemAddon.update.url", "");
user_pref("extensions.update.autoUpdateDefault", false); // Disable autoinstall extension updates
user_pref("extensions.update.enabled", false); // Disable autochecking for extension updates

// Features & Media Plugins
user_pref("accessibility.force_disabled", 1);
user_pref("extensions.formautofill.available", "off"); // Disable autofill
user_pref("extensions.pocket.enabled", false); // Disable pocket
user_pref("extensions.screenshots.disabled", true); // Disable screenshots
user_pref("extensions.webcompat-reporter.enabled", false); // Disable report this site
user_pref("identity.fxaccounts.enabled", false); // Disable Fx accounts
user_pref("media.eme.enabled", false); // Disable EME for DRM content
user_pref("media.gmp-gmpopenh264.enabled", false); // Disable OpenH264 for WebRTC
user_pref("media.gmp-manager.url", "");
user_pref("media.gmp-provider.enabled", false);
user_pref("media.gmp-widevinecdm.enabled", false); // Disable Widevine CDM
user_pref("privacy.trackingprotection.cryptomining.enabled", false);
user_pref("privacy.trackingprotection.enabled", false); // Redundant with uBlock0
user_pref("privacy.trackingprotection.fingerprinting.enabled", false);
user_pref("privacy.trackingprotection.pbmode.enabled", false);
user_pref("signon.management.page.breach-alerts.enabled", false);

// Miscellaneous
user_pref("browser.aboutConfig.showWarning", false); // Disable modify warning
user_pref("browser.shell.checkDefaultBrowser", false); // Disable default check
user_pref("browser.uidensity", 1); // Compact density
user_pref("findbar.highlightAll", true); // Highlight text search
user_pref("general.smoothScroll", false); // Smooth scrolling off
user_pref("reader.parse-on-load.enabled", false); // Disable reader
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true); // Legacy CSS support
user_pref("ui.systemUsesDarkTheme", 1);
user_pref("ui.prefersReducedMotion", 1); // Disable animations

// Google Safe Browsing
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.provider.mozilla.gethashURL", "");
user_pref("browser.safebrowsing.provider.mozilla.updateURL", "");
