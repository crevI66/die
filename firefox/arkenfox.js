
/* INDEX:

  0100: STARTUP
  0200: GEOLOCATION / LANGUAGE / LOCALE
  0300: QUIETER FOX
  0400: SAFE BROWSING
  0600: BLOCK IMPLICIT OUTBOUND
  0700: DNS / DoH / PROXY / SOCKS / IPv6
  0800: LOCATION BAR / SEARCH BAR / SUGGESTIONS / HISTORY / FORMS
  0900: PASSWORDS
  1000: DISK AVOIDANCE
  1200: HTTPS (SSL/TLS / OCSP / CERTS / HPKP)
  1400: FONTS
  1600: HEADERS / REFERERS
  1700: CONTAINERS
  2000: PLUGINS / MEDIA / WEBRTC
  2400: DOM (DOCUMENT OBJECT MODEL)
  2600: MISCELLANEOUS
  2700: ETP (ENHANCED TRACKING PROTECTION)
  2800: SHUTDOWN & SANITIZING
  4500: RFP (RESIST FINGERPRINTING)
  5000: OPTIONAL OPSEC
  5500: OPTIONAL HARDENING
  6000: DON'T TOUCH
  7000: DON'T BOTHER
  8000: DON'T BOTHER: FINGERPRINTING
  9000: NON-PROJECT RELATED
  9999: DEPRECATED / REMOVED / LEGACY / RENAMED

******/

/* START: internal custom pref to test for syntax errors*/

user_pref("_user.js.parrot", "START: Oh yes, the Norwegian Blue... what's wrong with it?");


/* 0000: disable about:config warning ***/

user_pref("browser.aboutConfig.showWarning", false);


/*** [SECTION 0100]: STARTUP ***/
user_pref("_user.js.parrot", "0100 syntax error: the parrot's dead!");
/* 0102: set startup page [SETUP-CHROME]
 * 0=blank, 1=home, 2=last visited page, 3=resume previous session */

user_pref("browser.startup.page", 0);


/* 0103: set HOME+NEWWINDOW page
 * about:home=Firefox Home, about:blank*/

user_pref("browser.startup.homepage", "about:blank");


/* 0104: set NEWTAB page
 * true=Firefox Home, false=blank page */

user_pref("browser.newtabpage.enabled", false);


/* 0105: disable sponsored content on Firefox Home (Activity Stream)*/

user_pref("browser.newtabpage.activity-stream.showSponsored", false); // [FF58+] Pocket > Sponsored Stories
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false); // [FF83+] Sponsored shortcuts


/* 0106: clear default topsites*/

user_pref("browser.newtabpage.activity-stream.default.sites", "");


/*** [SECTION 0200]: GEOLOCATION / LANGUAGE / LOCALE ***/
user_pref("_user.js.parrot", "0200 syntax error: the parrot's definitely deceased!");

/* 0201: use Mozilla geolocation service instead of Google if permission is granted [FF74+]
 * Optionally enable logging to the console (defaults to false) ***/

user_pref("geo.provider.network.url", "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%");
   // user_pref("geo.provider.network.logging.enabled", true); // [HIDDEN PREF]


/* 0202: disable using the OS's geolocation service ***/

user_pref("geo.provider.ms-windows-location", false); // [WINDOWS]
user_pref("geo.provider.use_corelocation", false); // [MAC]
user_pref("geo.provider.use_gpsd", false); // [LINUX]
user_pref("geo.provider.use_geoclue", false); // [FF102+] [LINUX]


/* 0210: set preferred language for displaying pages

 * [SETTING] General>Language and Appearance>Language>Choose your preferred language...*/

user_pref("intl.accept_languages", "en-US, en");


/* 0211: use en-US locale regardless of the system or region locale*/

user_pref("javascript.use_us_english_locale", true); // [HIDDEN PREF]


/*** [SECTION 0300]: QUIETER FOX ***/
user_pref("_user.js.parrot", "0300 syntax error: the parrot's not pinin' for the fjords!");


/** RECOMMENDATIONS ***/
/* 0320: disable recommendation pane in about:addons (uses Google Analytics) ***/

user_pref("extensions.getAddons.showPane", false); // [HIDDEN PREF]


/* 0321: disable recommendations in about:addons' Extensions and Themes panes [FF68+] ***/

user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);


/* 0322: disable personalized Extension Recommendations in about:addons and AMO [FF65+]*/

user_pref("browser.discovery.enabled", false);


/** TELEMETRY ***/
/* 0330: disable new data submission [FF41+]*/

user_pref("datareporting.policy.dataSubmissionEnabled", false);


/* 0331: disable Health Reports*/

user_pref("datareporting.healthreport.uploadEnabled", false);


/* 0332: disable telemetry*/

user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.server", "data:,");
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false); // [FF55+]
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false); // [FF55+]
user_pref("toolkit.telemetry.updatePing.enabled", false); // [FF56+]
user_pref("toolkit.telemetry.bhrPing.enabled", false); // [FF57+] Background Hang Reporter
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false); // [FF57+]
user_pref("toolkit.telemetry.coverage.opt-out", true); // [HIDDEN PREF]
user_pref("toolkit.coverage.opt-out", true); // [FF64+] [HIDDEN PREF]
user_pref("toolkit.coverage.endpoint.base", "");
user_pref("browser.ping-centre.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);


/** STUDIES ***/
/* 0340: disable Studies*/

user_pref("app.shield.optoutstudies.enabled", false);


/* 0341: disable Normandy/Shield [FF60+]*/

user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");

/** CRASH REPORTS ***/
/* 0350: disable Crash Reports ***/

user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false); // [FF44+]
   // user_pref("browser.crashReports.unsubmittedCheck.enabled", false); // [FF51+] [DEFAULT: false]
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false); // [DEFAULT: false]


/** OTHER ***/
/* 0360: disable Captive Portal detection*/

user_pref("captivedetect.canonicalURL", "");
user_pref("network.captive-portal-service.enabled", false); // [FF52+]


/* 0361: disable Network Connectivity checks [FF65+]*/

user_pref("network.connectivity-service.enabled", false);



/*** [SECTION 0400]: SAFE BROWSING (SB)
   SB has taken many steps to preserve privacy. If required, a full url is never sent
   to Google, only a part-hash of the prefix, hidden with noise of other real part-hashes.
   Firefox takes measures such as stripping out identifying parameters and since SBv4 (FF57+)
   doesn't even use cookies. (#Turn on browser.safebrowsing.debug to monitor this activity)

   [1] https://feeding.cloud.geek.nz/posts/how-safe-browsing-works-in-firefox/
   [2] https://wiki.mozilla.org/Security/Safe_Browsing
   [3] https://support.mozilla.org/kb/how-does-phishing-and-malware-protection-work
   [4] https://educatedguesswork.org/posts/safe-browsing-privacy/
***/

user_pref("_user.js.parrot", "0400 syntax error: the parrot's passed on!");


/* 0401: disable SB (Safe Browsing)
 * [WARNING] Do this at your own risk! These are the master switches
 * [SETTING] Privacy & Security>Security>... Block dangerous and deceptive content ***/
   // user_pref("browser.safebrowsing.malware.enabled", false);
   // user_pref("browser.safebrowsing.phishing.enabled", false);


/* 0402: disable SB checks for downloads (both local lookups + remote)
 * This is the master switch for the safebrowsing.downloads**/

   // user_pref("browser.safebrowsing.downloads.enabled", false);


/* 0403: disable SB checks for downloads (remote)
 * To verify the safety of certain executable files, Firefox may submit some information about the
 * file, including the name, origin, size and a cryptographic hash of the contents, to the Google
 * Safe Browsing service which helps Firefox determine whether or not the file should be blocked
 * [SETUP-SECURITY] If you do not understand this, or you want this protection, then override this ***/

user_pref("browser.safebrowsing.downloads.remote.enabled", false);
   // user_pref("browser.safebrowsing.downloads.remote.url", ""); // Defense-in-depth


/* 0404: disable SB checks for unwanted software
 * [SETTING] Privacy & Security>Security>... "Warn you about unwanted and uncommon software" ***/

   // user_pref("browser.safebrowsing.downloads.remote.block_potentially_unwanted", false);
   // user_pref("browser.safebrowsing.downloads.remote.block_uncommon", false);


/* 0405: disable "ignore this warning" on SB warnings [FF45+]
 * If clicked, it bypasses the block for that session. This is a means for admins to enforce SB
 * [TEST] see https://github.com/arkenfox/user.js/wiki/Appendix-A-Test-Sites#-mozilla
 * [1] https://bugzilla.mozilla.org/1226490 ***/

   // user_pref("browser.safebrowsing.allowOverride", false);



/*** [SECTION 0600]: BLOCK IMPLICIT OUTBOUND [not explicitly asked for - e.g. clicked on] ***/

user_pref("_user.js.parrot", "0600 syntax error: the parrot's no more!");


/* 0601: disable link prefetching*/

user_pref("network.prefetch-next", false);


/* 0602: disable DNS prefetching*/

user_pref("network.dns.disablePrefetch", true);
   // user_pref("network.dns.disablePrefetchFromHTTPS", true); // [DEFAULT: true]


/* 0603: disable predictor / prefetching ***/

user_pref("network.predictor.enabled", false);
user_pref("network.predictor.enable-prefetch", false); // [FF48+] [DEFAULT: false]


/* 0604: disable link-mouseover opening connection to linked server*/

user_pref("network.http.speculative-parallel-limit", 0);


/* 0605: disable mousedown speculative connections on bookmarks and history [FF98+] ***/

user_pref("browser.places.speculativeConnect.enabled", false);


/* 0610: enforce no "Hyperlink Auditing" (click tracking)*/

   // user_pref("browser.send_pings", false); // [DEFAULT: false]


/*** [SECTION 0700]: DNS / DoH / PROXY / SOCKS / IPv6 ***/

user_pref("_user.js.parrot", "0700 syntax error: the parrot's given up the ghost!");


/* 0701: disable IPv6
 * IPv6 can be abused, especially with MAC addresses, and can leak with VPNs: assuming
 * your ISP and/or router and/or website is IPv6 capable. Most sites will fall back to IPv4
 * [SETUP-WEB] PR_CONNECT_RESET_ERROR: this pref *might* be the cause
 * [STATS] Firefox telemetry (Sept 2022) shows ~8% of successful connections are IPv6
 * [NOTE] This is an application level fallback. Disabling IPv6 is best done at an
 * OS/network level, and/or configured properly in VPN setups. If you are not masking your IP,
 * then this won't make much difference. If you are masking your IP, then it can only help.

 * [NOTE] PHP defaults to IPv6 with "localhost". Use "php -S 127.0.0.1:PORT"
 * [TEST] https://ipleak.org/
 * [1] https://www.internetsociety.org/tag/ipv6-security/ (Myths 2,4,5,6) ***/
user_pref("network.dns.disableIPv6", true);


/* 0702: set the proxy server to do any DNS lookups when using SOCKS
 * e.g. in Tor, this stops your local DNS server from knowing your Tor destination
 * as a remote Tor node will handle the DNS request
 * [1] https://trac.torproject.org/projects/tor/wiki/doc/TorifyHOWTO/WebBrowsers ***/

user_pref("network.proxy.socks_remote_dns", true);


/* 0703: disable using UNC (Uniform Naming Convention) paths [FF61+]
 * [SETUP-CHROME] Can break extensions for profiles on network shares
 * [1] https://gitlab.torproject.org/tpo/applications/tor-browser/-/issues/26424 ***/

user_pref("network.file.disable_unc_paths", true); // [HIDDEN PREF]


/* 0704: disable GIO as a potential proxy bypass vector
 * Gvfs/GIO has a set of supported protocols like obex, network, archive, computer,
 * dav, cdda, gphoto2, trash, etc. By default only sftp is accepted (FF87+)*/

user_pref("network.gio.supported-protocols", ""); // [HIDDEN PREF]


/* 0705: disable proxy direct failover for system requests [FF91+]
 * [WARNING] Default true is a security feature against malicious extensions [1]
 * [SETUP-CHROME] If you use a proxy and you trust your extensions*/

   // user_pref("network.proxy.failover_direct", false);


/* 0706: disable proxy bypass for system request failures [FF95+]
 * RemoteSettings, UpdateService, Telemetry [1]
 * [WARNING] If false, this will break the fallback for some security features
 * [SETUP-CHROME] If you use a proxy and you understand the security impact*/

   // user_pref("network.proxy.allow_bypass", false); // [HIDDEN PREF FF95-96]


/* 0710: disable DNS-over-HTTPS (DoH) rollout [FF60+]
 * 0=off by default, 2=TRR (Trusted Recursive Resolver) first, 3=TRR only, 5=explicitly off
 * see "doh-rollout.home-region": USA 2019, Canada 2021, Russia/Ukraine 2022 [3]
 * [1] https://hacks.mozilla.org/2018/05/a-cartoon-intro-to-dns-over-https/
 * [2] https://wiki.mozilla.org/Security/DOH-resolver-policy
 * [3] https://support.mozilla.org/en-US/kb/firefox-dns-over-https
 * [4] https://www.eff.org/deeplinks/2020/12/dns-doh-and-odoh-oh-my-year-review-2020 ***/

   user_pref("network.trr.mode", 3);



/*** [SECTION 0800]: LOCATION BAR / SEARCH BAR / SUGGESTIONS / HISTORY / FORMS ***/

user_pref("_user.js.parrot", "0800 syntax error: the parrot's ceased to be!");


/* 0801: disable location bar using search
 * Don't leak URL typos to a search engine, give an error message instead
 * Examples: "secretplace,com", "secretplace/com", "secretplace com", "secret place.com"*/

user_pref("keyword.enabled", false);


/* 0802: disable location bar domain guessing
 * domain guessing intercepts DNS "hostname not found errors" and resends a
 * request (e.g. by adding www or .com). This is inconsistent use (e.g. FQDNs), does not work
 * via Proxy Servers (different error), is a flawed use of DNS (TLDs: why treat .com
 * as the 411 for DNS errors?), privacy issues (why connect to sites you didn't
 * intend to), can leak sensitive data (e.g. query strings: e.g. Princeton attack),
 * and is a security risk (e.g. common typos & malicious sites set up to exploit this) ***/

user_pref("browser.fixup.alternate.enabled", false); // [DEFAULT: false FF104+]


/* 0804: disable live search suggestions
 * [NOTE] Both must be true for the location bar to work*/

user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);


/* 0805: disable location bar making speculative connections [FF56+]*/

user_pref("browser.urlbar.speculativeConnect.enabled", false);


/* 0806: disable location bar leaking single words to a DNS provider **after searching** [FF78+]
 * 0=never resolve, 1=use heuristics, 2=always resolve*/

user_pref("browser.urlbar.dnsResolveSingleWordsAfterSearch", 0); // [DEFAULT: 0 FF104+]


/* 0807: disable location bar contextual suggestions [FF92+]*/

user_pref("browser.urlbar.suggest.quicksuggest.nonsponsored", false); // [FF95+]
user_pref("browser.urlbar.suggest.quicksuggest.sponsored", false);


/* 0808: disable tab-to-search [FF85+]
 * Alternatively, you can exclude on a per-engine basis by unchecking them in Options>Search
 * [SETTING] Privacy & Security>Address Bar>When using the address bar, suggest>Search engines ***/

  user_pref("browser.urlbar.suggest.engines", false);


/* 0810: disable search and form history
 * [SETUP-WEB] Be aware that autocomplete form data can be read by third parties [1][2]*/

user_pref("browser.formfill.enable", false);


/* 0820: disable coloring of visited links
 * [SETUP-HARDEN] Bulk rapid history sniffing was mitigated in 2010 [1][2]. Slower and more expensive
 * redraw timing attacks were largely mitigated in FF77+ [3]. Using RFP (4501) further hampers timing
 * attacks. Don't forget clearing history on exit (2811). However, social engineering [2#limits][4][5]
 * and advanced targeted timing attacks could still produce usable results*/

   // user_pref("layout.css.visited_links_enabled", false);


/*** [SECTION 0900]: PASSWORDS*/

user_pref("_user.js.parrot", "0900 syntax error: the parrot's expired!");


/* 0903: disable auto-filling username & password form fields*/

user_pref("signon.autofillForms", false);
user_pref("signon.formlessCapture.enabled", false);
user_pref("network.auth.subresource-http-auth-allow", 1);


/* 0906: enforce no automatic authentication on Microsoft sites [FF91+] [WINDOWS 10+]
 * [SETTING] Privacy & Security>Logins and Passwords>Allow Windows single sign-on for...
 * [1] https://support.mozilla.org/kb/windows-sso ***/

   // user_pref("network.http.windows-sso.enabled", false); // [DEFAULT: false]


/*** [SECTION 1000]: DISK AVOIDANCE ***/

user_pref("_user.js.parrot", "1000 syntax error: the parrot's gone to meet 'is maker!");


/* 1001: disable disk cache
 * [SETUP-CHROME] If you think disk cache helps perf, then feel free to override this
 * [NOTE] We also clear cache on exit (2811) ***/

user_pref("browser.cache.disk.enable", false);


/* 1002: disable media cache from writing to disk in Private Browsing
 * [NOTE] MSE (Media Source Extensions) are already stored in-memory in PB ***/

user_pref("browser.privatebrowsing.forceMediaMemoryCache", true); // [FF75+]
user_pref("media.memory_cache_max_size", 65536);


/* 1003: disable storing extra session data [SETUP-CHROME]
 * define on which sites to save extra session data such as form content, cookies and POST data
 * 0=everywhere, 1=unencrypted sites, 2=nowhere ***/

user_pref("browser.sessionstore.privacy_level", 2);


/* 1005: disable automatic Firefox start and session restore after reboot [FF62+] [WINDOWS]
 * [1] https://bugzilla.mozilla.org/603903 ***/

user_pref("toolkit.winRegisterApplicationRestart", false);


/* 1006: disable favicons in shortcuts
 * URL shortcuts use a cached randomly named .ico file which is stored in your
 * profile/shortcutCache directory. The .ico remains after the shortcut is deleted
 * If set to false then the shortcuts use a generic Firefox icon ***/

user_pref("browser.shell.shortcutFavicons", false);


/*** [SECTION 1200]: HTTPS (SSL/TLS / OCSP / CERTS / HPKP)*/

user_pref("_user.js.parrot", "1200 syntax error: the parrot's a stiff!");


/** SSL (Secure Sockets Layer) / TLS (Transport Layer Security) ***/
/* 1201: require safe negotiation
 * Blocks connections to servers that don't support RFC 5746 [2] as they're potentially vulnerable to a
 * MiTM attack [3]. A server without RFC 5746 can be safe from the attack if it disables renegotiations*/

user_pref("security.ssl.require_safe_negotiation", true);


/* 1206: disable TLS1.3 0-RTT (round-trip time) [FF51+]*/

user_pref("security.tls.enable_0rtt_data", false);


/** OCSP (Online Certificate Status Protocol)*/

/* 1211: enforce OCSP fetching to confirm current validity of certificates
 * 0=disabled, 1=enabled (default), 2=enabled for EV certificates only*/

user_pref("security.OCSP.enabled", 1); // [DEFAULT: 1]


/* 1212: set OCSP fetch failures (non-stapled, see 1211) to hard-fail*/

user_pref("security.OCSP.require", true);


/** CERTS / HPKP (HTTP Public Key Pinning) ***/
/* 1221: disable Windows 8.1's Microsoft Family Safety cert [FF50+] [WINDOWS]
 * 0=disable detecting Family Safety mode and importing the root
 * 1=only attempt to detect Family Safety mode (don't import the root)
 * 2=detect Family Safety mode and import the root*/

user_pref("security.family_safety.mode", 0);


/* 1223: enable strict PKP (Public Key Pinning)
 * 0=disabled, 1=allow user MiTM (default; such as your antivirus), 2=strict
 * [SETUP-WEB] MOZILLA_PKIX_ERROR_KEY_PINNING_FAILURE ***/

user_pref("security.cert_pinning.enforcement_level", 2);


/* 1224: enable CRLite [FF73+]
 * 0 = disabled
 * 1 = consult CRLite but only collect telemetry
 * 2 = consult CRLite and enforce both "Revoked" and "Not Revoked" results
 * 3 = consult CRLite and enforce "Not Revoked" results, but defer to OCSP for "Revoked" (FF99+, default FF100+)*/

user_pref("security.remote_settings.crlite_filters.enabled", true);
user_pref("security.pki.crlite_mode", 2);


/** MIXED CONTENT ***/
/* 1241: disable insecure passive content (such as images) on https pages ***/

   // user_pref("security.mixed_content.block_display_content", true); // Defense-in-depth (see 1244)


/* 1244: enable HTTPS-Only mode in all windows [FF76+]*/

user_pref("dom.security.https_only_mode", true); // [FF76+]
   // user_pref("dom.security.https_only_mode_pbm", true); // [FF80+]


/* 1245: enable HTTPS-Only mode for local resources [FF77+] ***/

   // user_pref("dom.security.https_only_mode.upgrade_local", true);


/* 1246: disable HTTP background requests [FF82+]
 * When attempting to upgrade, if the server doesn't respond within 3 seconds, Firefox sends
 * a top-level HTTP request without path in order to check if the server supports HTTPS or not
 * This is done to avoid waiting for a timeout which takes 90 seconds
 * [1] https://bugzilla.mozilla.org/buglist.cgi?bug_id=1642387,1660945 ***/

user_pref("dom.security.https_only_mode_send_http_background_request", false);


/** UI (User Interface) ***/
/* 1270: display warning on the padlock for "broken security" (if 1201 is false)*/

user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);


/* 1272: display advanced information on Insecure Connection warning pages
 * only works when it's possible to add an exception
 * i.e. it doesn't work for HSTS discrepancies (https://subdomain.preloaded-hsts.badssl.com/)
 * [TEST] https://expired.badssl.com/ ***/

user_pref("browser.xul.error_pages.expert_bad_cert", true);


/*** [SECTION 1400]: FONTS ***/

user_pref("_user.js.parrot", "1400 syntax error: the parrot's bereft of life!");


/* 1402: limit font visibility (Windows, Mac, some Linux) [FF94+]
 * Uses hardcoded lists with two parts: kBaseFonts + kLangPackFonts [1], bundled fonts are auto-allowed
 * In normal windows: uses the first applicable: RFP (4506) over TP over Standard
 * In Private Browsing windows: uses the most restrictive between normal and private
 * 1=only base system fonts, 2=also fonts from optional language packs, 3=also user-installed fonts*/

   // user_pref("layout.css.font-visibility.private", 1);
   // user_pref("layout.css.font-visibility.standard", 1);
   // user_pref("layout.css.font-visibility.trackingprotection", 1);



/*** [SECTION 1600]: HEADERS / REFERERS
                  full URI: https://example.com:8888/foo/bar.html?id=1234
     scheme+host+port+path: https://example.com:8888/foo/bar.html
          scheme+host+port: https://example.com:8888
   [1] https://feeding.cloud.geek.nz/posts/tweaking-referrer-for-privacy-in-firefox/
***/

user_pref("_user.js.parrot", "1600 syntax error: the parrot rests in peace!");


/* 1601: control when to send a cross-origin referer
 * 0=always (default), 1=only if base domains match, 2=only if hosts match
 * [SETUP-WEB] Breakage: older modems/routers and some sites e.g banks, vimeo, icloud, instagram
 * If "2" is too strict, then override to "0" and use Smart Referer extension (Strict mode + add exceptions) ***/

user_pref("network.http.referer.XOriginPolicy", 1);


/* 1602: control the amount of cross-origin information to send [FF52+]
 * 0=send full URI (default), 1=scheme+host+port+path, 2=scheme+host+port ***/

user_pref("network.http.referer.XOriginTrimmingPolicy", 2);



/*** [SECTION 1700]: CONTAINERS ***/

user_pref("_user.js.parrot", "1700 syntax error: the parrot's bit the dust!");


/* 1701: enable Container Tabs and its UI setting [FF50+]
 * [SETTING] General>Tabs>Enable Container Tabs*/

user_pref("privacy.userContext.enabled", true);
user_pref("privacy.userContext.ui.enabled", true);


/* 1702: set behavior on "+ Tab" button to display container menu on left click [FF74+]
 * [NOTE] The menu is always shown on long press and right click
 * [SETTING] General>Tabs>Enable Container Tabs>Settings>Select a container for each new tab ***/

   // user_pref("privacy.userContext.newTabContainerOnLeftClick.enabled", true);



/*** [SECTION 2000]: PLUGINS / MEDIA / WEBRTC ***/

user_pref("_user.js.parrot", "2000 syntax error: the parrot's snuffed it!");


/* 2001: disable WebRTC (Web Real-Time Communication)*/

    user_pref("media.peerconnection.enabled", false);


/* 2002: force WebRTC inside the proxy [FF70+] ***/

user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);


/* 2003: force a single network interface for ICE candidates generation [FF42+]*/

user_pref("media.peerconnection.ice.default_address_only", true);

/* 2004: force exclusion of private IPs from ICE candidates [FF51+]*/

   // user_pref("media.peerconnection.ice.no_host", true);


/* 2020: disable GMP (Gecko Media Plugins)

 * [1] https://wiki.mozilla.org/GeckoMediaPlugins ***/
 
   user_pref("media.gmp-provider.enabled", false);
   
   
/* 2021: disable widevine CDM (Content Decryption Module)
 * [NOTE] This is covered by the EME master switch (2022) ***/
 
   user_pref("media.gmp-widevinecdm.enabled", false);
   
   
/* 2022: disable all DRM content (EME: Encryption Media Extension)*/

user_pref("media.eme.enabled", false);
   // user_pref("browser.eme.ui.enabled", false);



/*** [SECTION 2400]: DOM (DOCUMENT OBJECT MODEL) ***/

user_pref("_user.js.parrot", "2400 syntax error: the parrot's kicked the bucket!");


/* 2402: prevent scripts from moving and resizing open windows ***/

user_pref("dom.disable_window_move_resize", true);


/*** [SECTION 2600]: MISCELLANEOUS ***/

user_pref("_user.js.parrot", "2600 syntax error: the parrot's run down the curtain!");


/* 2601: prevent accessibility services from accessing your browser [RESTART]**/

user_pref("accessibility.force_disabled", 1);


/* 2603: remove temp files opened with an external application*/

user_pref("browser.helperApps.deleteTempFileOnExit", true);


/* 2606: disable UITour backend so there is no chance that a remote page can use it ***/

user_pref("browser.uitour.enabled", false);
   // user_pref("browser.uitour.url", ""); // Defense-in-depth
   
   
/* 2608: reset remote debugging to disabled*/

user_pref("devtools.debugger.remote-enabled", false); // [DEFAULT: false]


/* 2611: disable middle mouse click opening links from clipboard**/

user_pref("middlemouse.contentLoadURL", true);


/* 2615: disable websites overriding Firefox's keyboard shortcuts [FF58+]
 * 0 (default) or 1=allow, 2=block**/
 
   // user_pref("permissions.default.shortcuts", 2);
   
   
/* 2616: remove special permissions for certain mozilla domains [FF35+]*/

user_pref("permissions.manager.defaultsUrl", "");


/* 2617: remove webchannel whitelist ***/

user_pref("webchannel.allowObject.urlWhitelist", "");


/* 2619: use Punycode in Internationalized Domain Names to eliminate possible spoofing*/

user_pref("network.IDN_show_punycode", true);


/* 2620: enforce PDFJS, disable PDFJS scripting*/

user_pref("pdfjs.disabled", false); // [DEFAULT: false]
user_pref("pdfjs.enableScripting", false); // [FF86+]


/* 2621: disable links launching Windows Store on Windows 8/8.1/10 [WINDOWS] ***/

user_pref("network.protocol-handler.external.ms-windows-store", false);


/* 2623: disable permissions delegation [FF73+]*/

user_pref("permissions.delegation.enabled", false);



/** DOWNLOADS ***/
/* 2651: enable user interaction for security by always asking where to download*/

user_pref("browser.download.useDownloadDir", false);


/* 2652: disable downloads panel opening on every download [FF96+] ***/

user_pref("browser.download.alwaysOpenPanel", false);


/* 2653: disable adding downloads to the system's "recent documents" list ***/

user_pref("browser.download.manager.addToRecentDocs", false);


/* 2654: enable user interaction for security by always asking how to handle new mimetypes [FF101+]
 * [SETTING] General>Files and Applications>What should Firefox do with other files ***/
 
user_pref("browser.download.always_ask_before_handling_new_types", true);



/** EXTENSIONS ***/
/* 2660: lock down allowed extension directories*/

user_pref("extensions.enabledScopes", 5); // [HIDDEN PREF]
user_pref("extensions.autoDisableScopes", 15); // [DEFAULT: 15]


/* 2661: disable bypassing 3rd party extension install prompts [FF82+]*/

user_pref("extensions.postDownloadThirdPartyPrompt", false);


/* 2662: disable webextension restrictions on certain mozilla domains (you also need 4503) [FF60+]*/

   // user_pref("extensions.webextensions.restrictedDomains", "");



/*** [SECTION 2700]: ETP (ENHANCED TRACKING PROTECTION) ***/

user_pref("_user.js.parrot", "2700 syntax error: the parrot's joined the bleedin' choir invisible!");


/* NOTE 2701: enable ETP Strict Mode [FF86+]
 * ETP Strict Mode enables Total Cookie Protection (TCP)
 * [NOTE] Adding site exceptions disables all ETP protections for that site and increases the risk of
 * cross-site state tracking e.g. exceptions for SiteA and SiteB means PartyC on both sites is shared*/
 
user_pref("browser.contentblocking.category", "strict");


/* 2702: disable ETP web compat features [FF93+]*/

   // user_pref("privacy.antitracking.enableWebcompat", false);
   
   
/* 2710: enable state partitioning of service workers [FF96+] ***/

user_pref("privacy.partition.serviceWorkers", true); // [DEFAULT: true FF105+]


/* 2720: enable APS (Always Partitioning Storage) ***/

user_pref("privacy.partition.always_partition_third_party_non_cookie_storage", true); // [FF104+] [DEFAULT: true FF109+]
user_pref("privacy.partition.always_partition_third_party_non_cookie_storage.exempt_sessionstorage", false); // [FF105+] [DEFAULT: false FF109+]



/*** [SECTION 2800]: SHUTDOWN & SANITIZING ***/

user_pref("_user.js.parrot", "2800 syntax error: the parrot's bleedin' demised!");


/* 2810: enable Firefox to clear items on shutdown*/

user_pref("privacy.sanitize.sanitizeOnShutdown", true);



/** SANITIZE ON SHUTDOWN: IGNORES "ALLOW" SITE EXCEPTIONS ***/

user_pref("privacy.clearOnShutdown.cache", true);     // [DEFAULT: true]
user_pref("privacy.clearOnShutdown.downloads", true); // [DEFAULT: true]
user_pref("privacy.clearOnShutdown.formdata", true);  // [DEFAULT: true]
user_pref("privacy.clearOnShutdown.history", true);   // [DEFAULT: true]
user_pref("privacy.clearOnShutdown.sessions", true);  // [DEFAULT: true]
   // user_pref("privacy.clearOnShutdown.siteSettings", false); // [DEFAULT: false]
   
   
/* 2812: set Session Restore to clear on shutdown (if 2810 is true) [FF34+]*/

   // user_pref("privacy.clearOnShutdown.openWindows", true);
   

/** SANITIZE ON SHUTDOWN: RESPECTS "ALLOW" SITE EXCEPTIONS FF103+ ***/

user_pref("privacy.clearOnShutdown.cookies", true); // Cookies
user_pref("privacy.clearOnShutdown.offlineApps", true); // Site Data


/* 2816: set cache to clear on exit [FF96+]
 * [NOTE] We already disable disk cache (1001) and clear on exit (2811) which is more robust*/
 
   user_pref("privacy.clearsitedata.cache.enabled", true);



/** SANITIZE MANUAL: IGNORES "ALLOW" SITE EXCEPTIONS ***/

user_pref("privacy.cpd.cache", true);    // [DEFAULT: true]
user_pref("privacy.cpd.formdata", true); // [DEFAULT: true]
user_pref("privacy.cpd.history", true);  // [DEFAULT: true]
user_pref("privacy.cpd.sessions", true); // [DEFAULT: true]
user_pref("privacy.cpd.offlineApps", false); // [DEFAULT: false]
user_pref("privacy.cpd.cookies", false);
   // user_pref("privacy.cpd.downloads", true); // not used, see note above
   // user_pref("privacy.cpd.openWindows", false); // Session Restore
   // user_pref("privacy.cpd.passwords", false);
   // user_pref("privacy.cpd.siteSettings", false);
   
   
/* 2822: reset default "Time range to clear" for "Clear Recent History" (2820)*/

user_pref("privacy.sanitize.timeSpan", 0);



/*** [SECTION 4500]: RFP (RESIST FINGERPRINTING)
   RFP covers a wide range of ongoing fingerprinting solutions.
   It is an all-or-nothing buy in: you cannot pick and choose what parts you want

   [WARNING] DO NOT USE extensions to alter RFP protected metrics

    418986 - limit window.screen & CSS media queries (FF41)
      [TEST] https://arkenfox.github.io/TZP/tzp.html#screen
   1281949 - spoof screen orientation (FF50)
   1330890 - spoof timezone as UTC0 (FF55)
   1360039 - spoof navigator.hardwareConcurrency as 2 (FF55)
 FF56
   1369303 - spoof/disable performance API
   1333651 - spoof User Agent & Navigator API
      version: android version spoofed as ESR
      OS: JS spoofed as Windows 10, OS 10.15, Android 10, or Linux | HTTP Headers spoofed as Windows or Android
   1369319 - disable device sensor API
   1369357 - disable site specific zoom
   1337161 - hide gamepads from content
   1372072 - spoof network information API as "unknown" when dom.netinfo.enabled = true
   1333641 - reduce fingerprinting in WebSpeech API
 FF57
   1369309 - spoof media statistics
   1382499 - reduce screen co-ordinate fingerprinting in Touch API
   1217290 & 1409677 - enable some fingerprinting resistance for WebGL
   1382545 - reduce fingerprinting in Animation API
   1354633 - limit MediaError.message to a whitelist
 FF58+
   1372073 - spoof/block fingerprinting in MediaDevices API (FF59)
      Spoof: enumerate devices as one "Internal Camera" and one "Internal Microphone"
      Block: suppresses the ondevicechange event
   1039069 - warn when language prefs are not set to "en*" (also see 0210, 0211) (FF59)
   1222285 & 1433592 - spoof keyboard events and suppress keyboard modifier events (FF59)
      Spoofing mimics the content language of the document. Currently it only supports en-US.
      Modifier events suppressed are SHIFT and both ALT keys. Chrome is not affected.
   1337157 - disable WebGL debug renderer info (FF60)
   1459089 - disable OS locale in HTTP Accept-Language headers (ANDROID) (FF62)
   1479239 - return "no-preference" with prefers-reduced-motion (FF63)
   1363508 - spoof/suppress Pointer Events (FF64)
   1492766 - spoof pointerEvent.pointerid (FF65)
   1485266 - disable exposure of system colors to CSS or canvas (FF67)
   1494034 - return "light" with prefers-color-scheme (FF67)
   1564422 - spoof audioContext outputLatency (FF70)
   1595823 - return audioContext sampleRate as 44100 (FF72)
   1607316 - spoof pointer as coarse and hover as none (ANDROID) (FF74)
   1621433 - randomize canvas (previously FF58+ returned an all-white canvas) (FF78)
   1653987 - limit font visibility to bundled and "Base Fonts" (Windows, Mac, some Linux) (FF80)
   1461454 - spoof smooth=true and powerEfficient=false for supported media in MediaCapabilities (FF82)
    531915 - use fdlibm's sin, cos and tan in jsmath (FF93, ESR91.1)
   1756280 - enforce navigator.pdfViewerEnabled as true and plugins/mimeTypes as hard-coded values (FF100)
   1692609 - reduce JS timing precision to 16.67ms (previously FF55+ was 100ms) (FF102)
   1422237 - return "srgb" with color-gamut (FF110)
***/

user_pref("_user.js.parrot", "4500 syntax error: the parrot's popped 'is clogs");


/* 4501: enable privacy.resistFingerprinting [FF41+]
 * [SETUP-WEB] RFP can cause some website breakage: mainly canvas, use a site exception via the urlbar*/
 
user_pref("privacy.resistFingerprinting", true);



/* NOTE 4502: set new window size rounding max values [FF55+]**/

user_pref("privacy.window.maxInnerWidth", 1600);
user_pref("privacy.window.maxInnerHeight", 900);


/* 4503: disable mozAddonManager Web API [FF57+]*/

user_pref("privacy.resistFingerprinting.block_mozAddonManager", true); // [HIDDEN PREF]


/* 4504: enable RFP letterboxing [FF67+]*/

user_pref("privacy.resistFingerprinting.letterboxing", true); // [HIDDEN PREF]
   // user_pref("privacy.resistFingerprinting.letterboxing.dimensions", ""); // [HIDDEN PREF]
   
   
/* 4505: experimental RFP [FF91+]
 * [WARNING] DO NOT USE unless testing, see [1] comment 12*/
 
   // user_pref("privacy.resistFingerprinting.exemptedDomains", "*.example.invalid");
   // user_pref("privacy.resistFingerprinting.testGranularityMask", 0);
   
   
/* 4506: set RFP's font visibility level (1402) [FF94+] ***/

   // user_pref("layout.css.font-visibility.resistFingerprinting", 1); // [DEFAULT: 1]
   
   
/* NOTE 4510: disable using system colors*/

user_pref("browser.display.use_system_colors", false); // [DEFAULT: false NON-WINDOWS]


/* 4511: enforce non-native widget theme
 * Security: removes/reduces system API calls, e.g. win32k API [1]
 * Fingerprinting: provides a uniform look and feel across platforms [2]**/
 
user_pref("widget.non-native-theme.enabled", true); // [DEFAULT: true]


/* 4512: enforce links targeting new windows to open in a new tab instead
 * 1=most recent window or tab, 2=new window, 3=new tab*/
 
user_pref("browser.link.open_newwindow", 3); // [DEFAULT: 3]


/* 4513: set all open window methods to abide by "browser.link.open_newwindow" (4512)*/

user_pref("browser.link.open_newwindow.restriction", 0);


/* 4520: disable WebGL (Web Graphics Library)*/

user_pref("webgl.disabled", true);



/*** [SECTION 5000]: OPTIONAL OPSEC
   Disk avoidance, application data isolation, eyeballs...
***/

user_pref("_user.js.parrot", "5000 syntax error: the parrot's taken 'is last bow");


/* 5001: start Firefox in PB (Private Browsing) mode
 * [NOTE] In this mode all windows are "private windows" and the PB mode icon is not displayed
 * [NOTE] The P in PB mode can be misleading: it means no "persistent" disk state such as history,
 * caches, searches, cookies, localStorage, IndexedDB etc (which you can achieve in normal mode).
 * In fact, PB mode limits or removes the ability to control some of these, and you need to quit
 * Firefox to clear them. PB is best used as a one off window (Menu>New Private Window) to provide
 * a temporary self-contained new session. Close all Private Windows to clear the PB mode session.*/
 
   user_pref("browser.privatebrowsing.autostart", true);
   
   
/* 5002: disable memory cache
 * capacity: -1=determine dynamically (default), 0=none, n=memory capacity in kibibytes ***/
 
   // user_pref("browser.cache.memory.enable", false);
   // user_pref("browser.cache.memory.capacity", 0);
   
   
/* 5003: disable saving passwords**/

   user_pref("signon.rememberSignons", false);
   
   
   
/* 5004: disable permissions manager from writing to disk [FF41+] [RESTART]
 * [NOTE] This means any permission changes are session only
 * [1] https://bugzilla.mozilla.org/967812 ***/
 
   // user_pref("permissions.memory_only", true); // [HIDDEN PREF]
   
   
/* 5005: disable intermediate certificate caching [FF41+] [RESTART]*/

   // user_pref("security.nocertdb", true);
   
   
/* 5006: disable favicons in history and bookmarks*/

   // user_pref("browser.chrome.site_icons", false);
   
   
/* 5007: exclude "Undo Closed Tabs" in Session Restore ***/

   user_pref("browser.sessionstore.max_tabs_undo", 0); // No tab restore
   
   
/* 5008: disable resuming session from crash
 * [TEST] about:crashparent ***/
 
   user_pref("browser.sessionstore.resume_from_crash", false);
   
   
/* 5009: disable "open with" in download dialog [FF50+]**/

   // user_pref("browser.download.forbid_open_with", true);
   
   
/* 5010: disable location bar suggestion types*/

   user_pref("browser.urlbar.suggest.history", false);
   user_pref("browser.urlbar.suggest.bookmark", false);
   user_pref("browser.urlbar.suggest.openpage", false);
   user_pref("browser.urlbar.suggest.topsites", false); // [FF78+]
   
   
/* NOTE 5011: disable location bar dropdown
 * This value controls the total number of entries to appear in the location bar dropdown ***/
 
 
   user_pref("browser.urlbar.maxRichResults", 0);
   
   
/* 5012: disable location bar autofill*/

   user_pref("browser.urlbar.autoFill", false);
   
   
/* NOTE 5013: disable browsing and download history**/

   // user_pref("places.history.enabled", false);
   
   
/* 5014: disable Windows jumplist [WINDOWS] ***/

   // user_pref("browser.taskbar.lists.enabled", false);
   // user_pref("browser.taskbar.lists.frequent.enabled", false);
   // user_pref("browser.taskbar.lists.recent.enabled", false);
   // user_pref("browser.taskbar.lists.tasks.enabled", false);
   
   
/* 5015: disable Windows taskbar preview [WINDOWS] ***/

   // user_pref("browser.taskbar.previews.enable", false); // [DEFAULT: false]
   
   
/* 5016: discourage downloading to desktop
 * 0=desktop, 1=downloads (default), 2=last used**/
 
   user_pref("browser.download.folderList", 2);
   
   
/* 5017: disable Form Autofill*/

   user_pref("extensions.formautofill.addresses.enabled", false); // [FF55+]
   user_pref("extensions.formautofill.creditCards.enabled", false); // [FF56+]
   user_pref("extensions.formautofill.heuristics.enabled", false); // [FF55+]
   
   
/* 5017: limit events that can cause a pop-up ***/

   // user_pref("dom.popup_allowed_events", "click dblclick mousedown pointerdown");
   
   
/* 5018: disable page thumbnail collection ***/

   // user_pref("browser.pagethumbnails.capturing_disabled", true); // [HIDDEN PREF]



/*** [SECTION 5500]: OPTIONAL HARDENING
   Not recommended. Overriding these can cause breakage and performance issues,
   they are mostly fingerprintable, and the threat model is practically nonexistent
***/

user_pref("_user.js.parrot", "5500 syntax error: this is an ex-parrot!");


/* 5501: disable MathML (Mathematical Markup Language) [FF51+]
 * [1] https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=mathml ***/
 
   // user_pref("mathml.disabled", true); // 1173199
   
   
/* 5502: disable in-content SVG (Scalable Vector Graphics) [FF53+]
 * [1] https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=firefox+svg ***/
 
   // user_pref("svg.disabled", true); // 1216893
   
   
/* 5503: disable graphite
 * [1] https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=firefox+graphite
 * [2] https://en.wikipedia.org/wiki/Graphite_(SIL) ***/
 
   // user_pref("gfx.font_rendering.graphite.enabled", false);
   
   
/* 5504: disable asm.js [FF22+]
 * [1] http://asmjs.org/
 * [2] https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=asm.js
 * [3] https://rh0dev.github.io/blog/2017/the-return-of-the-jit/ ***/
 
   // user_pref("javascript.options.asmjs", false);
   
   
/* 5505: disable Ion and baseline JIT to harden against JS exploits
 * [NOTE] When both Ion and JIT are disabled, and trustedprincipals
 * is enabled, then Ion can still be used by extensions (1599226)*/
 
   // user_pref("javascript.options.ion", false);
   // user_pref("javascript.options.baselinejit", false);
   // user_pref("javascript.options.jit_trustedprincipals", true); // [FF75+] [HIDDEN PREF]
   
   
/* 5506: disable WebAssembly [FF52+]
 * Vulnerabilities [1] have increasingly been found, including those known and fixed
 * in native programs years ago [2]. WASM has powerful low-level access, making
 * certain attacks (brute-force) and vulnerabilities more possible*/
 
   // user_pref("javascript.options.wasm", false);
   
   
/* 5507: disable rendering of SVG OpenType fonts ***/

   // user_pref("gfx.font_rendering.opentype_svg.enabled", false);


/*** [SECTION 6000]: DON'T TOUCH ***/

user_pref("_user.js.parrot", "6000 syntax error: the parrot's 'istory!");


/* 6001: enforce Firefox blocklist**/

user_pref("extensions.blocklist.enabled", true); // [DEFAULT: true]


/* 6002: enforce no referer spoofing
 * [WHY] Spoofing can affect CSRF (Cross-Site Request Forgery) protections ***/
 
user_pref("network.http.referer.spoofSource", false); // [DEFAULT: false]


/* 6004: enforce a security delay on some confirmation dialogs such as install, open/save
 * [1] https://www.squarefree.com/2004/07/01/race-conditions-in-security-dialogs/ ***/
 
user_pref("security.dialog_enable_delay", 1000); // [DEFAULT: 1000]


/* NOTENOW 6008: enforce no First Party Isolation [FF51+]
 * [WARNING] Replaced with network partitioning (FF85+) and TCP (2701),
 * and enabling FPI disables those. FPI is no longer maintained ***/
 
user_pref("privacy.firstparty.isolate", true); // [DEFAULT: false]


/* 6009: enforce SmartBlock shims [FF81+]
 * In FF96+ these are listed in about:compat
 * [1] https://blog.mozilla.org/security/2021/03/23/introducing-smartblock/ ***/
 
user_pref("extensions.webcompat.enable_shims", true); // [DEFAULT: true]


/* 6010: enforce no TLS 1.0/1.1 downgrades
 * [TEST] https://tls-v1-1.badssl.com:1010/ ***/
 
user_pref("security.tls.version.enable-deprecated", false); // [DEFAULT: false]


/* 6011: enforce disabling of Web Compatibility Reporter [FF56+]
 * Web Compatibility Reporter adds a "Report Site Issue" button to send data to Mozilla
 * [WHY] To prevent wasting Mozilla's time with a custom setup ***/
 
user_pref("extensions.webcompat-reporter.enabled", false); // [DEFAULT: false]



/* 6050: prefsCleaner: reset previously active items removed from arkenfox FF102+ ***/

   user_pref("beacon.enabled", false);
   // user_pref("browser.startup.blankWindow", "");
   // user_pref("browser.newtab.preload", "");
   // user_pref("browser.newtabpage.activity-stream.feeds.discoverystreamfeed", "");
   user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);
   user_pref("browser.region.network.url", "");
   // user_pref("browser.region.update.enabled", "");
   // user_pref("browser.ssl_override_behavior", "");
   // user_pref("devtools.chrome.enabled", "");
   // user_pref("dom.disable_beforeunload", "");
   // user_pref("dom.disable_open_during_load", "");
   user_pref("extensions.formautofill.available", "off"); // Disable autofill
   // user_pref("extensions.formautofill.addresses.supported", "");
   // user_pref("extensions.formautofill.creditCards.available", "");
   // user_pref("extensions.formautofill.creditCards.supported", "");








/*** [SECTION 7000]: DON'T BOTHER ***/

user_pref("_user.js.parrot", "7000 syntax error: the parrot's pushing up daisies!");


/* NOTE 7001: disable APIs
 * Location-Aware Browsing, Full Screen, offline cache (appCache)
 * [WHY] The API state is easily fingerprintable. Geo is behind a prompt (7002).
 * appCache storage capability was removed in FF90. Full screen requires user interaction ***/
 
   user_pref("geo.enabled", false);
   // user_pref("full-screen-api.enabled", false);
   user_pref("browser.cache.offline.enable", false);
   
   
/* 7002: set default permissions
 * Location, Camera, Microphone, Notifications [FF58+] Virtual Reality [FF73+]
 * 0=always ask (default), 1=allow, 2=block
 * [WHY] These are fingerprintable via Permissions API, except VR. Just add site
 * exceptions as allow/block for frequently visited/annoying sites: i.e. not global
 * [SETTING] to add site exceptions: Ctrl+I>Permissions>
 * [SETTING] to manage site exceptions: Options>Privacy & Security>Permissions>Settings ***/
 
   // user_pref("permissions.default.geo", 0);
   user_pref("permissions.default.camera", 2);
   user_pref("permissions.default.microphone", 0);
   user_pref("permissions.default.desktop-notification", 2);
   user_pref("permissions.default.xr", 2); // Virtual Reality
   
   
/* NOTE 7003: disable non-modern cipher suites [1]
 * [WHY] Passive fingerprinting. Minimal/non-existent threat of downgrade attacks
 * [1] https://browserleaks.com/ssl ***/
 
   // user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha", false); // [DEFAULT: false FF109+]
   // user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha", false); // [DEFAULT: false FF109+]
   // user_pref("security.ssl3.ecdhe_rsa_aes_128_sha", false);
   // user_pref("security.ssl3.ecdhe_rsa_aes_256_sha", false);
   // user_pref("security.ssl3.rsa_aes_128_gcm_sha256", false); // no PFS
   // user_pref("security.ssl3.rsa_aes_256_gcm_sha384", false); // no PFS
   // user_pref("security.ssl3.rsa_aes_128_sha", false); // no PFS
   // user_pref("security.ssl3.rsa_aes_256_sha", false); // no PFS
   
   
/* 7004: control TLS versions
 * [WHY] Passive fingerprinting and security ***/
 
   // user_pref("security.tls.version.min", 3); // [DEFAULT: 3]
   // user_pref("security.tls.version.max", 4);
   
   
/* 7005: disable SSL session IDs [FF36+]
 * [WHY] Passive fingerprinting and perf costs. These are session-only
 * and isolated with network partitioning (FF85+) and/or containers ***/
 
   // user_pref("security.ssl.disable_session_identifiers", true);
   
   
/* 7006: onions
 * [WHY] Firefox doesn't support hidden services. Use Tor Browser ***/
 
   // user_pref("dom.securecontext.allowlist_onions", true); // [FF97+] 1382359/1744006
   // user_pref("network.http.referer.hideOnionSource", true); // 1305144
   
   
/* 7007: referers
 * [WHY] Only cross-origin referers (1600s) need control ***/
 
   // user_pref("network.http.sendRefererHeader", 2);
   // user_pref("network.http.referer.trimmingPolicy", 0);
   
   
/* 7008: set the default Referrer Policy [FF59+]
 * 0=no-referer, 1=same-origin, 2=strict-origin-when-cross-origin, 3=no-referrer-when-downgrade
 * [WHY] Defaults are fine. They can be overridden by a site-controlled Referrer Policy ***/
 
   // user_pref("network.http.referer.defaultPolicy", 2); // [DEFAULT: 2]
   // user_pref("network.http.referer.defaultPolicy.pbmode", 2); // [DEFAULT: 2]
   
   
/* 7010: disable HTTP Alternative Services [FF37+]
 * [WHY] Already isolated with network partitioning (FF85+) ***/
 
   // user_pref("network.http.altsvc.enabled", false);
   
   
/* 7011: disable website control over browser right-click context menu
 * [WHY] Just use Shift-Right-Click ***/
 
   // user_pref("dom.event.contextmenu.enabled", false);
   
   
/* 7012: disable icon fonts (glyphs) and local fallback rendering
 * [WHY] Breakage, font fallback is equivalency, also RFP*/
 
   // user_pref("gfx.downloadable_fonts.enabled", false); // [FF41+]
   // user_pref("gfx.downloadable_fonts.fallback_delay", -1);
   
   
/* 7013: disable Clipboard API
 * [WHY] Fingerprintable. Breakage. Cut/copy/paste require user
 * interaction, and paste is limited to focused editable fields ***/
 
   // user_pref("dom.event.clipboardevents.enabled", false);
   
   
/* 7014: disable System Add-on updates
 * [WHY] It can compromise security. System addons ship with prefs, use those ***/
 
   // user_pref("extensions.systemAddon.update.enabled", false); // [FF62+]
   // user_pref("extensions.systemAddon.update.url", ""); // [FF44+]
   
   
/* 7015: enable the DNT (Do Not Track) HTTP header
 * [WHY] DNT is enforced with Tracking Protection which is used in ETP Strict (2701) ***/
 
   user_pref("privacy.donottrackheader.enabled", true);
   
   
/* NOTENOW 7016: customize ETP settings
 * [WHY] Arkenfox only supports strict (2701) which sets these at runtime ***/
 
   user_pref("network.cookie.cookieBehavior", 1); // [DEFAULT: 5 FF103+]
   // user_pref("network.http.referer.disallowCrossSiteRelaxingDefault", true);
   // user_pref("network.http.referer.disallowCrossSiteRelaxingDefault.top_navigation", true); // [FF100+]
   // user_pref("privacy.partition.network_state.ocsp_cache", true);
   // user_pref("privacy.query_stripping.enabled", true); // [FF101+] [ETP FF102+]
   // user_pref("privacy.trackingprotection.enabled", true);
   // user_pref("privacy.trackingprotection.socialtracking.enabled", true);
   // user_pref("privacy.trackingprotection.cryptomining.enabled", true); // [DEFAULT: true]
   // user_pref("privacy.trackingprotection.fingerprinting.enabled", true); // [DEFAULT: true]
   
   
/* 7017: disable service workers
 * [WHY] Already isolated with TCP (2701) behind a pref (2710) ***/
 
   // user_pref("dom.serviceWorkers.enabled", false);
   
   
/* 7018: disable Web Notifications
 * [WHY] Web Notifications are behind a prompt (7002)*/
 
   user_pref("dom.webnotifications.enabled", false); // [FF22+]
   // user_pref("dom.webnotifications.serviceworker.enabled", false); // [FF44+]
   
   
/* 7019: disable Push Notifications [FF44+]
 * [WHY] Push requires subscription
 * [NOTE] To remove all subscriptions, reset "dom.push.userAgentID"
 * [1] https://support.mozilla.org/kb/push-notifications-firefox ***/
 
   user_pref("dom.push.enabled", false);
   

/*** [SECTION 8000]: DON'T BOTHER: FINGERPRINTING
   [WHY] They are insufficient to help anti-fingerprinting and do more harm than good
   [WARNING] DO NOT USE with RFP. RFP already covers these and they can interfere
***/

user_pref("_user.js.parrot", "8000 syntax error: the parrot's crossed the Jordan");

/* 8001: prefsCleaner: reset items useless for anti-fingerprinting ***/

   // user_pref("browser.display.use_document_fonts", "");
   // user_pref("browser.zoom.siteSpecific", "");
   user_pref("device.sensors.enabled", false);
   // user_pref("dom.enable_performance", "");
   // user_pref("dom.enable_resource_timing", "");
   user_pref("dom.gamepad.enabled", false);
   // user_pref("dom.maxHardwareConcurrency", "");
   // user_pref("dom.w3c_touch_events.enabled", "");
   // user_pref("dom.webaudio.enabled", "");
   // user_pref("font.system.whitelist", "");
   // user_pref("general.appname.override", "");
   // user_pref("general.appversion.override", "");
   // user_pref("general.buildID.override", "");
   // user_pref("general.oscpu.override", "");
   // user_pref("general.platform.override", "");
   // user_pref("general.useragent.override", "");
   user_pref("media.navigator.enabled", false);
   // user_pref("media.ondevicechange.enabled", "");
   // user_pref("media.video_stats.enabled", "");
   user_pref("media.webspeech.synth.enabled", false);
   // user_pref("ui.use_standins_for_native_colors", "");
   // user_pref("webgl.enable-debug-renderer-info", "");


/*** [SECTION 9000]: NON-PROJECT RELATED ***/

user_pref("_user.js.parrot", "9000 syntax error: the parrot's cashed in 'is chips!");

/* 9001: disable welcome notices ***/

user_pref("browser.startup.homepage_override.mstone", "ignore");


/* 9002: disable General>Browsing>Recommend extensions/features as you browse [FF67+] ***/

user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);


/* 9003: disable What's New toolbar icon [FF69+] ***/

user_pref("browser.messaging-system.whatsNewPanel.enabled", false);


/* 9004: disable search terms [FF110+]
 * [SETTING] Search>Search Bar>Use the address bar for search and navigation>Show search terms instead of URL... ***/
 
user_pref("browser.urlbar.showSearchTerms.enabled", false);



/*** [SECTION 9999]: DEPRECATED / REMOVED / LEGACY / RENAMED
   Documentation denoted as [-]. Items deprecated prior to FF91 have been archived at [1]
   [1] https://github.com/arkenfox/user.js/issues/123
***/

user_pref("_user.js.parrot", "9999 syntax error: the parrot's shuffled off 'is mortal coil!");


/* ESR102.x still uses all the following prefs
// [NOTE] replace the * with a slash in the line above to re-enable them
// FF103
   // 2801: delete cookies and site data on exit - replaced by sanitizeOnShutdown* (2810)
   // 0=keep until they expire (default), 2=keep until you close Firefox
   // [SETTING] Privacy & Security>Cookies and Site Data>Delete cookies and site data when Firefox is closed
   // [-] https://bugzilla.mozilla.org/buglist.cgi?bug_id=1681493,1681495,1681498,1759665,1764761
user_pref("network.cookie.lifetimePolicy", 2);
// 6012: disable SHA-1 certificates
   // [-] https://bugzilla.mozilla.org/1766687
   // user_pref("security.pki.sha1_enforcement_level", 1); // [DEFAULT: 1]
// ***/



/* MISC */
user_pref("browser.bookmarks.max_backups", 0); // No bookmarks backup
user_pref("browser.newtabpage.activity-stream.discoverystream.enabled", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.highlights", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
user_pref("browser.newtabpage.activity-stream.showSearch", false);
user_pref("browser.topsites.contile.enabled", false);
user_pref("browser.search.update", false); // Disable search engine changes
user_pref("dom.battery.enabled", false); // Disable battery status
user_pref("identity.fxaccounts.enabled", false); // Disable Fx accounts
user_pref("extensions.pocket.enabled", false); // Disable pocket
user_pref("extensions.screenshots.disabled", true); // Disable screenshots
user_pref("media.gmp-gmpopenh264.enabled", false); // Disable OpenH264 for WebRTC
user_pref("browser.shell.checkDefaultBrowser", false); // Disable default check
user_pref("browser.uidensity", 1); // Compact density
user_pref("findbar.highlightAll", true); // Highlight text search
user_pref("general.smoothScroll", false); // Smooth scrolling off
user_pref("reader.parse-on-load.enabled", false); // Disable reader
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true); // Legacy CSS support
user_pref("ui.systemUsesDarkTheme", 1);
user_pref("ui.prefersReducedMotion", 1); // Disable animations




/* END: internal custom pref to test for syntax errors ***/
user_pref("_user.js.parrot", "SUCCESS: No no he's not dead, he's, he's restin'!");
