#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202401-10.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(187727);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/10");

  script_cve_id(
    "CVE-2023-3482",
    "CVE-2023-4058",
    "CVE-2023-4579",
    "CVE-2023-4863",
    "CVE-2023-5129",
    "CVE-2023-5170",
    "CVE-2023-5172",
    "CVE-2023-5173",
    "CVE-2023-5175",
    "CVE-2023-5722",
    "CVE-2023-5723",
    "CVE-2023-5729",
    "CVE-2023-5731",
    "CVE-2023-5758",
    "CVE-2023-6135",
    "CVE-2023-6210",
    "CVE-2023-6211",
    "CVE-2023-6213",
    "CVE-2023-6856",
    "CVE-2023-6857",
    "CVE-2023-6858",
    "CVE-2023-6859",
    "CVE-2023-6860",
    "CVE-2023-6861",
    "CVE-2023-6862",
    "CVE-2023-6863",
    "CVE-2023-6864",
    "CVE-2023-6865",
    "CVE-2023-6866",
    "CVE-2023-6867",
    "CVE-2023-6868",
    "CVE-2023-6869",
    "CVE-2023-6870",
    "CVE-2023-6871",
    "CVE-2023-6872",
    "CVE-2023-6873",
    "CVE-2023-32205",
    "CVE-2023-32206",
    "CVE-2023-32207",
    "CVE-2023-32208",
    "CVE-2023-32209",
    "CVE-2023-32210",
    "CVE-2023-32211",
    "CVE-2023-32212",
    "CVE-2023-32213",
    "CVE-2023-32214",
    "CVE-2023-32215",
    "CVE-2023-32216",
    "CVE-2023-34414",
    "CVE-2023-34415",
    "CVE-2023-34416",
    "CVE-2023-34417",
    "CVE-2023-37203",
    "CVE-2023-37204",
    "CVE-2023-37205",
    "CVE-2023-37206",
    "CVE-2023-37209",
    "CVE-2023-37210",
    "CVE-2023-37212"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/04");

  script_name(english:"GLSA-202401-10 : Mozilla Firefox: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202401-10 (Mozilla Firefox: Multiple Vulnerabilities)

  - When Firefox is configured to block storage of all cookies, it was still possible to store data in
    localstorage by using an iframe with a source of 'about:blank'. This could have led to malicious websites
    storing tracking data without permission. This vulnerability affects Firefox < 115. (CVE-2023-3482)

  - Memory safety bugs present in Firefox 115. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 116. (CVE-2023-4058)

  - Search queries in the default search engine could appear to have been the currently navigated URL if the
    search query itself was a well formed URL. This could have led to a site spoofing another if it had been
    maliciously set as the default search engine. This vulnerability affects Firefox < 117. (CVE-2023-4579)

  - Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a
    remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security
    severity: Critical) (CVE-2023-4863)

  - Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority. Duplicate of
    CVE-2023-4863. (CVE-2023-5129)

  - In canvas rendering, a compromised content process could have caused a surface to change unexpectedly,
    leading to a memory leak of a privileged process. This memory leak could be used to effect a sandbox
    escape if the correct data was leaked. This vulnerability affects Firefox < 118. (CVE-2023-5170)

  - A hashtable in the Ion Engine could have been mutated while there was a live interior reference, leading
    to a potential use-after-free and exploitable crash. This vulnerability affects Firefox < 118.
    (CVE-2023-5172)

  - In a non-standard configuration of Firefox, an integer overflow could have occurred based on network
    traffic (possibly under influence of a local unprivileged webpage), leading to an out-of-bounds write to
    privileged process memory. *This bug only affects Firefox if a non-standard preference allowing non-HTTPS
    Alternate Services (`network.http.altsvc.oe`) is enabled.* This vulnerability affects Firefox < 118.
    (CVE-2023-5173)

  - During process shutdown, it was possible that an `ImageBitmap` was created that would later be used after
    being freed from a different codepath, leading to a potentially exploitable crash. This vulnerability
    affects Firefox < 118. (CVE-2023-5175)

  - Using iterative requests an attacker was able to learn the size of an opaque response, as well as the
    contents of a server-supplied Vary header. This vulnerability affects Firefox < 119. (CVE-2023-5722)

  - An attacker with temporary script access to a site could have set a cookie containing invalid characters
    using `document.cookie` that could have led to unknown errors. This vulnerability affects Firefox < 119.
    (CVE-2023-5723)

  - A malicious web site can enter fullscreen mode while simultaneously triggering a WebAuthn prompt. This
    could have obscured the fullscreen notification and could have been leveraged in a spoofing attack. This
    vulnerability affects Firefox < 119. (CVE-2023-5729)

  - Memory safety bugs present in Firefox 118. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 119. (CVE-2023-5731)

  - When opening a page in reader mode, the redirect URL could have caused attacker-controlled script to
    execute in a reflected Cross-Site Scripting (XSS) attack. This vulnerability affects Firefox for iOS <
    119. (CVE-2023-5758)

  - Multiple NSS NIST curves were susceptible to a side-channel attack known as Minerva. This attack could
    potentially allow an attacker to recover the private key. This vulnerability affects Firefox < 121.
    (CVE-2023-6135)

  - When an https: web page created a pop-up from a javascript: URL, that pop-up was incorrectly allowed to
    load blockable content such as iframes from insecure http: URLs This vulnerability affects Firefox < 120.
    (CVE-2023-6210)

  - If an attacker needed a user to load an insecure http: page and knew that user had enabled HTTPS-only
    mode, the attacker could have tricked the user into clicking to grant an HTTPS-only exception if they
    could get the user to participate in a clicking game. This vulnerability affects Firefox < 120.
    (CVE-2023-6211)

  - Memory safety bugs present in Firefox 119. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 120. (CVE-2023-6213)

  - The WebGL `DrawElementsInstanced` method was susceptible to a heap buffer overflow when used on systems
    with the Mesa VM driver. This issue could allow an attacker to perform remote code execution and sandbox
    escape. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121.
    (CVE-2023-6856)

  - When resolving a symlink, a race may occur where the buffer passed to `readlink` may actually be smaller
    than necessary. *This bug only affects Firefox on Unix-based operating systems (Android, Linux, MacOS).
    Windows is unaffected.* This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox <
    121. (CVE-2023-6857)

  - Firefox was susceptible to a heap buffer overflow in `nsTextFragment` due to insufficient OOM handling.
    This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121. (CVE-2023-6858)

  - A use-after-free condition affected TLS socket creation when under memory pressure. This vulnerability
    affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121. (CVE-2023-6859)

  - The `VideoBridge` allowed any content process to use textures produced by remote decoders. This could be
    abused to escape the sandbox. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and
    Firefox < 121. (CVE-2023-6860)

  - The `nsWindow::PickerOpen(void)` method was susceptible to a heap buffer overflow when running in headless
    mode. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121.
    (CVE-2023-6861)

  - A use-after-free was identified in the `nsDNSService::Init`. This issue appears to manifest rarely during
    start-up. This vulnerability affects Firefox ESR < 115.6 and Thunderbird < 115.6. (CVE-2023-6862)

  - The `ShutdownObserver()` was susceptible to potentially undefined behavior due to its reliance on a
    dynamic type that lacked a virtual destructor. This vulnerability affects Firefox ESR < 115.6, Thunderbird
    < 115.6, and Firefox < 121. (CVE-2023-6863)

  - Memory safety bugs present in Firefox 120, Firefox ESR 115.5, and Thunderbird 115.5. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and
    Firefox < 121. (CVE-2023-6864)

  - `EncryptingOutputStream` was susceptible to exposing uninitialized data. This issue could only be abused
    in order to write data to a local disk which may have implications for private browsing mode. This
    vulnerability affects Firefox ESR < 115.6 and Firefox < 121. (CVE-2023-6865)

  - TypedArrays can be fallible and lacked proper exception handling. This could lead to abuse in other APIs
    which expect TypedArrays to always succeed. This vulnerability affects Firefox < 121. (CVE-2023-6866)

  - The timing of a button click causing a popup to disappear was approximately the same length as the anti-
    clickjacking delay on permission prompts. It was possible to use this fact to surprise users by luring
    them to click where the permission grant button would be about to appear. This vulnerability affects
    Firefox ESR < 115.6 and Firefox < 121. (CVE-2023-6867)

  - In some instances, the user-agent would allow push requests which lacked a valid VAPID even though the
    push manager subscription defined one. This could allow empty messages to be sent from unauthorized
    parties. *This bug only affects Firefox on Android.* This vulnerability affects Firefox < 121.
    (CVE-2023-6868)

  - A `<dialog>` element could have been manipulated to paint content outside of a sandboxed iframe. This
    could allow untrusted content to display under the guise of trusted content. This vulnerability affects
    Firefox < 121. (CVE-2023-6869)

  - Applications which spawn a Toast notification in a background thread may have obscured fullscreen
    notifications displayed by Firefox. *This issue only affects Android versions of Firefox and Firefox
    Focus.* This vulnerability affects Firefox < 121. (CVE-2023-6870)

  - Under certain conditions, Firefox did not display a warning when a user attempted to navigate to a new
    protocol handler. This vulnerability affects Firefox < 121. (CVE-2023-6871)

  - Browser tab titles were being leaked by GNOME to system logs. This could potentially expose the browsing
    habits of users running in a private tab. This vulnerability affects Firefox < 121. (CVE-2023-6872)

  - Memory safety bugs present in Firefox 120. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 121. (CVE-2023-6873)

  - In multiple cases browser prompts could have been obscured by popups controlled by content. These could
    have led to potential user confusion and spoofing attacks. This vulnerability affects Firefox < 113,
    Firefox ESR < 102.11, and Thunderbird < 102.11. (CVE-2023-32205)

  - An out-of-bound read could have led to a crash in the RLBox Expat driver. This vulnerability affects
    Firefox < 113, Firefox ESR < 102.11, and Thunderbird < 102.11. (CVE-2023-32206)

  - A missing delay in popup notifications could have made it possible for an attacker to trick a user into
    granting permissions. This vulnerability affects Firefox < 113, Firefox ESR < 102.11, and Thunderbird <
    102.11. (CVE-2023-32207)

  - Service workers could reveal script base URL due to dynamic `import()`. This vulnerability affects Firefox
    < 113. (CVE-2023-32208)

  - A maliciously crafted favicon could have led to an out of memory crash. This vulnerability affects Firefox
    < 113. (CVE-2023-32209)

  - Documents were incorrectly assuming an ordering of principal objects when ensuring we were loading an
    appropriately privileged principal. In certain circumstances it might have been possible to cause a
    document to be loaded with a higher privileged principal than intended. This vulnerability affects Firefox
    < 113. (CVE-2023-32210)

  - A type checking bug would have led to invalid code being compiled. This vulnerability affects Firefox <
    113, Firefox ESR < 102.11, and Thunderbird < 102.11. (CVE-2023-32211)

  - An attacker could have positioned a <code>datalist</code> element to obscure the address bar. This
    vulnerability affects Firefox < 113, Firefox ESR < 102.11, and Thunderbird < 102.11. (CVE-2023-32212)

  - When reading a file, an uninitialized value could have been used as read limit. This vulnerability affects
    Firefox < 113, Firefox ESR < 102.11, and Thunderbird < 102.11. (CVE-2023-32213)

  - Protocol handlers `ms-cxh` and `ms-cxh-full` could have been leveraged to trigger a denial of service.
    *Note: This attack only affects Windows. Other operating systems are not affected.* This vulnerability
    affects Firefox < 113, Firefox ESR < 102.11, and Thunderbird < 102.11. (CVE-2023-32214)

  - Memory safety bugs present in Firefox 112 and Firefox ESR 102.10. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. This vulnerability affects Firefox < 113, Firefox ESR < 102.11, and Thunderbird < 102.11.
    (CVE-2023-32215)

  - Memory safety bugs present in Firefox 112. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 113. (CVE-2023-32216)

  - The error page for sites with invalid TLS certificates was missing the activation-delay Firefox uses to
    protect prompts and permission dialogs from attacks that exploit human response time delays. If a
    malicious page elicited user clicks in precise locations immediately before navigating to a site with a
    certificate error and made the renderer extremely busy at the same time, it could create a gap between
    when the error page was loaded and when the display actually refreshed. With the right timing the elicited
    clicks could land in that gap and activate the button that overrides the certificate error for that site.
    This vulnerability affects Firefox ESR < 102.12, Firefox < 114, and Thunderbird < 102.12. (CVE-2023-34414)

  - When choosing a site-isolated process for a document loaded from a data: URL that was the result of a
    redirect, Firefox would load that document in the same process as the site that issued the redirect. This
    bypassed the site-isolation protections against Spectre-like attacks on sites that host an open
    redirect. Firefox no longer follows HTTP redirects to data: URLs. This vulnerability affects Firefox <
    114. (CVE-2023-34415)

  - Memory safety bugs present in Firefox 113, Firefox ESR 102.11, and Thunderbird 102.12. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox ESR < 102.12, Firefox < 114, and
    Thunderbird < 102.12. (CVE-2023-34416)

  - Memory safety bugs present in Firefox 113. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 114. (CVE-2023-34417)

  - Insufficient validation in the Drag and Drop API in conjunction with social engineering, may have allowed
    an attacker to trick end-users into creating a shortcut to local system files. This could have been
    leveraged to execute arbitrary code. This vulnerability affects Firefox < 115. (CVE-2023-37203)

  - A website could have obscured the fullscreen notification by using an option element by introducing lag
    via an expensive computational function. This could have led to user confusion and possible spoofing
    attacks. This vulnerability affects Firefox < 115. (CVE-2023-37204)

  - The use of RTL Arabic characters in the address bar may have allowed for URL spoofing. This vulnerability
    affects Firefox < 115. (CVE-2023-37205)

  - Uploading files which contain symlinks may have allowed an attacker to trick a user into submitting
    sensitive data to a malicious website. This vulnerability affects Firefox < 115. (CVE-2023-37206)

  - A use-after-free condition existed in `NotifyOnHistoryReload` where a `LoadingSessionHistoryEntry` object
    was freed and a reference to that object remained. This resulted in a potentially exploitable condition
    when the reference to that object was later reused. This vulnerability affects Firefox < 115.
    (CVE-2023-37209)

  - A website could prevent a user from exiting full-screen mode via alert and prompt calls. This could lead
    to user confusion and possible spoofing attacks. This vulnerability affects Firefox < 115.
    (CVE-2023-37210)

  - Memory safety bugs present in Firefox 114. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 115. (CVE-2023-37212)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202401-10");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=908245");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=914073");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=918433");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=920507");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Firefox ESR binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-115.6.0:esr
        
All Mozilla Firefox ESR users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-115.6.0:esr
        
All Mozilla Firefox binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-121.0:rapid
        
All Mozilla Firefox users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-121.0:rapid");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6873");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-5731");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 115.6.0", "lt 115.0.0"),
    'vulnerable' : make_list("lt 115.6.0")
  },
  {
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 121.0", "lt 116.0.0"),
    'vulnerable' : make_list("lt 121.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 115.6.0", "lt 115.0.0"),
    'vulnerable' : make_list("lt 115.6.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 121.0", "lt 116.0.0"),
    'vulnerable' : make_list("lt 121.0")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Mozilla Firefox');
}
