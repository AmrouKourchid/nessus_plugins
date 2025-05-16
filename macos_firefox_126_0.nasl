#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-21.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(196991);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id(
    "CVE-2024-4367",
    "CVE-2024-4764",
    "CVE-2024-4765",
    "CVE-2024-4766",
    "CVE-2024-4767",
    "CVE-2024-4768",
    "CVE-2024-4769",
    "CVE-2024-4770",
    "CVE-2024-4771",
    "CVE-2024-4772",
    "CVE-2024-4773",
    "CVE-2024-4774",
    "CVE-2024-4775",
    "CVE-2024-4776",
    "CVE-2024-4777",
    "CVE-2024-4778"
  );
  script_xref(name:"IAVA", value:"2024-A-0279-S");
  script_xref(name:"IAVA", value:"2025-A-0079-S");

  script_name(english:"Mozilla Firefox < 126.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 126.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2024-21 advisory.

  - Multiple WebRTC threads could have claimed a newly connected audio input leading to use-after-free.
    (CVE-2024-4764)

  - A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution
    in the PDF.js context. (CVE-2024-4367)

  - Web application manifests were stored by using an insecure MD5 hash which allowed for a hash collision to
    overwrite another application's manifest. This could have been exploited to run arbitrary code in another
    application's context.  This issue only affects Firefox for Android. Other versions of Firefox are
    unaffected. (CVE-2024-4765)

  - Different techniques existed to obscure the fullscreen notification in Firefox for Android.  These could
    have lead to potential user confusion and spoofing attacks. This bug only affects Firefox for Android.
    Other versions of Firefox are unaffected. (CVE-2024-4766)

  - If the <code>browser.privatebrowsing.autostart</code> preference is enabled, IndexedDB files were not
    properly deleted when the window was closed. This preference is disabled by default in Firefox.
    (CVE-2024-4767)

  - A bug in popup notifications' interaction with WebAuthn made it easier for an attacker to trick a user
    into granting permissions. (CVE-2024-4768)

  - When importing resources using Web Workers, error messages would distinguish the difference between
    <code>application/javascript</code> responses and non-script responses.  This could have been abused to
    learn information cross-origin. (CVE-2024-4769)

  - When saving a page to PDF, certain font styles could have led to a potential use-after-free crash.
    (CVE-2024-4770)

  - A memory allocation check was missing which would lead to a use-after-free if the allocation failed. This
    could have triggered a crash or potentially be leveraged to achieve code execution. (CVE-2024-4771)

  - An HTTP digest authentication nonce value was generated using <code>rand()</code> which could lead to
    predictable values. (CVE-2024-4772)

  - When a network error occurred during page load, the prior content could have remained in view with a blank
    URL bar. This could have been used to obfuscate a spoofed web site. (CVE-2024-4773)

  - The <code>ShmemCharMapHashEntry()</code> code was susceptible to potentially undefined behavior by
    bypassing the move semantics for one of its data members. (CVE-2024-4774)

  - An iterator stop condition was missing when handling WASM code in the built-in profiler, potentially
    leading to invalid memory access and undefined behavior. Note: This issue only affects the application
    when the profiler is running. (CVE-2024-4775)

  - A file dialog shown while in full-screen mode could have resulted in the window remaining disabled.
    (CVE-2024-4776)

  - Memory safety bugs present in Firefox 125, Firefox ESR 115.10, and Thunderbird 115.10. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2024-4777)

  - Memory safety bugs present in Firefox 125. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2024-4778)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-21/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 126.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4777");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'126.0', severity:SECURITY_HOLE);
