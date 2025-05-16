#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-67.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(211869);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/02");

  script_cve_id(
    "CVE-2024-11691",
    "CVE-2024-11692",
    "CVE-2024-11693",
    "CVE-2024-11694",
    "CVE-2024-11695",
    "CVE-2024-11696",
    "CVE-2024-11697",
    "CVE-2024-11698",
    "CVE-2024-11699",
    "CVE-2024-11700",
    "CVE-2024-11701",
    "CVE-2024-11702",
    "CVE-2024-11704",
    "CVE-2024-11705",
    "CVE-2024-11706",
    "CVE-2024-11708"
  );

  script_name(english:"Mozilla Thunderbird < 133.0");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 133.0. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2024-67 advisory.

  - Certain WebGL operations on Apple silicon M series devices could have lead to an out-of-bounds write and
    memory corruption due to a flaw in Apple's GPU driver.   This bug only affected the application on Apple M
    series hardware. Other platforms were unaffected. (CVE-2024-11691)

  - Malicious websites may have been able to perform user intent confirmation through tapjacking. This could
    have led to users unknowingly approving the launch of external applications, potentially exposing them to
    underlying vulnerabilities. (CVE-2024-11700)

  - An attacker could cause a select dropdown to be shown over another tab; this could have led to user
    confusion and possible spoofing attacks. (CVE-2024-11692)

  - The incorrect domain may have been displayed in the address bar during an interrupted navigation attempt.
    This could have led to user confusion and possible spoofing attacks. (CVE-2024-11701)

  - Copying sensitive information from Private Browsing tabs on Android, such as passwords, may have
    inadvertently stored data in the cloud-based clipboard history if enabled. (CVE-2024-11702)

  - The executable file warning was not presented when downloading .library-ms files.   Note: This issue only
    affected Windows operating systems. Other operating systems are unaffected. (CVE-2024-11693)

  - Enhanced Tracking Protection's Strict mode may have inadvertently allowed a CSP `frame-src` bypass and
    DOM-based XSS through the Google SafeFrame shim in the Web Compatibility extension. This issue could have
    exposed users to malicious frames masquerading as legitimate content. (CVE-2024-11694)

  - A crafted URL containing Arabic script and whitespace characters could have hidden the true origin of the
    page, resulting in a potential spoofing attack. (CVE-2024-11695)

  - The application failed to account for exceptions thrown by the `loadManifestFromFile` method during add-on
    signature verification. This flaw, triggered by an invalid or unsupported extension manifest, could have
    caused runtime errors that disrupted the signature validation process. As a result, the enforcement of
    signature validation for unrelated add-ons may have been bypassed.  Signature validation in this context
    is used to ensure that third-party applications on the user's computer have not tampered with the user's
    extensions, limiting the impact of this issue. (CVE-2024-11696)

  - When handling keypress events, an attacker may have been able to trick a user into bypassing the Open
    Executable File? confirmation dialog. This could have led to malicious code execution. (CVE-2024-11697)

  - A double-free issue could have occurred in `secpkcs7decoderstartdecrypt()` when handling an error path.
    Under specific conditions, the same symmetric key could have been freed twice, potentially leading to
    memory corruption. (CVE-2024-11704)

  - A flaw in handling fullscreen transitions may have inadvertently caused the application to become stuck in
    fullscreen mode when a modal dialog was opened during the transition. This issue left users unable to exit
    fullscreen mode using standard actions like pressing Esc or accessing right-click menus, resulting in a
    disrupted browsing experience until the browser is restarted.   This bug only affects the application when
    running on macOS. Other operating systems are unaffected. (CVE-2024-11698)

  - <code>NSCDeriveKey</code> inadvertently assumed that the <code>phKey</code> parameter is always non-NULL.
    When it was passed as NULL, a segmentation fault (SEGV) occurred, leading to crashes. This behavior
    conflicted with the PKCS#11 v3.0 specification, which allows <code>phKey</code> to be NULL for certain
    mechanisms. (CVE-2024-11705)

  - A null pointer dereference may have inadvertently occurred in `pk12util`, and specifically in the
    <code>SECASN1DecodeItemUtil</code> function, when handling malformed or improperly formatted input files.
    (CVE-2024-11706)

  - Missing thread synchronization primitives could have led to a data race on members of the PlaybackParams
    structure. (CVE-2024-11708)

  - Memory safety bugs present in Firefox 132, Thunderbird 132, Firefox ESR 128.4, and Thunderbird 128.4. Some
    of these bugs showed evidence of memory corruption and we presume that with enough effort some of these
    could have been exploited to run arbitrary code. (CVE-2024-11699)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-67/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 133.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11694");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-11704");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Thunderbird';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Thunderbird installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'133.0', severity:SECURITY_HOLE);
