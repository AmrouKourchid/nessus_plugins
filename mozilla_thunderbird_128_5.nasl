#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-68.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(211871);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/28");

  script_cve_id(
    "CVE-2024-11691",
    "CVE-2024-11692",
    "CVE-2024-11693",
    "CVE-2024-11694",
    "CVE-2024-11695",
    "CVE-2024-11696",
    "CVE-2024-11697",
    "CVE-2024-11698",
    "CVE-2024-11699"
  );

  script_name(english:"Mozilla Thunderbird < 128.5");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 128.5. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2024-68 advisory.

  - Certain WebGL operations on Apple silicon M series devices could have lead to an out-of-bounds write and
    memory corruption due to a flaw in Apple's GPU driver.   This bug only affected the application on Apple M
    series hardware. Other platforms were unaffected. (CVE-2024-11691)

  - An attacker could cause a select dropdown to be shown over another tab; this could have led to user
    confusion and possible spoofing attacks. (CVE-2024-11692)

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

  - A flaw in handling fullscreen transitions may have inadvertently caused the application to become stuck in
    fullscreen mode when a modal dialog was opened during the transition. This issue left users unable to exit
    fullscreen mode using standard actions like pressing Esc or accessing right-click menus, resulting in a
    disrupted browsing experience until the browser is restarted.   This bug only affects the application when
    running on macOS. Other operating systems are unaffected. (CVE-2024-11698)

  - Memory safety bugs present in Firefox 132, Thunderbird 132, Firefox ESR 128.4, and Thunderbird 128.4. Some
    of these bugs showed evidence of memory corruption and we presume that with enough effort some of these
    could have been exploited to run arbitrary code. (CVE-2024-11699)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-68/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 128.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11694");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-11698");

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
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'128.5', severity:SECURITY_WARNING);
