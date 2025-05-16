#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-26.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(200317);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id(
    "CVE-2024-5688",
    "CVE-2024-5690",
    "CVE-2024-5691",
    "CVE-2024-5692",
    "CVE-2024-5693",
    "CVE-2024-5696",
    "CVE-2024-5700",
    "CVE-2024-5702"
  );
  script_xref(name:"IAVA", value:"2024-A-0335-S");
  script_xref(name:"IAVA", value:"2024-A-0361-S");

  script_name(english:"Mozilla Firefox ESR < 115.12");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 115.12. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2024-26 advisory.

  - Memory corruption in the networking stack could have led to a potentially exploitable crash.
    (CVE-2024-5702)

  - If a garbage collection was triggered at the right time, a use-after-free could have occurred during
    object transplant. (CVE-2024-5688)

  - By monitoring the time certain operations take, an attacker could have guessed which external protocol
    handlers were functional on a user's system. (CVE-2024-5690)

  - By tricking the browser with a <code>X-Frame-Options</code> header, a sandboxed iframe could have
    presented a button that, if clicked by a user, would bypass restrictions to open a new window.
    (CVE-2024-5691)

  - On Windows 10, when using the 'Save As' functionality, an attacker could have tricked the browser into
    saving the file with a disallowed extension such as <code>.url</code> by including an invalid character in
    the extension. Note: This issue only affected Windows operating systems. Other operating systems are
    unaffected. (CVE-2024-5692)

  - Offscreen Canvas did not properly track cross-origin tainting, which could be used to access image data
    from another site in violation of same-origin policy. (CVE-2024-5693)

  - By manipulating the text in an <code><input></code> tag, an attacker could have caused corrupt
    memory leading to a potentially exploitable crash. (CVE-2024-5696)

  - Memory safety bugs present in Firefox 126, Firefox ESR 115.11, and Thunderbird 115.11. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2024-5700)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-26/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 115.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5700");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-5691");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (isnull(is_esr)) audit(AUDIT_NOT_INST, 'Mozilla Firefox ESR');

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'115.12', min:'115.0.0', severity:SECURITY_HOLE);
