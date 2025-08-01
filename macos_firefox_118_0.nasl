#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-41.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(181876);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2023-5168",
    "CVE-2023-5169",
    "CVE-2023-5170",
    "CVE-2023-5171",
    "CVE-2023-5172",
    "CVE-2023-5173",
    "CVE-2023-5174",
    "CVE-2023-5175",
    "CVE-2023-5176"
  );
  script_xref(name:"IAVA", value:"2023-A-0507-S");

  script_name(english:"Mozilla Firefox < 118.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 118.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2023-41 advisory.

  - A compromised content process could have provided malicious data to <code>FilterNodeD2D1</code> resulting
    in an out-of-bounds write, leading to a potentially exploitable crash in a privileged process.
    (CVE-2023-5168)

  - A compromised content process could have provided malicious data in a <code>PathRecording</code> resulting
    in an out-of-bounds write, leading to a potentially exploitable crash in a privileged process.
    (CVE-2023-5169)

  - In canvas rendering, a compromised content process could have caused a surface to change unexpectedly,
    leading to a memory leak of a privileged process. This memory leak could be used to effect a sandbox
    escape if the correct data was leaked. (CVE-2023-5170)

  - During Ion compilation, a Garbage Collection could have resulted in a use-after-free condition, allowing
    an attacker to write two NUL bytes, and cause a potentially exploitable crash. (CVE-2023-5171)

  - A hashtable  in the Ion Engine could have been mutated while there was a live interior reference, leading
    to a potential use-after-free and exploitable crash. (CVE-2023-5172)

  - In a non-standard configuration of Firefox, an integer overflow could have occurred based on network
    traffic (possibly under influence of a local unprivileged webpage), leading to an out-of-bounds write to
    privileged process memory.  This bug only affects Firefox if a non-standard preference allowing non-HTTPS
    Alternate Services (<code>network.http.altsvc.oe</code>) is enabled. (CVE-2023-5173)

  - If Windows failed to duplicate a handle during process creation, the sandbox code may have inadvertently
    freed a pointer twice, resulting in a use-after-free and a potentially exploitable crash. This bug only
    affects Firefox on Windows when run in non-standard configurations (such as using <code>runas</code>).
    Other operating systems are unaffected. (CVE-2023-5174)

  - During process shutdown, it was possible that an <code>ImageBitmap</code> was created that would later be
    used after being freed from a different codepath, leading to a potentially exploitable crash.
    (CVE-2023-5175)

  - Memory safety bugs present in Firefox 117, Firefox ESR 115.2, and Thunderbird 115.2. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2023-5176)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-41/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 118.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5176");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'118.0', severity:SECURITY_HOLE);
