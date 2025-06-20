#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2025-23.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(233648);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2025-3028",
    "CVE-2025-3029",
    "CVE-2025-3030",
    "CVE-2025-3031",
    "CVE-2025-3032",
    "CVE-2025-3033",
    "CVE-2025-3034"
  );
  script_xref(name:"IAVA", value:"2025-A-0213-S");

  script_name(english:"Mozilla Thunderbird < 137.0");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 137.0. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2025-23 advisory.

  - Memory safety bugs present in Firefox 136 and Thunderbird 136. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. (CVE-2025-3034)

  - JavaScript code running while transforming a document with the XSLTProcessor could lead to a use-after-
    free. (CVE-2025-3028)

  - An attacker could read 32 bits of values spilled onto the stack in a JIT compiled function.
    (CVE-2025-3031)

  - Leaking of file descriptors from the fork server to web content processes could allow for privilege
    escalation attacks. (CVE-2025-3032)

  - A crafted URL containing specific Unicode characters could have hidden the true origin of the page,
    resulting in a potential spoofing attack. (CVE-2025-3029)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-23/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 137.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-3034");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'137.0', severity:SECURITY_HOLE);
