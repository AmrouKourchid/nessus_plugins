#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2025-16.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(221616);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2024-43097",
    "CVE-2025-1930",
    "CVE-2025-1931",
    "CVE-2025-1932",
    "CVE-2025-1933",
    "CVE-2025-1934",
    "CVE-2025-1935",
    "CVE-2025-1936",
    "CVE-2025-1937",
    "CVE-2025-1938"
  );
  script_xref(name:"IAVA", value:"2025-A-0146-S");

  script_name(english:"Mozilla Firefox ESR < 128.8");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 128.8. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2025-16 advisory.

  - Memory safety bugs present in Firefox 135, Thunderbird 135, Firefox ESR 115.20, Firefox ESR 128.7, and
    Thunderbird 128.7. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. (CVE-2025-1937)

  - An inconsistent comparator in xslt/txNodeSorter could have resulted in potentially exploitable out-of-
    bounds access. Only affected version 122 and later. (CVE-2025-1932)

  - In resizeToAtLeast of SkRegion.cpp, there was a possible out of bounds write due to an integer overflow
    (CVE-2024-43097)

  - On Windows, a compromised content process could use bad StreamData sent over AudioIPC to trigger a use-
    after-free in the Browser process. This could have led to a sandbox escape. (CVE-2025-1930)

  - It was possible to cause a use-after-free in the content process side of a WebTransport connection,
    leading to a potentially exploitable crash. (CVE-2025-1931)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-16/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 128.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1937");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-1932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'128.8', min:'128.0.0', severity:SECURITY_WARNING);
