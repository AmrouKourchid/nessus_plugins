#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-57.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(209860);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_cve_id("CVE-2024-10458", "CVE-2024-10459", "CVE-2024-10463");
  script_xref(name:"IAVA", value:"2024-A-0695-S");

  script_name(english:"Mozilla Firefox ESR < 115.17");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 115.17. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2024-57 advisory.

  - A permission leak could have occurred from a trusted site to an untrusted site via <code>embed</code> or
    <code>object</code> elements. (CVE-2024-10458)

  - An attacker could have caused a use-after-free when accessibility was enabled, leading to a potentially
    exploitable crash. (CVE-2024-10459)

  - Video frames could have been leaked between origins in some situations. (CVE-2024-10463)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-57/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 115.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10463");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-10458");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'115.17', min:'115.0.0', severity:SECURITY_HOLE);
