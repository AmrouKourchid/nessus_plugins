#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181413);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2023-30547");

  script_name(english:"Node.js Module vm2 < 3.9.17 Sandbox Breakout");

  script_set_attribute(attribute:"synopsis", value:
"A module in the Node.js JavaScript run-time environment is affected by a sandbox breakout vulnerability.");
  script_set_attribute(attribute:"description", value:
"There exists a vulnerability in exception sanitization of vm2 for versions up to 3.9.16, allowing attackers to raise 
an unsanitized host exception inside `handleException()` which can be used to escape the sandbox and run arbitrary code 
in host context. This vulnerability was patched in the release of version `3.9.17` of `vm2`. There are no known 
workarounds for this vulnerability. Users are advised to upgrade.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/patriksimek/vm2/security/advisories/GHSA-ch3r-j5x3-6q2m
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?686ece7c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vm2 version 3.9.17 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30547");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vm2_project:vm2");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_modules_win_installed.nbin", "nodejs_modules_linux_installed.nbin", "nodejs_modules_mac_installed.nbin");
  script_require_keys("Host/nodejs/modules/enumerated");

  exit(0);
}

include('vcf_extras_nodejs.inc');

get_kb_item_or_exit('Host/nodejs/modules/enumerated');
var app_info = vcf_extras::nodejs_modules::get_app_info(app:'vm2');

var constraints = [
  { 'fixed_version' : '3.9.17' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

