#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179692);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/09");

  script_cve_id(
    "CVE-2023-32002",
    "CVE-2023-32003",
    "CVE-2023-32004",
    "CVE-2023-32005",
    "CVE-2023-32006",
    "CVE-2023-32558",
    "CVE-2023-32559"
  );
  script_xref(name:"IAVB", value:"2023-B-0059-S");

  script_name(english:"Node.js 16.x < 16.20.2 / 18.x < 18.17.1 / 20.x < 20.5.1 Multiple Vulnerabilities (Wednesday August 09 2023 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 16.20.2, 18.17.1, 20.5.1. It is, therefore, affected 
by multiple vulnerabilities as referenced in the Wednesday August 09 2023 Security Releases advisory:

  - Permissions policies can be bypassed via Module._load (CVE-2023-32002)

  - Permission model bypass by specifying a path traversal sequence in a Buffer (CVE-2023-32004)

  - process.binding() can bypass the permission model through path traversal (CVE-2023-32558)

  - Permissions policies can impersonate other modules in using module.constructor.createRequire() (CVE-2023-32006)

  - Permissions policies can be bypassed via process.binding (CVE-2023-32559)

  - fs.statfs can retrive stats from files restricted by the Permission Model (CVE-2023-32005)

  - fs.mkdtemp() and fs.mkdtempSync() are missing getValidatedPath() checks (CVE-2023-32003)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/august-2023-security-releases
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4ab34c1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 16.20.22 / 18.17.1 / 20.5.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_win_installed.nbin", "nodejs_installed_nix.nbin", "macosx_nodejs_installed.nbin");
  script_require_keys("installed_sw/Node.js");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
var os = get_kb_item_or_exit('Host/OS');
if ('windows' >< tolower(os)) win_local = TRUE;
var app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '16.0.0', 'fixed_version' : '16.20.2' },
  { 'min_version' : '18.0.0', 'fixed_version' : '18.17.1' },
  { 'min_version' : '20.0.0', 'fixed_version' : '20.5.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);