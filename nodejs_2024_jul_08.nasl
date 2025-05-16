#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201969);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2024-22018",
    "CVE-2024-22020",
    "CVE-2024-27980",
    "CVE-2024-36137",
    "CVE-2024-37372"
  );
  script_xref(name:"IAVB", value:"2024-B-0039-S");
  script_xref(name:"IAVB", value:"2024-B-0083-S");

  script_name(english:"Node.js 18.x < 18.20.4 / 20.x < 20.15.1 / 22.x < 22.4.1 Multiple Vulnerabilities (Monday, July 8, 2024 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 18.20.4, 20.15.1, 22.4.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the Monday, July 8, 2024 Security Releases advisory.

  - The CVE-2024-27980 was identified as an incomplete fix for the BatBadBut vulnerability. This vulnerability
    arises from improper handling of batch files with all possible extensions on Windows via
    child_process.spawn / child_process.spawnSync. A malicious command line argument can inject arbitrary
    commands and achieve code execution even if the shell option is not enabled. This vulnerability affects
    all users of child_process.spawn and child_process.spawnSync on Windows in all active release lines.
    Impact: Thank you, to tianst for reporting this vulnerability and thank you RafaelGSS for fixing it.
    (CVE-2024-27980)

  - A security flaw in Node.js allows a bypass of network import restrictions. By embedding non-network
    imports in data URLs, an attacker can execute arbitrary code, compromising system security. Verified on
    various platforms, the vulnerability is mitigated by forbidding data URLs in network imports. Exploiting
    this flaw can violate network import security, posing a risk to developers and servers. Impact: Thank you,
    to dittyroma for reporting this vulnerability and thank you RafaelGSS for fixing it. (CVE-2024-22020)

  - A vulnerability has been identified in Node.js, affecting users of the experimental permission model when
    the --allow-fs-write flag is used. Node.js Permission Model do not operate on file descriptors, however,
    operations such as fs.fchown or fs.fchmod can use a read-only file descriptor to change the owner and
    permissions of a file. This vulnerability affects all users using the experimental permission model in
    Node.js 20 and Node.js 22. Please note that at the time this CVE was issued, the permission model is an
    experimental feature of Node.js. Impact: Thank you, to 4xpl0r3r for reporting this vulnerability and thank
    you RafaelGSS for fixing it. (CVE-2024-36137)

  - A vulnerability has been identified in Node.js, affecting users of the experimental permission model when
    the --allow-fs-read flag is used. This flaw arises from an inadequate permission model that fails to
    restrict file stats through the fs.lstat API. As a result, malicious actors can retrieve stats from files
    that they do not have explicit read access to. This vulnerability affects all users using the experimental
    permission model in Node.js 20 and Node.js 22. Please note that at the time this CVE was issued, the
    permission model is an experimental feature of Node.js. Impact: Thank you, to haxatron1 for reporting this
    vulnerability and thank you RafaelGSS for fixing it. (CVE-2024-22018)

  - The Permission Model assumes that any path starting with two backslashes \ has a four-character prefix
    that can be ignored, which is not always true. This subtle bug leads to vulnerable edge cases. This
    vulnerability affects Windows users of the Node.js Permission Model in version v22.x and v20.x Impact:
    Thank you, to tniessen for reporting this vulnerability and thank you RafaelGSS for fixing it.
    (CVE-2024-37372)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nodejs.org/en/blog/vulnerability/july-2024-security-releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 18.20.4 / 20.15.1 / 22.4.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22020");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-27980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '18.0.0', 'fixed_version' : '18.20.4' },
  { 'min_version' : '20.0.0', 'fixed_version' : '20.15.1' },
  { 'min_version' : '22.0.0', 'fixed_version' : '22.4.1' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
