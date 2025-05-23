#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193573);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/09");

  script_cve_id("CVE-2024-27980");
  script_xref(name:"IAVB", value:"2024-B-0039-S");

  script_name(english:"Node.js 18.x < 18.20.2 / 20.x < 20.12.2 / 21.x < 21.7.3 Command Injection Vulnerability (Wednesday, April 10, 2024 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by command Injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 18.20.2, 20.12.2, 21.7.3. It is, therefore, affected by
a command injection vulnerability as referenced in the Wednesday, April 10, 2024 Security Releases advisory.  This is due 
to the improper handling of batch files in child_process.spawn / child_process.spawnSync, a malicious command line argument
 can inject arbitrary commands and achieve code execution even if the shell option is not enabled.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/april-2024-security-releases-2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4a7d9bc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 18.20.2 / 20.12.2 / 21.7.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_win_installed.nbin");
  script_require_keys("installed_sw/Node.js");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
var os = get_kb_item_or_exit('Host/OS');
if ('windows' >< tolower(os)) win_local = TRUE;
else audit(AUDIT_OS_NOT, 'affected');

var app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '18.0.0', 'fixed_version' : '18.20.2' },
  { 'min_version' : '20.0.0', 'fixed_version' : '20.12.2' },
  { 'min_version' : '21.0.0', 'fixed_version' : '21.7.3' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
