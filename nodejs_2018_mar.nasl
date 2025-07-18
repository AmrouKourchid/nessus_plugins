#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118933);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/09");

  script_cve_id("CVE-2018-7158", "CVE-2018-7159", "CVE-2018-7160");

  script_name(english:"Node.js multiple vulnerabilities (March 2018 Security Releases).");
  script_summary(english:"Checks the Node.js version.");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is 4.x prior to 4.9.0, 6.x prior to 6.14.0, 8.x prior to 8.11.0 or
9.x prior to 9.10.0. It is, therefore, affected by multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/march-2018-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d516633a");
  script_set_attribute(attribute:"solution", value:
"Upgrade Node.js to a recommended by vendor version or above.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7160");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
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
if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

var app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);

vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '4.0.0', 'fixed_version' : '4.9.0' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.14.0' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.11.0' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.10.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
