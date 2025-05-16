#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232700);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/17");
  script_xref(name:"IAVA", value:"2025-A-0149-S");

  script_name(english:"Commvault Critical Webserver Vulnerability (CV_2025_03_1)");

  script_set_attribute(attribute:"synopsis", value:
"The Commvault install running on the remote host is affected by a critical webserver vulnerability.");
  script_set_attribute(attribute:"description", value:
"A critical webserver vulnerability exists in Commvault. A  remote attacker can exploit this to execute arbitrary
commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://documentation.commvault.com/securityadvisories/CV_2025_03_1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?910663c6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the version referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:commvault:commvault");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("commvault_win_installed.nbin");
  script_require_keys("installed_sw/Commvault");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::commvault::get_app_info_windows();

constraints = [
  {"min_version" : "11.20.0", "fixed_version": "11.20.217"},
  {"min_version" : "11.28.0", "fixed_version": "11.28.141"},
  {"min_version" : "11.32.0", "fixed_version": "11.32.89"},
  {"min_version" : "11.36.0", "fixed_version": "11.36.46"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
