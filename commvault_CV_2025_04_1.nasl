#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234836);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id("CVE-2025-34028");
  script_xref(name:"IAVA", value:"2025-A-0299");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/05/23");

  script_name(english:"Commvault Command Center 11.38 < 11.38.20 RCE (CV_2025_04_1)");

  script_set_attribute(attribute:"synopsis", value:
"The Commvault install running on the remote host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"An arbitrary code execution vulnerability in Commvault Command Center Innovation Release allows an unauthenticated
actor to upload ZIP files, which, when expanded by the target server, result in Remote Code Execution. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://documentation.commvault.com/securityadvisories/CV_2025_04_1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d86cb0f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 11.38.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-34028");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/25");

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
  {'min_version' : '11.38.0', 'fixed_version': '11.38.20'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
