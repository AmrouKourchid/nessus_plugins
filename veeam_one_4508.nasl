#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185458);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id("CVE-2023-38547", "CVE-2023-38549", "CVE-2023-41723");
  script_xref(name:"IAVA", value:"2023-A-0607-S");

  script_name(english:"Veeam ONE 11.x < 11.0.0.1379 / 11.0.1.x < 11.0.1.1880 / 12.x < 12.0.1.2591 Multiple Vulnerabiltiies (KB4508)");

  script_set_attribute(attribute:"synopsis", value:
"Veeam ONE installed on remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Veeam ONE installed on the remote Windows host is affected by multiple vulnerabilities, as
disclosed in the vendor's advisory with KB ID 4508, including the following:

  - A vulnerability in Veeam ONE allows an unauthenticated user to gain information about the SQL server
  connection Veeam ONE uses to access its configuration database. This may lead to remote code execution on
  the SQL server hosting the Veeam ONE configuration database. (CVE-2023-38547)

  - A vulnerability in Veeam ONE allows a user with the Veeam ONE Power User role to obtain the access token
  of a user with the Veeam ONE Administrator role through the use of XSS. Note: The criticality of this
  vulnerability is reduced as it requires interaction by a user with the Veeam ONE Administrator role. 
  (CVE-2023-38549)

  - A vulnerability in Veeam ONE allows a user with the Veeam ONE Read-Only User role to view the Dashboard
  Schedule. Note: The criticality of this vulnerability is reduced because the user with the Read-Only role is
  only able to view the schedule and cannot make changes. (CVE-2023-41723)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veeam.com/kb4508");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veeam ONE version 11.0.0.1379, 11.0.1.1880, 12.0.1.2591 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veeam:one");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veeam_one_win_installed.nbin");
  script_require_keys("installed_sw/Veeam ONE", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Veeam ONE', win_local:TRUE);

var constraints = [
  {'min_version': '11.0', 'fixed_version': '11.0.0.1379', 'fixed_display': 'Veeam ONE 11 (11.0.0.1379)'},
  {'min_version': '11.0.1', 'fixed_version': '11.0.1.1880', 'fixed_display': 'Veeam ONE 11a (11.0.1.1880)'},
  {'min_version': '12.0', 'fixed_version': '12.0.1.2591', 'fixed_display': 'Veeam ONE 12 (12.0.1.2591)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{'xss':TRUE});
