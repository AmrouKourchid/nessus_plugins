#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202022);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/12");

  script_cve_id("CVE-2024-35266", "CVE-2024-35267");
  script_xref(name:"IAVA", value:"2024-A-0400");

  script_name(english:"Security Updates for Microsoft Team Foundation Server and Azure DevOps Server (July 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server or Azure DevOps is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server or Azure DevOps is missing security updates. It is, therefore, affected by
multiple vulnerabilities:
  - A session spoofing vulnerability exists. An attacker can
    exploit this to perform actions with the privileges of
    another user. (CVE-2024-35266, CVE-2024-35267)
    
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  # https://devblogs.microsoft.com/devops/azure-devops-server-2022-2-rtw-now-available/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2d7384a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates:
  - Azure DevOps Server 2022.2 RTW

Please refer to the vendor guidance to determine the version and patch to
apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35267");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:azure_devops_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_team_foundation_server_installed.nasl");
  script_require_keys("installed_sw/Microsoft Team Foundation Server");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::azure_devops_server::get_app_info();

# These file_fix versions are stored in both the patch & the registry, use the python script to obtain / extract the value easily
var ado_constraints = [
  {
    'release'        : '2022',
    'update_min_ver' : '1.0',
    'update_max_ver' : '2.0',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '19.225.34309.2',
    'file_fix_ver'   : '19.225.34530.2',
    'note'           : 'Azure DevOps Server 2022.1 prior to 2022.2 is vulnerable. Ensure\n' +
                       'the installation is updated to 2022.2.\n'
  }
];

vcf::microsoft::azure_devops_server::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS24-07',
  constraints:ado_constraints, 
  severity:SECURITY_HOLE
);
