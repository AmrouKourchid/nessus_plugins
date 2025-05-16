#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182861);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/12");

  script_cve_id("CVE-2023-36561");
  script_xref(name:"IAVA", value:"2023-A-0546-S");

  script_name(english:"Security Updates for Microsoft Team Foundation Server and Azure DevOps Server (October 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server or Azure DevOps is affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server or Azure DevOps install is missing security updates. It is, therefore, affected by
an elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://devblogs.microsoft.com/devops/october-patches-for-azure-devops-server-3/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5823a27");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates:
  - Azure DevOps Server 2022.0.1 with patch 4
  - Azure DevOps Server 2020.1.2 with patch 9
  - Azure DevOps Server 2020.0.2 with patch 5

Please refer to the vendor guidance to determine the version and patch to apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36561");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:azure_devops_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_team_foundation_server_installed.nasl");
  script_require_keys("installed_sw/Microsoft Team Foundation Server");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::azure_devops_server::get_app_info();

# These file_fix versions are stored in both the patch & the registry, use the python script to obtain / extract the value easily
var ado_constraints = [
  {
    'release'        : '2020',
    'update_min_ver' : '0',
    'update_max_ver' : '0.2',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '18.0.0.0',
    'file_fix_ver'   : '18.170.34127.1',
    'note'           : 'Azure DevOps Server 2020 prior to 2020.0.2 patch 5 is vulnerable. Ensure\n' +
                       'the installation is updated to 2020.0.2 patch 5.\n'
  },
  {
    'release'        : '2020',
    'update_min_ver' : '1.0',
    'update_max_ver' : '2.0',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '18.0.0.0',
    'file_fix_ver'   : '18.181.34126.2',
    'note'           : 'Azure DevOps Server 2020 prior to 2020.1.2 patch 9 is vulnerable. Ensure\n' +
                       'the installation is updated to 2020.1.2 patch 9.\n'
  },
  {
    'release'        : '2022',
    'update_min_ver' : '0.1',
    'update_max_ver' : '0.2',
    'append_path'    : 'Application Tier\\Web Services\\bin',
    'file'           : 'Microsoft.TeamFoundation.Framework.Server.dll',
    'file_min_ver'   : '19.0.0.0',
    'file_fix_ver'   : '19.205.34206.1',
    'note'           : 'Azure DevOps Server 2022 prior to 2022.0.1 patch 4 is vulnerable. Ensure\n' +
                       'the installation is updated to 2022.0.1 patch 4.\n'
  }
];

vcf::microsoft::azure_devops_server::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS23-10',
  constraints:ado_constraints, 
  severity:SECURITY_HOLE
);
