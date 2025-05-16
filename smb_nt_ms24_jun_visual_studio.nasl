#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200353);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2024-29060", "CVE-2024-29187", "CVE-2024-30052");
  script_xref(name:"IAVA", value:"2024-A-0346-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (June 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. They are, therefore, affected by 
multiple vulnerabilities, including:

  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.
    (CVE-2024-29060, CVE-2024-29187)

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-30052)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17102--visual-studio-2022-version-17102
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?869ec9a2");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.8#17811--visual-studio-2022-version-17811
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cee079bc");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#17616--visual-studio-2022-version-17616
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ab2536f");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#17420--visual-studio-2022-version-17420
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d3ba2e5");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.37
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bb5de16");
  # https://learn.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.63
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc1b86f6");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    - Update 15.9.63 for Visual Studio 2017
    - Update 16.11.37 for Visual Studio 2019
    - Update 17.4.20 for Visual Studio 2022
    - Update 17.6.16 for Visual Studio 2022
    - Update 17.8.11 for Visual Studio 2022
    - Update 17.10.2 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29060");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio", "SMB/Registry/Enumerated");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_visual_studio.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::visual_studio::get_app_info();

var constraints = [
  {'product': '2017', 'min_version': '15.0', 'fixed_version': '15.9.34930.103', 'fixed_display': '15.9.34930.103 (15.9.63)'},
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.11.34931.43', 'fixed_display': '16.11.34931.43 (16.11.37)'},
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.34931.60', 'fixed_display': '17.4.34931.60 (17.4.20)'},
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.34931.59', 'fixed_display': '17.6.34931.59 (17.6.16)'},
  {'product': '2022', 'min_version': '17.8', 'fixed_version': '17.8.34931.61', 'fixed_display': '17.8.34931.61 (17.8.11)'},
  {'product': '2022', 'min_version': '17.10', 'fixed_version': '17.10.35004.147', 'fixed_display': '17.10.35004.147 (17.10.2)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_WARNING
);
