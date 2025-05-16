#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197296);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id(
    "CVE-2024-30045",
    "CVE-2024-30046",
    "CVE-2024-32002",
    "CVE-2024-32004"
  );
  script_xref(name:"IAVA", value:"2024-A-0287-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (May 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. They are, therefore, affected by 
multiple vulnerabilities, including:

  - Recursive clones on case-insensitive filesystems that support symlinks are susceptible to Remote Code 
    Execution. (CVE-2024-32002)

  - Remote Code Execution while cloning special-crafted local repositories. (CVE-2024-32004)

  - A Remote Code Execution vulnerability exists in .NET 7.0 and .NET 8.0 where a stack buffer overrun
    occurs in .NET Double Parse routine. (CVE-2024-30045)

  - A Vulnerability exists in Microsoft.AspNetCore.Server.Kestrel.Core.dll where a dead-lock can occur 
    resulting in Denial of Service. (CVE-2024-30046)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#1797--visual-studio-2022-version-1797
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e226eb87");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.8#17810--visual-studio-2022-version-17810
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87c3971a");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#17615--visual-studio-2022-version-17615
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?131d08ea");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#17419--visual-studio-2022-version-17419
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb28bccd");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#whats-new-in-visual-studio-2019-version-1611
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55672f84");
  # https://learn.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.62
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?253c4747");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    - Update 15.9.62 for Visual Studio 2017
    - Update 16.11.36 for Visual Studio 2019
    - Update 17.4.19 for Visual Studio 2022
    - Update 17.6.15 for Visual Studio 2022
    - Update 17.8.10 for Visual Studio 2022
    - Update 17.9.7 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/17");

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
  {'product': '2017', 'min_version': '15.0', 'fixed_version': '15.9.34830.200', 'fixed_display': '15.9.34830.200 (15.9.62)'},
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.11.34902.97', 'fixed_display': '16.11.34902.97 (16.11.36)'},
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.34902.99', 'fixed_display': '17.4.34902.99 (17.4.19)'},
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.34902.100', 'fixed_display': '17.6.34902.100 (17.6.15)'},
  {'product': '2022', 'min_version': '17.8', 'fixed_version': '17.8.34902.127', 'fixed_display': '17.8.34902.127 (17.8.10)'},
  {'product': '2022', 'min_version': '17.9', 'fixed_version': '17.9.34902.65', 'fixed_display': '17.9.34902.65 (17.9.7)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
