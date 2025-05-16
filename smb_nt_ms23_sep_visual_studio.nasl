#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
 ##

include('compat.inc');

if (description)
{
  script_id(181293);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/12");

  script_cve_id(
    "CVE-2023-36758",
    "CVE-2023-36759",
    "CVE-2023-36792",
    "CVE-2023-36793",
    "CVE-2023-36794",
    "CVE-2023-36796",
    "CVE-2023-36799"
  );
  script_xref(name:"IAVA", value:"2023-A-0476-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (September 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected 
by multiple vulnerabilities:

  - A vulnerability in VSInstallerElevationService when running a malicious executable, which 
    can lead to an Elevation of Privilege. (CVE-2023-36758)

  - A vulnerability in pgodriver.sys where reading a malicious file can lead to an Elevation of 
    Privilege. (CVE-2023-36759)

  - A vulnerability in DiaSymReader.dll when reading a corrupted PDB file can lead to a Remote 
    Code Execution. (CVE-2023-36792, CVE-2023-36793, CVE-2023-36794, CVE-2023-36796) 

  - A vulnerability in .NET where reading a maliciously crafted X.509 certificate may result in 
    a Denial of Service. This issue only affects Linux systems. (CVE-2023-36799) 

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#1774--visual-studio-2022-version-1774
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7e9c1a2");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#1767--visual-studio-2022-version-1767
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3960c23");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#17411--visual-studio-2022-version-17411
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6795c11");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2#17.2.19
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f5a55b7");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.30
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e53c470d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
        - Update 16.11.30 for Visual Studio 2019
        - Update 17.2.19 for Visual Studio 2022
        - Update 17.4.11 for Visual Studio 2022
        - Update 17.6.7 for Visual Studio 2022
        - Update 17.7.4 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36758");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio", "SMB/Registry/Enumerated");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_visual_studio.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::visual_studio::get_app_info();

var constraints = [
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.11.34031.81', 'fixed_display': '16.11.34031.81 (16.11.30)'},
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.34031.104', 'fixed_display': '17.2.34031.104 (17.2.19)'},
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.34031.109', 'fixed_display': '17.4.34031.109 (17.4.11)'},
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.34031.178', 'fixed_display': '17.6.34031.178 (17.6.7)'},
  {'product': '2022', 'min_version': '17.7', 'fixed_version': '17.7.34024.191', 'fixed_display': '17.7.34024.191 (17.7.4)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
