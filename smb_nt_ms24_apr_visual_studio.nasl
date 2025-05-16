#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193088);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id(
    "CVE-2024-21409",
    "CVE-2024-28929",
    "CVE-2024-28930",
    "CVE-2024-28931",
    "CVE-2024-28932",
    "CVE-2024-28933",
    "CVE-2024-28934",
    "CVE-2024-28935",
    "CVE-2024-28936",
    "CVE-2024-28937",
    "CVE-2024-28938"
  );
  script_xref(name:"IAVA", value:"2024-A-0223-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (April 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. They are, therefore, affected by multiple
vulnerabilities, including:

  - A remote code execution vulnerability exists in .NET, .NET Framework, and Visual Studio. An
    unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary code.
    (CVE-2024-21409)

  - A remote code execution vulnerability exists in the Microsoft ODBC Driver for SQL Server. An
    unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary code.
    (CVE-2024-28929, CVE-2024-28930, CVE-2024-28931, CVE-2024-28932, CVE-2024-28933, CVE-2024-28934,
    CVE-2024-28935, CVE-2024-28936, CVE-2024-28937, CVE-2024-28938)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#1796--visual-studio-2022-version-1796
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bdde8af5");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.8#1789--visual-studio-2022-version-1789
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46e1978f");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#17614--visual-studio-2022-version-17614
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07a4a571");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#17418--visual-studio-2022-version-17418
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac7d7f93");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.35
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad32b903");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    - Update 16.11.35 for Visual Studio 2019
    - Update 17.4.18 for Visual Studio 2022
    - Update 17.6.14 for Visual Studio 2022
    - Update 17.8.9 for Visual Studio 2022
    - Update 17.9.6 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28938");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/09");

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
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.11.34729.46', 'fixed_display': '16.11.34729.46 (16.11.35)'},
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.34729.48', 'fixed_display': '17.4.34729.48 (17.4.18)'},
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.34728.177', 'fixed_display': '17.6.34728.177 (17.6.14)'},
  {'product': '2022', 'min_version': '17.8', 'fixed_version': '17.8.34728.176', 'fixed_display': '17.8.34728.176 (17.8.9)'},
  {'product': '2022', 'min_version': '17.9', 'fixed_version': '17.9.34728.123', 'fixed_display': '17.9.34728.123 (17.9.6)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
