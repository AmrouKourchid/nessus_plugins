#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187806);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/16");

  script_cve_id(
    "CVE-2023-29349",
    "CVE-2023-29356",
    "CVE-2023-32025",
    "CVE-2023-32026",
    "CVE-2023-32027",
    "CVE-2023-32028",
    "CVE-2024-0056",
    "CVE-2024-0057",
    "CVE-2024-20656",
    "CVE-2024-21319"
  );
  script_xref(name:"IAVA", value:"2024-A-0018-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (January 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. They are, therefore, affected by multiple
vulnerabilities, including:

  - Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability (CVE-2023-29356, CVE-2023-32025,
    CVE-2023-32026, CVE-2023-32027)

  - NET, .NET Framework, and Visual Studio Security Feature Bypass Vulnerability (CVE-2024-0057)

  - Visual Studio Elevation of Privilege Vulnerability (CVE-2024-20656)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#1784--visual-studio-2022-version-1784
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abd939e1");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#17611--visual-studio-2022-version-17611
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a578d49");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#17415--visual-studio-2022-version-17415
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23a163cd");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2#17.2.23
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c571457");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.33
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?485fb21f");
  # https://learn.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.59
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e87822b0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    - Update 15.9.59 for Visual Studio 2017
    - Update 16.11.33 for Visual Studio 2019
    - Update 17.2.23 for Visual Studio 2022
    - Update 17.4.15 for Visual Studio 2022
    - Update 17.6.11 for Visual Studio 2022
    - Update 17.8.4 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0057");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/09");

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
  {'product': '2017', 'min_version': '15.0', 'fixed_version': '15.9.34407.156', 'fixed_display': '15.9.34407.156 (15.9.59)'},
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.11.34407.143', 'fixed_display': '16.11.34407.143 (16.11.33)'},
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.34408.132', 'fixed_display': '17.2.34408.132 (17.2.23)'},
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.34408.133', 'fixed_display': '17.4.34408.133 (17.4.15)'},
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.34408.137', 'fixed_display': '17.6.34408.137 (17.6.11)'},
  {'product': '2022', 'min_version': '17.8', 'fixed_version': '17.8.34408.163', 'fixed_display': '17.8.34408.163 (17.8.4)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
