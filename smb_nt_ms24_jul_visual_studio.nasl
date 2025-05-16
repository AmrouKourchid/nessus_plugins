#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202032);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2024-30105",
    "CVE-2024-35264",
    "CVE-2024-38081",
    "CVE-2024-38095"
  );
  script_xref(name:"IAVA", value:"2024-A-0398-S");
  script_xref(name:"IAVA", value:"2024-A-0406-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (July 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. They are, therefore, affected by 
multiple vulnerabilities, including:

  - .NET Core and Visual Studio Denial of Service Vulnerability. (CVE-2024-30105, CVE-2024-38095)

  - .NET and Visual Studio Remote Code Execution Vulnerability. (CVE-2024-35264)

  - .NET, .NET Framework, and Visual Studio Elevation of Privilege Vulnerability. (CVE-2024-38081)

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.10.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b5d94d6");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.8#17.8.12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6bfc7518");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#17.6.17
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab6fdc7c");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#17.4.21
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60f543bb");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    - Update 17.4.21 for Visual Studio 2022
    - Update 17.6.17 for Visual Studio 2022
    - Update 17.8.12 for Visual Studio 2022
    - Update 17.10.4 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35264");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-38081");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio", "SMB/Registry/Enumerated");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_visual_studio.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::visual_studio::get_app_info();

var constraints = [
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.35026.314', 'fixed_display': '17.4.35026.314 (17.4.21)'},
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.35028.176', 'fixed_display': '17.6.35028.176 (17.6.17)'},
  {'product': '2022', 'min_version': '17.8', 'fixed_version': '17.8.35027.43', 'fixed_display': '17.8.35027.43 (17.8.12)'},
  {'product': '2022', 'min_version': '17.10', 'fixed_version': '17.10.35027.167', 'fixed_display': '17.10.35027.167 (17.10.4)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
