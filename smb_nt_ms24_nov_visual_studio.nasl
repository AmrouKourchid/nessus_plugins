#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210895);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id(
    "CVE-2024-43498",
    "CVE-2024-43499",
    "CVE-2024-49044",
    "CVE-2024-49050",
    "CVE-2024-49049"
  );
  script_xref(name:"IAVA", value:"2024-A-0734-S");
  script_xref(name:"IAVA", value:"2024-A-0726-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (November 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. They are, therefore, affected by 
multiple vulnerabilities, including:

  - A remote unauthenticated attacker could exploit this vulnerability by sending specially crafted requests 
    to a .NET vulnerable webapp or loading a specially crafted file into a vulnerable application. (CVE-2024-43498)
  
  - The NrbfDecoder component in .NET 9 contains a denial of service vulnerability due to 
    incorrect input validation. (CVE-2024-43499)

  - Elevation of Privilege Vulnerability in Visual Studio C++ Redistributable Installer (CVE-2024-43590)

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#17.6.21
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea0e64c4");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.8#17.8.16
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f1051c7");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.11#17.11.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a4d413d");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.10#17.10.9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f4b3a92");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    - Update 17.6.20 for Visual Studio 2022
    - Update 17.8.15 for Visual Studio 2022
    - Update 17.10.8 for Visual Studio 2022
    - Update 17.11.5 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49050");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-43498");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/13");

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
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.35430.205', 'fixed_display': '17.6.35430.205 (17.6.21)'},
  {'product': '2022', 'min_version': '17.8', 'fixed_version': '17.8.35430.204', 'fixed_display': '17.8.35430.204 (17.8.16)'},
  {'product': '2022', 'min_version': '17.10', 'fixed_version': '17.10.35431.56', 'fixed_display': '17.10.35431.56 (17.10.9)'},
  {'product': '2022', 'min_version': '17.11', 'fixed_version': '17.11.35431.28', 'fixed_display': '17.11.35431.28 (17.11.6)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
