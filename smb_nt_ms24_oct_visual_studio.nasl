#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208750);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id(
    "CVE-2024-43483",
    "CVE-2024-43484",
    "CVE-2024-43485",
    "CVE-2024-43590",
    "CVE-2024-43603"
  );
  script_xref(name:"IAVA", value:"2024-A-0626-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (October 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. They are, therefore, affected by 
multiple vulnerabilities, including:

  - .NET Denial of Service Vulnerability in System.Security.Cryptography.Cose, 
    System.IO.Packaging, System.Runtime.Caching (CVE-2024-43483)
  
  - .NET Denial of Service Vulnerability in System.IO.Packaging (CVE-2024-43484)

  - Elevation of Privilege Vulnerability in Visual Studio C++ Redistributable Installer (CVE-2024-43590)

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#17.6.20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db3c4e1c");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.8#17.8.15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?075270bf");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.11#17.11.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e01e5a6b");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.10#17.10.8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af75a6c5");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    - Update 17.6.20 for Visual Studio 2022
    - Update 17.8.15 for Visual Studio 2022
    - Update 17.11.5 for Visual Studio 2022
    - Update 17.10.8 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43590");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

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
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.35326.246', 'fixed_display': '17.6.35326.246 (17.6.20)'},
  {'product': '2022', 'min_version': '17.8', 'fixed_version': '17.8.35326.199', 'fixed_display': '17.8.35326.199 (17.8.15)'},
  {'product': '2022', 'min_version': '17.10', 'fixed_version': '17.10.35326.205', 'fixed_display': '17.10.35326.205 (17.10.8)'},
  {'product': '2022', 'min_version': '17.11', 'fixed_version': '17.11.35327.3', 'fixed_display': '17.11.35327.3 (17.11.5)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_WARNING
);
