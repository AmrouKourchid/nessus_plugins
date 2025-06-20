#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214126);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id(
    "CVE-2024-50338",
    "CVE-2025-21171",
    "CVE-2025-21172",
    "CVE-2025-21173",
    "CVE-2025-21176",
    "CVE-2025-21178"
  );
  script_xref(name:"IAVA", value:"2025-A-0035-S");

  script_name(english:"Security Updates for Microsoft Visual Studio 2022 17.6 / 17.8 / 17.10 Products (January 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. They are, therefore, affected by 
multiple vulnerabilities, including:

  - An undisclosed .NET, .NET Framework, and Visual Studio Remote Code Execution Vulnerability (CVE-2025-21176)

  - An undisclosed Visual Studio Remote Code Execution Vulnerability (CVE-2025-21178)

  - An undisclosed .NET and Visual Studio Remote Code Execution Vulnerability (CVE-2025-21172)

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.10#171010--visual-studio-2022-version-171010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a84b0fc");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.8#17817--visual-studio-2022-version-17817
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cd84461");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#17622--visual-studio-2022-version-17622
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c66e1c9b");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    - Update 17.10.10 for Visual Studio 2022
    - Update 17.8.17 for Visual Studio 2022
    - Update 17.6.22 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21178");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio", "SMB/Registry/Enumerated");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_visual_studio.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::visual_studio::get_app_info();

var constraints = [
  {'product': '2022', 'min_version': '17.10', 'fixed_version': '17.10.35707.196', 'fixed_display': '17.10.35707.196 (17.10.10)'},
  {'product': '2022', 'min_version': '17.8', 'fixed_version': '17.8.35707.121', 'fixed_display': '17.8.35707.121 (17.8.17)'},
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.35707.66', 'fixed_display': '17.6.35707.66 (17.6.22)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
