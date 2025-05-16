#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214119);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id(
    "CVE-2024-50338",
    "CVE-2025-21172",
    "CVE-2025-21176",
    "CVE-2025-21178"
  );
  script_xref(name:"IAVA", value:"2025-A-0035-S");

  script_name(english:"Security Updates for Microsoft Visual Studio 2019 16.11 / 2017 15.9 Products (January 2025)");

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
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#release-notes-icon-visual-studio-2019-version-161143
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8864d1f");
  # https://learn.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.69
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85e0b114");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    - Update 16.11.43 for Visual Studio 2019
    - Update 15.9.69 for Visual Studio 2017");
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
  {'product': '2019', 'min_version': '16.11', 'fixed_version': '16.11.35706.149', 'fixed_display': '16.11.35706.149 (16.11.43)'},
  {'product': '2017', 'min_version': '15.9', 'fixed_version': '15.9.35706.162', 'fixed_display': '15.9.35706.162 (15.9.69)'},
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
