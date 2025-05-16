#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190548);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2024-21386", "CVE-2024-21404");
  script_xref(name:"IAVA", value:"2024-A-0090-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (February 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. They are, therefore, affected by multiple
vulnerabilities, including:

  - A denial of service (DoS) vulnerability. An attacker can exploit this issue to cause the affected component to
    deny system or application services. (CVE-2024-21386, CVE-2024-21404)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#17416--visual-studio-2022-version-17416
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f56115c8");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#17612--visual-studio-2022-version-17612
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9edc428");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.8#1787--visual-studio-2022-version-1787
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8beb8f3d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    - Update 17.4.16 for Visual Studio 2022
    - Update 17.6.12 for Visual Studio 2022
    - Update 17.8.7 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21404");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/14");

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
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.34601.181', 'fixed_display': '17.4.34601.181 (17.4.16)'},
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.34601.182', 'fixed_display': '17.6.34601.182 (17.6.12)'},
  {'product': '2022', 'min_version': '17.8', 'fixed_version': '17.8.34601.278', 'fixed_display': '17.8.34601.278 (17.8.7)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
