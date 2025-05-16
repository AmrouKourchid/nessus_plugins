#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234217);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id("CVE-2025-29802", "CVE-2025-29804");
  script_xref(name:"IAVA", value:"2025-A-0243");
  script_name(english:"Security Updates for Microsoft Visual Studio 2022 17.8 / 17.10 / 17.12 Products (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. They are, therefore, affected by 
multiple vulnerabilities, including:

  - Improper access control in Visual Studio allows an authorized attacker to eleveate priveleges 
    locally (CVE-2025-29802)

  - Improper access control in Visual Studio allows an authorized attacker to eleveate priveleges 
    locally (CVE-2025-29804)

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
    # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba2fed34");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?256c5953");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf5a6817");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    - Update 17.8.20 for Visual Studio 2022
    - Update 17.10.13 for Visual Studio 2022
    - Update 17.12.7 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-29802");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

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
  {'product': '2022', 'min_version': '17.8', 'fixed_version': '17.8.35931.193', 'fixed_display': '17.8.35931.193 (17.8.20)'},
  {'product': '2022', 'min_version': '17.10', 'fixed_version': '17.10.35931.201', 'fixed_display': '17.10.35931.201 (17.10.13)'},
  {'product': '2022', 'min_version': '17.12', 'fixed_version': '17.12.35931.192', 'fixed_display': '17.12.35931.192 (17.12.7)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_WARNING
);
