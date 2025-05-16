#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(216241);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id("CVE-2025-21206");
  script_xref(name:"IAVA", value:"2025-A-0107-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (February 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by a privelige elevation vulnerability");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security
updates. It is, therefore, affected by a privilege elevation vulnerability.
  - An attacker could exploit the flaw to gain higher-level access privileges than they are normally allowed. 
    Specifically, in this case, the weakness lies within the Visual Studio Installer. When exploited, it could allow 
    a malicious user or process to bypass certain security controls, potentially resulting in unauthorized system 
    access. This kind of vulnerability is particularly dangerous because it may empower an attacker with administrative 
    rights, granting them the ability to install software, delete files, or even 
    take over system functions. (CVE-2025-21206)");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
    - Update 17.12.5 for Visual Studio 2022
    - Update 17.10.11 for Visual Studio 2022
    - Update 17.8.18 for Visual Studio 2022
    - Update 16.11.44 for Visual Studio 2019
    - Update 15.9.70 for Visual Studio 2017");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21206");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/13");

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
  // 2017  
  {'product': '2017', 'min_version': '15.0', 'fixed_version': '15.9.35727.129', 'fixed_display': '15.9.35727.129 (15.9.70)'},
    
  // 2019  
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.11.35706.149', 'fixed_display': '16.11.35706.149 (16.11.44)'},

  // 2022
  {'product': '2022', 'min_version': '17.8', 'fixed_version': '17.8.35728.64', 'fixed_display': '17.8.35728.64 (17.8.18)'},
  {'product': '2022', 'min_version': '17.10', 'fixed_version': '17.10.35728.63', 'fixed_display': '17.10.35728.63 (17.10.11)'},
  {'product': '2022', 'min_version': '17.12', 'fixed_version': '17.12.35728.132', 'fixed_display': '17.12.35728.132 (17.12.5)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_WARNING
);