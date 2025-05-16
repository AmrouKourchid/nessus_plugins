#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
 ##

include('compat.inc');

if (description)
{
  script_id(178161);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/01");

  script_cve_id("CVE-2023-33127", "CVE-2023-33170");
  script_xref(name:"IAVA", value:"2023-A-0343-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (July 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - A vulnerability exist in ASP.NET Core applications where account lockout maximum failed attempts may
    not be immediately updated, allowing an attacker to try more passwords. (CVE-2023-33170)

  - A vulnerability exists in .NET applications where the diagnostic server can be exploited to achieve
    cross-session/cross-user elevation of privilege (EoP) and code execution. (CVE-2023-33127)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.6.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74184403");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#1749--visual-studio-2022-version-1749
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2eaf3ccc");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2#17.2.17
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb220552");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.0#17.0.23
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6694e7b7");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
        - Update 17.0.23 for Visual Studio 2022
        - Update 17.2.17 for Visual Studio 2022
        - Update 17.4.9 for Visual Studio 2022
        - Update 17.6.5 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33127");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio", "SMB/Registry/Enumerated");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_visual_studio.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::visual_studio::get_app_info();

var constraints = [
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.33829.163', 'fixed_display': '17.0.33829.163 (17.0.23)'},
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.33829.164', 'fixed_display': '17.2.33829.164 (17.2.17)'},
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.33829.165', 'fixed_display': '17.4.33829.165 (17.4.9)'},
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.33829.357', 'fixed_display': '17.6.33829.357 (17.6.5)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
