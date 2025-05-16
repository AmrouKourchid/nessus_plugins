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
  script_id(185735);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/29");

  script_cve_id(
    "CVE-2023-36038",
    "CVE-2023-36042",
    "CVE-2023-36049",
    "CVE-2023-36558"
  );
  script_xref(name:"IAVA", value:"2023-A-0624-S");
  script_xref(name:"IAVA", value:"2023-A-0618-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (November 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - A security feature bypass vulnerability exists. An attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising the integrity of the system/application. (CVE-2023-36558)

  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges. (CVE-2023-36049)

  - A denial of service (DoS) vulnerability. An attacker can exploit this issue to cause the affected component to
    deny system or application services. (CVE-2023-36038, CVE-2023-36042)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.7#1777--visual-studio-2022-version-1777
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da640b88");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#17.6.10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0236e928");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#17.4.14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac2fc1d3");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2#17.2.22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?908bbf80");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.32
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0df345d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
        - Update 16.11.32 for Visual Studio 2019
        - Update 17.2.22 for Visual Studio 2022
        - Update 17.4.14 for Visual Studio 2022
        - Update 17.6.10 for Visual Studio 2022
        - Update 17.7.7 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36049");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio", "SMB/Registry/Enumerated");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_visual_studio.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::visual_studio::get_app_info();

var constraints = [
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.11.34301.259', 'fixed_display': '16.11.34301.259 (16.11.32)'},
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.34302.75', 'fixed_display': '17.2.34302.75 (17.2.22)'},
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.34302.79', 'fixed_display': '17.4.34302.79 (17.4.14)'},
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.34302.98', 'fixed_display': '17.6.34302.98 (17.6.10)'},
  {'product': '2022', 'min_version': '17.7', 'fixed_version': '17.7.34302.85', 'fixed_display': '17.7.34302.85 (17.7.7)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
