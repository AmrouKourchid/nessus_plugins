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
  script_id(179645);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/01");

  script_cve_id(
    "CVE-2023-35390",
    "CVE-2023-35391",
    "CVE-2023-38178",
    "CVE-2023-38180"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/30");
  script_xref(name:"IAVA", value:"2023-A-0415-S");
  script_xref(name:"IAVA", value:"2023-A-0404-S");
  script_xref(name:"IAVA", value:"2023-A-0406-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (August 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - .NET Core and Visual Studio Denial of Service Vulnerability. (CVE-2023-38178)

  - .NET and Visual Studio Remote Code Execution Vulnerability. (CVE-2023-35390)

  - .NET and Visual Studio Denial of Service Vulnerability. (CVE-2023-38180)

  - ASP.NET Core SignalR and Visual Studio Information Disclosure Vulnerability. (CVE-2023-35391)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#1770--visual-studio-2022-version-177
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a7fd065");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#17.6.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03c492a3");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#17.4.10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee0cd3a3");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2#17.2.18
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f36add8d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 17.2.18 for Visual Studio 2022
        - Update 17.4.10 for Visual Studio 2022
        - Update 17.6.6 for Visual Studio 2022
        - Update 17.7 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35391");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/10");

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
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.33927.290', 'fixed_display': '17.2.33927.290 (17.2.18)'},
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.33927.135', 'fixed_display': '17.4.33927.135 (17.4.10)'},
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.33927.249', 'fixed_display': '17.6.33927.249 (17.6.6)'},
  {'product': '2022', 'min_version': '17.7', 'fixed_version': '17.7.34003.232', 'fixed_display': '17.7.34003.232 (17.7.0)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);