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
  script_id(183020);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/23");

  script_cve_id("CVE-2023-38171", "CVE-2023-44487");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"IAVA", value:"2023-A-0542-S");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"IAVB", value:"2023-B-0083-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (October 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security
  updates. It is, therefore, affected by multiple denial of
  service vulnerabilities:
    - A denial of service (DoS) vulnerability. An attacker can
      exploit this issue to cause the affected component to
      deny system or application services. (CVE-2023-38171)

    - The HTTP/2 protocol allows a denial of service (server
      resource consumption) because request cancellation can
      reset many streams quickly (CVE-2023-44487)");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#1774--visual-studio-2022-version-1774
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7e9c1a2");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.6#1767--visual-studio-2022-version-1767
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3960c23");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#17411--visual-studio-2022-version-17411
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6795c11");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2#17.2.19
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f5a55b7");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
        - Update 17.2.20 for Visual Studio 2022
        - Update 17.4.12 for Visual Studio 2022
        - Update 17.6.8 for Visual Studio 2022
        - Update 17.7.5 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/13");

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
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.34202.200', 'fixed_display': '17.2.34202.200 (17.2.20)'},
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.34202.201', 'fixed_display': '17.4.34202.201 (17.4.12)'},
  {'product': '2022', 'min_version': '17.6', 'fixed_version': '17.6.34202.202', 'fixed_display': '17.6.34202.202 (17.6.8)'},
  {'product': '2022', 'min_version': '17.7', 'fixed_version': '17.7.34202.233', 'fixed_display': '17.7.34202.233 (17.7.5)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
