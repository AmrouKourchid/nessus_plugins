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
  script_id(162068);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/20");

  script_cve_id("CVE-2020-17062", "CVE-2020-17064");
  script_xref(name:"IAVA", value:"2020-A-0516-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0135");

  script_name(english:"Security Updates for Microsoft Office Products C2R (November 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft office Product is missing security updates.

  - Microsoft Office Access Connectivity Engine Remote Code Execution Vulnerability (CVE-2020-17062)

  - Microsoft Excel Remote Code Execution Vulnerability This CVE ID is unique from CVE-2020-17019,
    CVE-2020-17065, CVE-2020-17066. (CVE-2020-17064)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17062");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-17064");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS20-11';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.12527.21330','channel': 'Microsoft 365 Apps on Windows 7'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.12527.21330','channel': 'Deferred','channel_version': '2002'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.11929.20974','channel': 'Deferred'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.13231.20514','channel': 'Enterprise Deferred','channel_version': '2009'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.13127.20760','channel': 'Enterprise Deferred'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.13127.20760','channel': 'First Release for Deferred'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.13328.20356','channel': '2016 Retail'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.13328.20356','channel': 'Current'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.13328.20356','channel': '2019 Retail','channel_version': '2010'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.13328.20356','channel': '2019 Retail','channel_version': '2004'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.13231.20514','channel': '2019 Retail','channel_version': '2009'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.13127.20760','channel': '2019 Retail','channel_version': '2008'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.12527.21330','channel': '2019 Retail','channel_version': '2002'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.11929.20974','channel': '2019 Retail','channel_version': '1908'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.11929.20974','channel': '2019 Retail'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.10368.20035','channel': '2019 Volume'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Office'
);
