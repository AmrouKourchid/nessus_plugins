#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(208746);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2024-43576", "CVE-2024-43609", "CVE-2024-43616");

  script_name(english:"Security Updates for Microsoft Office Products C2R (October 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing a security update. It is, therefore, affected by the following vulnerabilities:

  - Microsoft Office is affected by a remote code execution vulnerability. (CVE-2024-43576)

  - Microsoft Office is affected by a remote code execution vulnerability. (CVE-2024-43616)

  - Microsoft Office is affected by a spoofing vulnerability. (CVE-2024-43609)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5931548c");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43609");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-43616");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS24-10';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.18025.20140','channel':'Current'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.17928.20216','channel':'Enterprise Deferred','channel_version':'2408'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.17830.20232','channel':'Enterprise Deferred'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.17928.20216','channel':'First Release for Deferred'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.17328.20612','channel':'Deferred', 'channel_version':'2402'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.16731.20822','channel':'Deferred', 'channel_version':'2308'},
  {'product':'Microsoft Office 2024','file':'graph.exe','fixed_version':'16.0.18025.20140','channel':'2024 Retail'},
  {'product':'Microsoft Office 2021','file':'graph.exe','fixed_version':'16.0.18025.20140','channel':'2021 Retail'},
  {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.18025.20140','channel':'2019 Retail'},
  {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.18025.20140','channel':'2016 Retail'},
  {'product':'Microsoft Office 2021','file':'graph.exe','fixed_version':'16.0.17932.20130','channel':'LTSC 2024'},
  {'product':'Microsoft Office 2021','file':'graph.exe','fixed_version':'16.0.14332.20791','channel':'LTSC 2021'},
  {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.10415.20025','channel':'2019 Volume'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Office'
);
