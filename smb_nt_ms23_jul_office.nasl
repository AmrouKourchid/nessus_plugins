#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178169);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/11");

  script_cve_id("CVE-2023-33149", "CVE-2023-33152", "CVE-2023-33153");
  script_xref(name:"MSKB", value:"4464506");
  script_xref(name:"MSKB", value:"4475581");
  script_xref(name:"MSKB", value:"4493154");
  script_xref(name:"MSKB", value:"5001952");
  script_xref(name:"MSKB", value:"5002058");
  script_xref(name:"MSKB", value:"5002069");
  script_xref(name:"MSKB", value:"5002400");
  script_xref(name:"MSKB", value:"5002419");
  script_xref(name:"MSFT", value:"MS23-4464506");
  script_xref(name:"MSFT", value:"MS23-4475581");
  script_xref(name:"MSFT", value:"MS23-4493154");
  script_xref(name:"MSFT", value:"MS23-5001952");
  script_xref(name:"MSFT", value:"MS23-5002058");
  script_xref(name:"MSFT", value:"MS23-5002069");
  script_xref(name:"MSFT", value:"MS23-5002400");
  script_xref(name:"MSFT", value:"MS23-5002419");
  script_xref(name:"IAVA", value:"2023-A-0349-S");

  script_name(english:"Security Updates for Microsoft Office Products (July 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2023-33149, CVE-2023-33152, CVE-2023-33153)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4464506");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4475581");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493154");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001952");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002058");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002069");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002400");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002419");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4464506
  -KB4475581
  -KB4493154
  -KB5001952
  -KB5002058
  -KB5002069
  -KB5002400
  -KB5002419");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include('vcf_extras_office.inc');

var bulletin = 'MS23-07';
var kbs = make_list(
  '4464506',
  '4475581',
  '4493154',
  '5001952',
  '5002058',
  '5002069',
  '5002400',
  '5002419'
);
var severity = SECURITY_HOLE;

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office', kbs:kbs, bulletin:bulletin, severity:severity);

var constraints = [
  {'product' : 'Microsoft Office 2013 SP1', 'kb':'5002400', 'file':'mso.dll', 'fixed_version': '15.0.5571.1000'},
  {'product' : 'Microsoft Office 2016',     'kb':'5002419', 'file':'mso.dll', 'fixed_version': '16.0.5404.1000'},
  {'product' : 'Microsoft Office 2013 SP1', 'kb':'5001952', 'file':'oart.dll', 'fixed_version': '15.0.5571.1000'},
  {'product' : 'Microsoft Office 2016',     'kb':'4493154', 'file':'oart.dll', 'fixed_version': '16.0.5404.1000'},
  {'product' : 'Microsoft Office 2013 SP1', 'kb':'4464506', 'file':'umoutlookaddin.dll', 'fixed_version': '15.0.5571.1000'},
  {'product' : 'Microsoft Office 2016',     'kb':'4475581', 'file':'umoutlookaddin.dll', 'fixed_version': '16.0.5404.1000'},
  {'product' : 'Microsoft Office 2013 SP1', 'kb':'5002069', 'file':'msrtedit.dll', 'fixed_version': '15.0.5571.1000'},
  {'product' : 'Microsoft Office 2016',     'kb':'5002058', 'file':'msrtedit.dll', 'fixed_version': '16.0.5404.1000'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Office'
);
