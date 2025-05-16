#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181295);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/13");

  script_cve_id("CVE-2023-36767", "CVE-2023-41764");
  script_xref(name:"MSKB", value:"5002100");
  script_xref(name:"MSKB", value:"5002457");
  script_xref(name:"MSKB", value:"5002477");
  script_xref(name:"MSKB", value:"5002498");
  script_xref(name:"MSFT", value:"MS23-5002100");
  script_xref(name:"MSFT", value:"MS23-5002457");
  script_xref(name:"MSFT", value:"MS23-5002477");
  script_xref(name:"MSFT", value:"MS23-5002498");
  script_xref(name:"IAVA", value:"2023-A-0474-S");

  script_name(english:"Security Updates for Microsoft Office Products (September 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - A security feature bypass vulnerability exists. An
    attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising
    the integrity of the system/application.
    (CVE-2023-36767)

  - A session spoofing vulnerability exists. An attacker can
    exploit this to perform actions with the privileges of
    another user. (CVE-2023-41764)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002100");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002457");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002477");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002498");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002100
  -KB5002457
  -KB5002477
  -KB5002498");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41764");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/12");

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

var bulletin = 'MS23-09';
var kbs = make_list(
  '5002100',
  '5002457',
  '5002477',
  '5002498'
);
var severity = SECURITY_WARNING;

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office', kbs:kbs, bulletin:bulletin, severity:severity);

var constraints = [
  {'product' : 'Microsoft Office 2013 SP1', 'kb':'5002477', 'file':'mso.dll', 'fixed_version': '15.0.5589.1000'},
  {'product' : 'Microsoft Office 2016',     'kb':'5002100', 'file':'mso99lwin32client.dll', 'fixed_version': '16.0.5413.1000'},
  {'product' : 'Microsoft Office 2016',     'kb':'5002498', 'file':'mso30win32client.dll',  'fixed_version': '16.0.5413.1000'},
  {'product' : 'Microsoft Office 2016',     'kb':'5002457', 'file':'mso.dll', 'fixed_version': '16.0.5413.1000'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Office'
);
