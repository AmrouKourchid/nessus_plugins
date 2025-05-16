#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190483);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id("CVE-2024-20673", "CVE-2024-21413");
  script_xref(name:"MSKB", value:"5002467");
  script_xref(name:"MSKB", value:"5002469");
  script_xref(name:"MSKB", value:"5002519");
  script_xref(name:"MSKB", value:"5002522");
  script_xref(name:"MSKB", value:"5002537");
  script_xref(name:"MSFT", value:"MS24-5002467");
  script_xref(name:"MSFT", value:"MS24-5002469");
  script_xref(name:"MSFT", value:"MS24-5002519");
  script_xref(name:"MSFT", value:"MS24-5002522");
  script_xref(name:"MSFT", value:"MS24-5002537");
  script_xref(name:"IAVA", value:"2024-A-0096-S");
  script_xref(name:"IAVA", value:"2024-A-0095-S");
  script_xref(name:"IAVA", value:"2024-A-0099-S");
  script_xref(name:"IAVA", value:"2024-A-0100-S");
  script_xref(name:"IAVA", value:"2024-A-0101-S");
  script_xref(name:"IAVA", value:"2024-A-0094-S");
  script_xref(name:"IAVA", value:"2024-A-0097-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/27");

  script_name(english:"Security Updates for Microsoft Office Products (February 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. They are, therefore, affected by multiple remote code
execution vulnerabilities. An attacker can exploit these to bypass authentication and execute unauthorized arbitrary
commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002467");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002469");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002519");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002522");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002537");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002467
  -KB5002469
  -KB5002519
  -KB5002522
  -KB5002537");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21413");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS24-02';
var kbs = make_list(
  '5002467',
  '5002469',
  '5002519',
  '5002522',
  '5002537'
);
var severity = SECURITY_HOLE;

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office', kbs:kbs, bulletin:bulletin, severity:severity);

var constraints = [
  {'product' : 'Microsoft Office 2016', 'kb':'5002537', 'file':'mso.dll', 'fixed_version': '16.0.5435.1001'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002467', 'file':'mso20win32client.dll', 'fixed_version': '16.0.5431.1000'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002522', 'file':'mso30win32client.dll', 'fixed_version': '16.0.5435.1001'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002469', 'file':'mso40uiwin32client.dll', 'fixed_version': '16.0.5435.1000'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002519', 'file':'mso99lwin32client.dll', 'fixed_version': '16.0.5431.1000'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Office'
);
