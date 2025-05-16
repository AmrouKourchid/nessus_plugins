#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235849);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id(
    "CVE-2025-30377",
    "CVE-2025-30379",
    "CVE-2025-30386",
    "CVE-2025-32704"
  );
  script_xref(name:"MSKB", value:"5002695");
  script_xref(name:"MSKB", value:"5002711");
  script_xref(name:"MSKB", value:"5002716");
  script_xref(name:"MSFT", value:"MS25-5002695");
  script_xref(name:"MSFT", value:"MS25-5002711");
  script_xref(name:"MSFT", value:"MS25-5002716");

  script_name(english:"Security Updates for Microsoft Office Products (May 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple remote code
execution vulnerabilities. An attacker can exploit these to bypass authentication and execute unauthorized arbitrary
commands.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002695");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002711");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002716");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates to address these issues:
  - KB5002695
  - KB5002711
  - KB5002716");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30377");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-30377");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS25-05';
var kbs = make_list(
  '5002695',
  '5002711',
  '5002716'
);
var severity = SECURITY_HOLE;

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office', kbs:kbs, bulletin:bulletin, severity:severity);

var constraints = [
  {'product' : 'Microsoft Office 2016', 'kb':'5002716', 'file':'graph.exe', 'fixed_version': '16.0.5500.1000'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002695', 'file':'gkexcel.dll', 'fixed_version': '16.0.5500.1001'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002711', 'file':'mso.dll', 'fixed_version': '16.0.5500.1002'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Office'
);
