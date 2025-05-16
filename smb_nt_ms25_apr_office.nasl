#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234041);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id(
    "CVE-2025-26642",
    "CVE-2025-27745",
    "CVE-2025-27746",
    "CVE-2025-27748",
    "CVE-2025-27749",
    "CVE-2025-27752",
    "CVE-2025-29791",
    "CVE-2025-29792",
    "CVE-2025-29816"
  );
  script_xref(name:"MSKB", value:"4484432");
  script_xref(name:"MSKB", value:"5002573");
  script_xref(name:"MSKB", value:"5002588");
  script_xref(name:"MSKB", value:"5002700");
  script_xref(name:"MSKB", value:"5002703");
  script_xref(name:"MSFT", value:"MS25-4484432");
  script_xref(name:"MSFT", value:"MS25-5002573");
  script_xref(name:"MSFT", value:"MS25-5002588");
  script_xref(name:"MSFT", value:"MS25-5002700");
  script_xref(name:"MSFT", value:"MS25-5002703");
  script_xref(name:"IAVA", value:"2025-A-0244");
  script_xref(name:"IAVA", value:"2025-A-0245");
  script_xref(name:"IAVA", value:"2025-A-0246");

  script_name(english:"Security Updates for Microsoft Office Products (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. They are, therefore, affected by multiple vulnerabilities:

  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.
    (CVE-2025-29792)

  - A security feature bypass vulnerability exists. An attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising the integrity of the system/application.
    (CVE-2025-29816)

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2025-26642, CVE-2025-27745, CVE-2025-27746, CVE-2025-27748,
    CVE-2025-27749, CVE-2025-27752, CVE-2025-29791)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484432");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002573");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002588");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002700");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002703");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates to address these issues:
  - KB4484432
  - KB5002573
  - KB5002588
  - KB5002700
  - KB5002703");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26642");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var bulletin = 'MS25-04';
var kbs = make_list(
  '4484432',
  '5002573',
  '5002588',
  '5002700',
  '5002703'
);
var severity = SECURITY_HOLE;

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office', kbs:kbs, bulletin:bulletin, severity:severity);

var constraints = [
  {'product' : 'Microsoft Office 2016', 'kb':'5002588', 'file':'aceexcl.dll', 'fixed_version': '16.0.5404.1000'},
  {'product' : 'Microsoft Office 2016', 'kb':'4484432', 'file':'chart.dll', 'fixed_version': '16.0.5495.1000'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002703', 'file':'graph.exe', 'fixed_version': '16.0.5495.1000'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002700', 'file':'mso.dll', 'fixed_version': '16.0.5495.1002'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002573', 'file':'mso30win32client.dll', 'fixed_version': '16.0.5495.1002'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Office'
);
