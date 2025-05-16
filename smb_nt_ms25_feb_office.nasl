#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216125);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id(
    "CVE-2025-21383",
    "CVE-2025-21387",
    "CVE-2025-21390",
    "CVE-2025-21392"
  );
  script_xref(name:"MSKB", value:"5002179");
  script_xref(name:"MSKB", value:"5002684");
  script_xref(name:"MSKB", value:"5002686");
  script_xref(name:"MSFT", value:"MS25-5002179");
  script_xref(name:"MSFT", value:"MS25-5002684");
  script_xref(name:"MSFT", value:"MS25-5002686");
  script_xref(name:"IAVA", value:"2025-A-0105");
  script_xref(name:"IAVA", value:"2025-A-0104-S");

  script_name(english:"Security Updates for Microsoft Office Products (February 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - An information disclosure vulnerability. An attacker can exploit this to disclose potentially sensitive
    information. (CVE-2025-21383)

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2025-21387, CVE-2025-21390, CVE-2025-21392)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002179");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002684");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002686");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates to address these issues:
  - KB5002179
  - KB5002684
  - KB5002686");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/11");

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

var bulletin = 'MS25-02';
var kbs = make_list(
  '5002179',
  '5002684',
  '5002686'
);
var severity = SECURITY_HOLE;

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office', kbs:kbs, bulletin:bulletin, severity:severity);

var constraints = [
  {'product' : 'Microsoft Office 2016', 'kb':'5002684', 'file':'graph.exe', 'fixed_version': '16.0.5487.1000'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002179', 'file':'gkexcel.dll', 'fixed_version': '16.0.5487.1000'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002686', 'file':'mso.dll', 'fixed_version': '16.0.5487.1000'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Office'
);
