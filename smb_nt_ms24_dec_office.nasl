#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212230);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2024-43600", "CVE-2024-49059", "CVE-2024-49065");
  script_xref(name:"MSKB", value:"4475587");
  script_xref(name:"MSKB", value:"5002661");
  script_xref(name:"MSFT", value:"MS24-4475587");
  script_xref(name:"MSFT", value:"MS24-5002661");
  script_xref(name:"IAVA", value:"2024-A-0807-S");

  script_name(english:"Security Updates for Microsoft Office Products (December 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. They are, therefore, affected by multiple vulnerabilities:

  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.
    (CVE-2024-43600, CVE-2024-49059)

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-49065)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4475587");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002661");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates to address these issues:
  - KB4475587
  - KB5002661");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43600");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-49059");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/10");

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

var bulletin = 'MS24-12';
var kbs = make_list(
  '4475587',
  '5002661'
);
var severity = SECURITY_WARNING;

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office', kbs:kbs, bulletin:bulletin, severity:severity);

var constraints = [
  {'product' : 'Microsoft Office 2016', 'kb':'4475587', 'file':'olicenseheartbeat.exe', 'fixed_version': '16.0.5478.1000'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002661', 'file':'mso.dll', 'fixed_version': '16.0.5478.1000'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Office'
);
