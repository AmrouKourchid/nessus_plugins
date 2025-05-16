#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181309);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/06");

  script_cve_id(
    "CVE-2023-36744",
    "CVE-2023-36745",
    "CVE-2023-36756",
    "CVE-2023-36757",
    "CVE-2023-36777"
  );
  script_xref(name:"MSFT", value:"MS23-5030524");
  script_xref(name:"MSKB", value:"5030524");
  script_xref(name:"IAVA", value:"2023-A-0477-S");

  script_name(english:"Security Updates for Microsoft Exchange Server (September 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities as referenced in the Sep, 2023 security bulletin.

  - Microsoft Exchange Server Spoofing Vulnerability (CVE-2023-36757)

  - Microsoft Exchange Server Remote Code Execution Vulnerability (CVE-2023-36744, CVE-2023-36745,
    CVE-2023-36756)

  - Microsoft Exchange Server Information Disclosure Vulnerability (CVE-2023-36777)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB5030524");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36757");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server:2016");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server:2019");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::exchange::get_app_info();

var constraints = [
  { 'fixed_version' : '15.1.2507.32', 'product' : '2016', 'cu' : 23, 'unsupported_cu' : 22, 'kb' : '5030524' },
  { 'fixed_version' : '15.2.1118.37', 'product' : '2019', 'cu' : 12, 'unsupported_cu' : 11, 'kb' : '5030524' },
  { 'fixed_version' : '15.2.1258.25', 'product' : '2019', 'cu' : 13, 'unsupported_cu' : 11, 'kb' : '5030524' }
];

vcf::microsoft::exchange::check_version_and_report(
  app_info:app_info,
  bulletin:'MS23-09',
  constraints:constraints,
  severity:SECURITY_HOLE
);
