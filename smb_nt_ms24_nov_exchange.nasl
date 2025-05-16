#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211401);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/07");

  script_cve_id("CVE-2024-49040");
  script_xref(name:"MSFT", value:"MS24-5049233");
  script_xref(name:"MSKB", value:"5049233");
  script_xref(name:"IAVA", value:"2024-A-0732");

  script_name(english:"Security Updates for Microsoft Exchange Server (November 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing a security update. It is, therefore, affected by a
vulnerability as referenced in the March 2024 security bulletin.

  - Microsoft Exchange Server Spoofing Vulnerability (CVE-2024-49040)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5049233");
  # https://techcommunity.microsoft.com/blog/exchange/re-release-of-november-2024-exchange-server-security-update-packages/4341892
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f65d786");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB5049233
Please note that Microsoft has re-issued the November 2024 security update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49040");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server:2016");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server:2019");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::exchange::get_app_info();

var constraints = [
  { 'fixed_version' : '15.1.2507.044', 'product' : '2016', 'cu' : 23, 'unsupported_cu' : 22, 'kb' : '5049233' },
  { 'fixed_version' : '15.2.1258.039', 'product' : '2019', 'cu' : 13, 'unsupported_cu' : 12, 'kb' : '5049233' },
  { 'fixed_version' : '15.2.1544.014', 'product' : '2019', 'cu' : 14, 'unsupported_cu' : 12, 'kb' : '5049233' }
];

vcf::microsoft::exchange::check_version_and_report(
  app_info:app_info,
  bulletin:'MS24-11',
  constraints:constraints,
  severity:SECURITY_HOLE
);
