#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(161054);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/06");

  script_cve_id("CVE-2022-21978");
  script_xref(name:"MSKB", value:"5014260");
  script_xref(name:"MSKB", value:"5014261");
  script_xref(name:"MSFT", value:"MS22-5014260");
  script_xref(name:"MSFT", value:"MS22-5014261");
  script_xref(name:"IAVA", value:"2022-A-0194-S");

  script_name(english:"Security Updates for Exchange (May 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing security
updates. It is, therefore, affected by an elevation of privilege vulnerability.
An attacker can exploit this to gain elevated privileges.

Note: Additional security hardening measures, described in the kb article, are
required in addition to the installation of the update. Nessus is unable to
determine if these measures have been applied.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5014260");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5014261");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
-KB5014260
-KB5014261");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21978");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server:2016");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server:2019");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::exchange::get_app_info();

var constraints =
[
  {
    'product' : '2013',
    'cu': 23,
    'unsupported_cu': 22,
    'fixed_version': '15.0.1497.36',
    'kb': '5014260'
  },
  {
    'product' : '2016',
    'cu': 22,
    'unsupported_cu': 21,
    'fixed_version': '15.1.2375.28',
    'kb': '5014261'
  },
  {
    'product': '2016',
    'cu': 23,
    'unsupported_cu': 21,
    'fixed_version': '15.1.2507.9',
    'kb': '5014261'
  },
  {
    'product' : '2019',
    'cu': 11,
    'unsupported_cu': 10,
    'fixed_version': '15.2.986.26',
    'kb': '5014261'
  },
  {
    'product' : '2019',
    'cu': 12,
    'unsupported_cu': 10,
    'fixed_version': '15.2.1118.9',
    'kb': '5014261'
  }
];

vcf::microsoft::exchange::check_version_and_report(
  app_info:app_info,
  bulletin:'MS22-05',
  constraints:constraints,
  severity:SECURITY_HOLE
);
