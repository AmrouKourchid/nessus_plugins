#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207067);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id(
    "CVE-2024-26186",
    "CVE-2024-26191",
    "CVE-2024-37335",
    "CVE-2024-37337",
    "CVE-2024-37338",
    "CVE-2024-37339",
    "CVE-2024-37340",
    "CVE-2024-37342",
    "CVE-2024-37966"
  );
  script_xref(name:"MSKB", value:"5042578");
  script_xref(name:"MSKB", value:"5042749");
  script_xref(name:"MSKB", value:"5042211");
  script_xref(name:"MSKB", value:"5042215");
  script_xref(name:"MSKB", value:"5042214");
  script_xref(name:"MSKB", value:"5042217");
  script_xref(name:"MSFT", value:"MS24-5042578");
  script_xref(name:"MSFT", value:"MS24-5042749");
  script_xref(name:"MSFT", value:"MS24-5042211");
  script_xref(name:"MSFT", value:"MS24-5042215");
  script_xref(name:"MSFT", value:"MS24-5042214");
  script_xref(name:"MSFT", value:"MS24-5042217");
  script_xref(name:"IAVA", value:"2024-A-0565-S");

  script_name(english:"Security Updates for Microsoft SQL Server (September 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is missing a security update. It is, therefore, 
affected by the following vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-26186, CVE-2024-26191, CVE-2024-37335, CVE-2024-37338, 
    CVE-2024-37339, CVE-2024-37340)

  - An information disclosure vulnerability. An authenticated, remote attacker can exploit this to disclose 
    sensitive database and file information. (CVE-2024-37337, CVE-2024-37342, CVE-2024-37966)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042578");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042749");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042211");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042215");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042214");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042217");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft SQL Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37340");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "smb_enum_services.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 1433, "Services/mssql", "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::mssql::get_app_info();

var constraints =
[
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.1000.169',
    'fixed_version'   : '2017.140.2060.1',
    'kb'              : '5042217'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.3006.16',
    'fixed_version'   : '2017.140.3475.1',
    'kb'              : '5042215'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.2000.5',
    'fixed_version'   : '2019.150.2120.1',
    'kb'              : '5042214 '
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.4003.23',
    'fixed_version'   : '2019.150.4390.2',
    'kb'              : '5042749'
  },
  {
    'product_version' : '2022',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2022.160.1000.6',
    'fixed_version'   : '2022.160.1125.1',
    'kb'              : '5042211'
  },
  {
    'product_version' : '2022',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2022.160.4003.1',
    'fixed_version'   : '2022.160.4140.3',
    'kb'              : '5042578'
  }
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  bulletin          : 'MS24-09',
  severity          : SECURITY_HOLE
);
