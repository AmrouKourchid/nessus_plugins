#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211472);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/18");

  script_cve_id(
    "CVE-2024-38255",
    "CVE-2024-43459",
    "CVE-2024-43462",
    "CVE-2024-48993",
    "CVE-2024-48994",
    "CVE-2024-48995",
    "CVE-2024-48996",
    "CVE-2024-48997",
    "CVE-2024-48998",
    "CVE-2024-48999",
    "CVE-2024-49000",
    "CVE-2024-49001",
    "CVE-2024-49002",
    "CVE-2024-49003",
    "CVE-2024-49004",
    "CVE-2024-49005",
    "CVE-2024-49006",
    "CVE-2024-49007",
    "CVE-2024-49008",
    "CVE-2024-49009",
    "CVE-2024-49010",
    "CVE-2024-49011",
    "CVE-2024-49012",
    "CVE-2024-49013",
    "CVE-2024-49014",
    "CVE-2024-49015",
    "CVE-2024-49016",
    "CVE-2024-49017",
    "CVE-2024-49018",
    "CVE-2024-49021",
    "CVE-2024-49043"
  );
  script_xref(name:"MSKB", value:"5046855");
  script_xref(name:"MSKB", value:"5046856");
  script_xref(name:"MSKB", value:"5046857");
  script_xref(name:"MSKB", value:"5046858");
  script_xref(name:"MSKB", value:"5046859");
  script_xref(name:"MSKB", value:"5046860");
  script_xref(name:"MSKB", value:"5046861");
  script_xref(name:"MSKB", value:"5046862");
  script_xref(name:"MSFT", value:"MS24-5046855");
  script_xref(name:"MSFT", value:"MS24-5046856");
  script_xref(name:"MSFT", value:"MS24-5046857");
  script_xref(name:"MSFT", value:"MS24-5046858");
  script_xref(name:"MSFT", value:"MS24-5046859");
  script_xref(name:"MSFT", value:"MS24-5046860");
  script_xref(name:"MSFT", value:"MS24-5046861");
  script_xref(name:"MSFT", value:"MS24-5046862");
  script_xref(name:"IAVA", value:"2024-A-0731");

  script_name(english:"Security Updates for Microsoft SQL Server (November 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-38255,
    CVE-2024-43459, CVE-2024-43462, CVE-2024-48993,
    CVE-2024-48994, CVE-2024-48995, CVE-2024-48996,
    CVE-2024-48997, CVE-2024-48998, CVE-2024-48999,
    CVE-2024-49000, CVE-2024-49001, CVE-2024-49002,
    CVE-2024-49003, CVE-2024-49004, CVE-2024-49005,
    CVE-2024-49006, CVE-2024-49007, CVE-2024-49008,
    CVE-2024-49009, CVE-2024-49010, CVE-2024-49011,
    CVE-2024-49012, CVE-2024-49013, CVE-2024-49014,
    CVE-2024-49015, CVE-2024-49016, CVE-2024-49017,
    CVE-2024-49018, CVE-2024-49021, CVE-2024-49043)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046855");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046856");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046857");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046858");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046859");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046860");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046861");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046862");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft SQL Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

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
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.6300.2',
    'fixed_version'   : '2015.131.6455.2',
    'kb'              : '5046855'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.7000.253',
    'fixed_version'   : '2015.131.7050.2',
    'kb'              : '5046856'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.1000.169',
    'fixed_version'   : '2017.140.2070.1',
    'kb'              : '5046857'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.3006.16',
    'fixed_version'   : '2017.140.3485.1',
    'kb'              : '5046858'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.2000.5',
    'fixed_version'   : '2019.150.2130.3',
    'kb'              : '5046859'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.4003.23',
    'fixed_version'   : '2019.150.4410.1',
    'kb'              : '5046860'
  },
  {
    'product_version' : '2022',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2022.160.1000.6',
    'fixed_version'   : '2022.160.1135.2',
    'kb'              : '5046861'
  },
  {
    'product_version' : '2022',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2022.160.4003.1',
    'fixed_version'   : '2022.160.4155.4',
    'kb'              : '5046862'
  }
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  bulletin          : 'MS24-11',
  severity          : SECURITY_HOLE
);
