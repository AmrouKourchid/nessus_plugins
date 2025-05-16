#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216604);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/24");

  script_cve_id(
    "CVE-2024-20701",
    "CVE-2024-21303",
    "CVE-2024-21308",
    "CVE-2024-21317",
    "CVE-2024-21331",
    "CVE-2024-21332",
    "CVE-2024-21333",
    "CVE-2024-21335",
    "CVE-2024-21373",
    "CVE-2024-21398",
    "CVE-2024-21414",
    "CVE-2024-21415",
    "CVE-2024-21425",
    "CVE-2024-21428",
    "CVE-2024-21449",
    "CVE-2024-28928",
    "CVE-2024-35256",
    "CVE-2024-35271",
    "CVE-2024-35272",
    "CVE-2024-37318",
    "CVE-2024-37319",
    "CVE-2024-37320",
    "CVE-2024-37321",
    "CVE-2024-37322",
    "CVE-2024-37323",
    "CVE-2024-37324",
    "CVE-2024-37326",
    "CVE-2024-37327",
    "CVE-2024-37328",
    "CVE-2024-37329",
    "CVE-2024-37330",
    "CVE-2024-37331",
    "CVE-2024-37332",
    "CVE-2024-37333",
    "CVE-2024-37334",
    "CVE-2024-37336",
    "CVE-2024-38087",
    "CVE-2024-38088"
  );
  script_xref(name:"MSKB", value:"5040942");
  script_xref(name:"MSKB", value:"5040939");
  script_xref(name:"MSKB", value:"5040936");
  script_xref(name:"MSKB", value:"5040986");
  script_xref(name:"MSKB", value:"5040944");
  script_xref(name:"MSKB", value:"5040948");
  script_xref(name:"MSKB", value:"5040940");
  script_xref(name:"MSKB", value:"5040946");
  script_xref(name:"MSFT", value:"MS24-5040942");
  script_xref(name:"MSFT", value:"MS24-5040939");
  script_xref(name:"MSFT", value:"MS24-5040936");
  script_xref(name:"MSFT", value:"MS24-5040986");
  script_xref(name:"MSFT", value:"MS24-5040944");
  script_xref(name:"MSFT", value:"MS24-5040948");
  script_xref(name:"MSFT", value:"MS24-5040940");
  script_xref(name:"MSFT", value:"MS24-5040946");

  script_name(english:"Security Updates for Microsoft SQL Server (July 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-20701,
    CVE-2024-21303, CVE-2024-21308, CVE-2024-21317,
    CVE-2024-21331, CVE-2024-21332, CVE-2024-21333,
    CVE-2024-21335, CVE-2024-21373, CVE-2024-21398,
    CVE-2024-21414, CVE-2024-21415, CVE-2024-21425,
    CVE-2024-21428, CVE-2024-21449, CVE-2024-28928,
    CVE-2024-35256, CVE-2024-35271, CVE-2024-35272,
    CVE-2024-37318, CVE-2024-37319, CVE-2024-37320,
    CVE-2024-37321, CVE-2024-37322, CVE-2024-37323,
    CVE-2024-37324, CVE-2024-37326, CVE-2024-37327,
    CVE-2024-37328, CVE-2024-37329, CVE-2024-37330,
    CVE-2024-37331, CVE-2024-37332, CVE-2024-37333,
    CVE-2024-37334, CVE-2024-37336, CVE-2024-38087,
    CVE-2024-38088)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040942");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040939");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040936");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040986");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040944");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040948");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040940");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040946");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5040942
  -KB5040939
  -KB5040936
  -KB5040986
  -KB5040944
  -KB5040948
  -KB5040940
  -KB5040946");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38088");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'fixed_version'   : '2015.131.6441.1',
    'kb'              : '5040946'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.7000.253',
    'fixed_version'   : '2015.131.7037.1',
    'kb'              : '5040944'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.1000.169',
    'fixed_version'   : '2017.140.2056.2',
    'kb'              : '5040942'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.3006.16',
    'fixed_version'   : '2017.140.3471.2',
    'kb'              : '5040940'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.2000.5',
    'fixed_version'   : '2019.150.2116.2',
    'kb'              : '5040986'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.4003.23',
    'fixed_version'   : '2019.150.4382.1',
    'kb'              : '5040948'
  },
  {
    'product_version' : '2022',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2022.160.1000.6',
    'fixed_version'   : '2022.160.1121.4',
    'kb'              : '5040936'
  },
  {
    'product_version' : '2022',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2022.160.4003.1',
    'fixed_version'   : '2022.160.4131.2',
    'kb'              : '5040939'
  }
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  bulletin          : 'MS24-07',
  severity          : SECURITY_HOLE
);
