#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(182956);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/12");

  script_cve_id("CVE-2023-36728");
  script_xref(name:"MSKB", value:"5029184");
  script_xref(name:"MSKB", value:"5029185");
  script_xref(name:"MSKB", value:"5029186");
  script_xref(name:"MSKB", value:"5029187");
  script_xref(name:"MSKB", value:"5029375");
  script_xref(name:"MSKB", value:"5029376");
  script_xref(name:"MSKB", value:"5029377");
  script_xref(name:"MSKB", value:"5029378");
  script_xref(name:"MSKB", value:"5029379");
  script_xref(name:"MSKB", value:"5029503");
  script_xref(name:"MSFT", value:"MS23-5029184");
  script_xref(name:"MSFT", value:"MS23-5029185");
  script_xref(name:"MSFT", value:"MS23-5029186");
  script_xref(name:"MSFT", value:"MS23-5029187");
  script_xref(name:"MSFT", value:"MS23-5029375");
  script_xref(name:"MSFT", value:"MS23-5029376");
  script_xref(name:"MSFT", value:"MS23-5029377");
  script_xref(name:"MSFT", value:"MS23-5029378");
  script_xref(name:"MSFT", value:"MS23-5029379");
  script_xref(name:"MSFT", value:"MS23-5029503");
  script_xref(name:"IAVA", value:"2023-A-0541-S");

  script_name(english:"Security Updates for Microsoft SQL Server (October 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability:

  - A Denial of Service vulnerability. An attacker could impact availability of the service resulting in Denial 
    of Service (DoS) (CVE-2023-36728)
    
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029184");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029185");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029186");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029187");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029375");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029376");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029377");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029378");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029379");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029503");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft SQL Server.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36728");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2014.120.6024.0',
    'fixed_version'   : '2014.120.6179.1',
    'kb'              : '5029184'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2014.120.6205.1',
    'fixed_version'   : '2014.120.6449.1',
    'kb'              : '5029185' 
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.6300.2',
    'fixed_version'   : '2015.131.6435.1',
    'kb'              : '5029186'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.7000.253',
    'fixed_version'   : '2015.131.7029.3',
    'kb'              : '5029187'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.1000.169',
    'fixed_version'   : '2017.140.2052.1',
    'kb'              : '5029375'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.3006.16',
    'fixed_version'   : '2017.140.3465.1',
    'kb'              : '5029376'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.2000.5',
    'fixed_version'   : '2019.150.2104.1',
    'kb'              : '5029377'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.4003.23',
    'fixed_version'   : '2019.150.4326.1',
    'kb'              : '5029378'
  },
  {
    'product_version' : '2022',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2022.160.1000.6',
    'fixed_version'   : '2022.160.1105.1',
    'kb'              : '5029379'
  },
  {
    'product_version' : '2022',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2022.160.4003.1',
    'fixed_version'   : '2022.160.4080.1',
    'kb'              : '5029503'
  }
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  bulletin          : 'MS23-10',
  severity          : SECURITY_WARNING
);