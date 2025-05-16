#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180007);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/09");

  script_cve_id("CVE-2023-38169");

  script_name(english:"Security Updates for Microsoft SQL Server ODBC Driver (August 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server driver installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability:

  - A remote code execution vulnerability. An attacker could exploit the vulnerability by 
    tricking an authenticated user into attempting to connect to a malicious SQL server 
    via OLEDB, which could result in the server receiving a malicious networking packet. 
    This could allow the attacker to execute code remotely on the client. (CVE-2023-38169)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38169");
  # https://learn.microsoft.com/en-us/sql/connect/odbc/windows/release-notes-odbc-sql-server-windows?view=sql-server-ver16#1822
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6326af5e");
  # https://learn.microsoft.com/en-us/sql/connect/odbc/windows/release-notes-odbc-sql-server-windows?view=sql-server-ver16#171041
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e496c8cb");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for the Microsoft SQL Driver.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_odbc_driver_for_sql_server_nix_installed.nbin", "microsoft_odbc_driver_for_sql_server_mac_installed.nbin", "microsoft_odbc_driver_for_sql_server_win_installed.nbin");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_microsoft.inc');

var app = 'Microsoft ODBC Driver for SQL Server';

var app_info = vcf::get_app_info(app:app);

var constraints = [
  { 'min_version' : '17.0', 'fixed_version' : '17.10.4.1',   'os' : 'unix'},
  { 'min_version' : '17.0', 'fixed_version' : '17.10.4.1',   'os' : 'win'},
  { 'min_version' : '17.0', 'fixed_version' : '17.10.4.1',   'os' : 'osx'},
  { 'min_version' : '18.0', 'fixed_version' : '18.2.2.1',    'os' : 'win'}, # 2.2.1 is correct
  { 'min_version' : '18.0', 'fixed_version' : '18.2.1.1',    'os' : 'unix'},
  { 'min_version' : '18.0', 'fixed_version' : '18.2.1.1',    'os' : 'osx'}
];

vcf::microsoft::odbc_driver::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
