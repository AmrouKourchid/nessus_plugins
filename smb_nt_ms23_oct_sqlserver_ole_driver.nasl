#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(182968);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/12");

  script_cve_id("CVE-2023-36417", "CVE-2023-36728");
  script_xref(name:"IAVA", value:"2023-A-0541-S");

  script_name(english:"Security Updates for Microsoft SQL Server OLE DB Driver (October 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server OLE DB Driver installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server OLE DB Driver installed on the remote host is missing a security update. It is, therefore, 
affected by multiple vulnerabilities. 

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2023-36417)

  - A denial of service (DoS) vulnerability. An attacker can exploit this issue to cause the affected 
    component to deny system or application services. (CVE-2023-36728)
    
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  # https://learn.microsoft.com/en-us/sql/connect/oledb/release-notes-for-oledb-driver-for-sql-server?view=sql-server-ver16#1932
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3bfe241");
  # https://learn.microsoft.com/en-us/sql/connect/oledb/release-notes-for-oledb-driver-for-sql-server?view=sql-server-ver16#1867
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?570713a8");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for the Microsoft SQL OLE DB Driver.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36417");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_ole_db_driver_for_sql_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft OLE DB Driver for SQL Server", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
include('install_func.inc');
include('smb_hotfixes_fcheck.inc');

var app = 'Microsoft OLE DB Driver for SQL Server';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '18.6', 'fixed_version' : '18.6.7' },
  { 'min_version' : '19.3', 'fixed_version' : '19.3.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
