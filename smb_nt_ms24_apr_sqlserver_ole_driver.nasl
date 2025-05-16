#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(193161);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/12");

  script_cve_id(
    "CVE-2024-28906",
    "CVE-2024-28908",
    "CVE-2024-28909",
    "CVE-2024-28910",
    "CVE-2024-28911",
    "CVE-2024-28912",
    "CVE-2024-28913",
    "CVE-2024-28914",
    "CVE-2024-28915",
    "CVE-2024-28926",
    "CVE-2024-28927",
    "CVE-2024-28939",
    "CVE-2024-28940",
    "CVE-2024-28942",
    "CVE-2024-28944",
    "CVE-2024-28945",
    "CVE-2024-29044",
    "CVE-2024-29045",
    "CVE-2024-29046",
    "CVE-2024-29047",
    "CVE-2024-29048",
    "CVE-2024-29982",
    "CVE-2024-29983",
    "CVE-2024-29984",
    "CVE-2024-29985"
  );
  script_xref(name:"IAVA", value:"2024-A-0221-S");

  script_name(english:"Security Updates for Microsoft SQL Server OLE DB Driver (April 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server OLE DB Driver installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server OLE DB Driver installed on the remote host is missing a security update. It is, therefore, 
affected by multiple vulnerabilities: 

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-28906)

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-28908)

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-28909)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  # https://techcommunity.microsoft.com/t5/sql-server-blog/update-security-hotfixes-released-for-odbc-and-ole-db-drivers/ba-p/4107575
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27c5c1aa");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for the Microsoft SQL OLE DB Driver.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29985");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '18', 'fixed_version' : '18.7.2' },
  { 'min_version' : '19', 'fixed_version' : '19.3.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
