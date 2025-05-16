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
  script_id(205300);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/12");

  script_cve_id("CVE-2024-37334");

  script_name(english:"Security Updates for Microsoft SQL Server OLE DB Driver (July 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server OLE DB Driver installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server OLE DB Driver installed on the remote host is missing a security update. It is, therefore, 
affected by a remote code execution vulnerability. An attacker could exploit the vulnerability by tricking an 
authenticated user (UI:R) into attempting to connect to a malicious SQL server database via a connection driver. 
This could result in the database returning malicious data that could cause arbitrary code execution on the client.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  # https://techcommunity.microsoft.com/t5/sql-server-blog/update-security-hotfix-released-for-ole-db-driver-for-sql-server/ba-p/4186782
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2166018b");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for the Microsoft SQL OLE DB Driver.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37334");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
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
  { 'min_version' : '18', 'fixed_version' : '18.7.4' },
  { 'min_version' : '19', 'fixed_version' : '19.3.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
