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
  script_id(193160);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2024-28929",
    "CVE-2024-28930",
    "CVE-2024-28931",
    "CVE-2024-28932",
    "CVE-2024-28933",
    "CVE-2024-28934",
    "CVE-2024-28935",
    "CVE-2024-28936",
    "CVE-2024-28937",
    "CVE-2024-28938",
    "CVE-2024-28941",
    "CVE-2024-28943",
    "CVE-2024-29043"
  );
  script_xref(name:"IAVA", value:"2024-A-0221-S");

  script_name(english:"Security Updates for Microsoft SQL Server ODBC Driver (April 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server driver installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-28929)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-28930)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-28931)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  # https://techcommunity.microsoft.com/t5/sql-server-blog/update-security-hotfixes-released-for-odbc-and-ole-db-drivers/ba-p/4107575
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27c5c1aa");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for the Microsoft SQL Driver.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28943");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-29043");

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

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_odbc_driver_for_sql_server_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
include('install_func.inc');
include('smb_hotfixes_fcheck.inc');

var app = 'Microsoft ODBC Driver for SQL Server';

var app_info = vcf::get_app_info(app:app);

var constraints = [
  { 'min_version' : '17.0',  'fixed_version' : '17.10.6' },
  { 'min_version' : '18.0',  'fixed_version' : '18.3.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);

