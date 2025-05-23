#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197194);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/16");

  script_cve_id("CVE-2024-21096");

  script_name(english:"MariaDB 10.5.0 < 10.5.25");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.5.25. It is, therefore, affected by a vulnerability
as referenced in the mdb-10525-rn advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Client: mysqldump). Supported
    versions that are affected are 8.0.36 and prior and 8.3.0 and prior. Difficult to exploit vulnerability
    allows unauthenticated attacker with logon to the infrastructure where MySQL Server executes to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of MySQL Server accessible data as well as unauthorized read access to a subset of MySQL
    Server accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of
    MySQL Server. (CVE-2024-21096)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10525-rn");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.5.25 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21096");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "mariadb_nix_installed.nbin", "mariadb_win_installed.nbin");
  script_require_keys("installed_sw/MariaDB");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MariaDB');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '10.5', 'fixed_version' : '10.5.25' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    require_paranoia:TRUE,
    severity:SECURITY_NOTE
);
