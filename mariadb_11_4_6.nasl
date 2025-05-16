#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235352);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/06");

  script_cve_id(
    "CVE-2023-52969",
    "CVE-2023-52970",
    "CVE-2023-52971",
    "CVE-2025-30693",
    "CVE-2025-30722"
  );

  script_name(english:"MariaDB 11.4.0 < 11.4.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 11.4.6. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-1146-release-notes advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.0-8.0.41, 8.4.0-8.4.4 and 9.0.0-9.2.0. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of
    MySQL Server accessible data. (CVE-2025-30693)

  - MariaDB Server 10.4 through 10.5.*, 10.6 through 10.6.*, 10.7 through 10.11.*, and 11.0 through 11.0.* can
    sometimes crash with an empty backtrace log. This may be related to make_aggr_tables_info and
    optimize_stage2. (CVE-2023-52969)

  - MariaDB Server 10.4 through 10.5.*, 10.6 through 10.6.*, 10.7 through 10.11.*, 11.0 through 11.0.*, and
    11.1 through 11.4.* crashes in Item_direct_view_ref::derived_field_transformer_for_where. (CVE-2023-52970)

  - MariaDB Server 10.10 through 10.11.* and 11.0 through 11.4.* crashes in JOIN::fix_all_splittings_in_plan.
    (CVE-2023-52971)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: Client: mysqldump). Supported
    versions that are affected are 8.0.0-8.0.41, 8.4.0-8.4.4 and 9.0.0-9.2.0. Difficult to exploit
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Client. Successful attacks of this vulnerability can result in unauthorized access to critical data
    or complete access to all MySQL Client accessible data as well as unauthorized update, insert or delete
    access to some of MySQL Client accessible data. (CVE-2025-30722)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-1146-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 11.4.6 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30693");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "mariadb_nix_installed.nbin", "mariadb_win_installed.nbin");
  script_require_keys("installed_sw/MariaDB");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MariaDB');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '11.4', 'fixed_version' : '11.4.6' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    require_paranoia:TRUE,
    severity:SECURITY_WARNING
);
