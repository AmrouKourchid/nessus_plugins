##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163502);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/29");

  script_cve_id(
    "CVE-2018-25032",
    "CVE-2022-32084",
    "CVE-2022-32091",
    "CVE-2022-38791",
    "CVE-2023-5157"
  );

  script_name(english:"MariaDB 10.3.0 < 10.3.36 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.3.36. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-10-3-36-release-notes advisory.

  - zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many
    distant matches. (CVE-2018-25032)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component sub_select.
    (CVE-2022-32084)

  - MariaDB v10.7 was discovered to contain an use-after-poison in in __interceptor_memset at
    /libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc. (CVE-2022-32091)

  - In MariaDB before 10.9.2, compress_write in extra/mariabackup/ds_compress.cc does not release data_mutex
    upon a stream write failure, which allows local users to trigger a deadlock. (CVE-2022-38791)

  - A vulnerability was found in MariaDB. An OpenVAS port scan on ports 3306 and 4567 allows a malicious
    remote client to cause a denial of service. (CVE-2023-5157)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-10-3-36-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.3.36 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32091");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-5157");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "mariadb_nix_installed.nbin", "mariadb_win_installed.nbin");
  script_require_keys("installed_sw/MariaDB");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MariaDB');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '10.3', 'fixed_version' : '10.3.36' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    require_paranoia:TRUE,
    severity:SECURITY_WARNING
);
