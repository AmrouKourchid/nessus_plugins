#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118236);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2016-9843",
    "CVE-2018-3133",
    "CVE-2018-3137",
    "CVE-2018-3143",
    "CVE-2018-3144",
    "CVE-2018-3145",
    "CVE-2018-3155",
    "CVE-2018-3156",
    "CVE-2018-3161",
    "CVE-2018-3162",
    "CVE-2018-3170",
    "CVE-2018-3171",
    "CVE-2018-3173",
    "CVE-2018-3174",
    "CVE-2018-3182",
    "CVE-2018-3185",
    "CVE-2018-3186",
    "CVE-2018-3187",
    "CVE-2018-3195",
    "CVE-2018-3200",
    "CVE-2018-3203",
    "CVE-2018-3212",
    "CVE-2018-3247",
    "CVE-2018-3251",
    "CVE-2018-3276",
    "CVE-2018-3277",
    "CVE-2018-3278",
    "CVE-2018-3279",
    "CVE-2018-3280",
    "CVE-2018-3282",
    "CVE-2018-3283",
    "CVE-2018-3284",
    "CVE-2018-3285",
    "CVE-2018-3286",
    "CVE-2019-2743",
    "CVE-2019-2746",
    "CVE-2019-2747"
  );
  script_bugtraq_id(
    95131,
    105594,
    105600,
    105607,
    105610,
    105612,
    109239
  );

  script_name(english:"MySQL 8.0.x < 8.0.13 Multiple Vulnerabilities (Oct 2018 CPU) (Jul 2019 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 8.0.x prior to
8.0.13. It is, therefore, affected by multiple vulnerabilities as
noted in the October 2018 Critical Patch Update advisory. Please
consult the CVRF details for the applicable CVEs for additional
information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-13.html");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?705136d8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 8.0.13 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9843");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "mysql_version_local.nasl", "mysql_win_installed.nbin", "macosx_mysql_installed.nbin");
  script_require_keys("installed_sw/MySQL Server");

  exit(0);
}

include('vcf_extras_mysql.inc');

var app_info = vcf::mysql::combined_get_app_info();

vcf::check_all_backporting(app_info:app_info);

var constraints = [{ 'min_version' : '8.0.0', 'fixed_version' : '8.0.13'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
