##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(135701);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2020-2759",
    "CVE-2020-2760",
    "CVE-2020-2762",
    "CVE-2020-2763",
    "CVE-2020-2765",
    "CVE-2020-2780",
    "CVE-2020-2804",
    "CVE-2020-2812",
    "CVE-2020-2892",
    "CVE-2020-2893",
    "CVE-2020-2895",
    "CVE-2020-2896",
    "CVE-2020-2897",
    "CVE-2020-2898",
    "CVE-2020-2901",
    "CVE-2020-2903",
    "CVE-2020-2904",
    "CVE-2020-2921",
    "CVE-2020-2923",
    "CVE-2020-2924",
    "CVE-2020-2925",
    "CVE-2020-2926",
    "CVE-2020-2928",
    "CVE-2020-2930",
    "CVE-2021-2006",
    "CVE-2021-2007",
    "CVE-2021-2009",
    "CVE-2021-2016",
    "CVE-2021-2019",
    "CVE-2021-2144"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"IAVA", value:"2021-A-0193-S");
  script_xref(name:"IAVA", value:"2021-A-0038-S");
  script_xref(name:"IAVA", value:"2020-A-0143-S");

  script_name(english:"MySQL 8.0.x < 8.0.20 Multiple Vulnerabilities (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 8.0.x prior to 8.0.20. It is, therefore, affected by multiple
vulnerabilities, including the following, as noted in the April 2020 Critical Patch Update advisory:

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Parser). Supported versions
  that are affected are 5.7.29 and prior and 8.0.19 and prior. Easily exploitable vulnerability allows high
  privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of
  this vulnerability can result in takeover of MySQL Server. (CVE-2021-2144)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Memcached). Supported versions
  that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. This difficult to exploit
  vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server.
  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
  repeatable crash (complete DOS) of MySQL Server. (CVE-2020-2804)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Replication). Supported
  versions that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. This easily exploitable
  vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
  repeatable crash (complete DOS) of MySQL Server. (CVE-2020-2763)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html#AppendixMSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html#AppendixMSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html#AppendixMSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 8.0.20 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2144");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "mysql_version_local.nasl", "mysql_win_installed.nbin", "macosx_mysql_installed.nbin");
  script_require_keys("installed_sw/MySQL Server");

  exit(0);
}


include('vcf_extras_mysql.inc');

var app_info = vcf::mysql::combined_get_app_info();

vcf::check_all_backporting(app_info:app_info);

var constraints = [{ 'min_version' : '8.0.0', 'fixed_version' : '8.0.20'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
