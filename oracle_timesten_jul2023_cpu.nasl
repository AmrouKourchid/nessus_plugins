#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188072);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/17");

  script_cve_id(
    "CVE-2020-29508",
    "CVE-2020-35163",
    "CVE-2020-35164",
    "CVE-2020-35166",
    "CVE-2020-35167",
    "CVE-2020-35168",
    "CVE-2020-35169",
    "CVE-2022-41881",
    "CVE-2022-41915",
    "CVE-2023-24532"
  );

  script_name(english:"Oracle TimesTen 22.x < 22.1.1.7.0 Multiple Vulnerabilities (July 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The Oracle TimesTen instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle TimesTen installed on the remote host is 22.x prior to 22.1.1.7.0.
It is, therefore, affected by multiple vulnerabilities as referenced in the July 2023 CPU advisory

  - Vulnerability in Oracle TimesTen In-Memory Database (component: TimesTen IMDB (Dell BSAFE Micro Edition Suite)). 
    Supported versions that are affected are 22.1.1.1.0 - 22.1.1.6.0. Difficult to exploit vulnerability allows 
    unauthenticated attacker with network access via multiple protocols to compromise Oracle TimesTen In-Memory 
    Database. (CVE-2020-35168)

  - Security-in-Depth issue in Oracle TimesTen In-Memory Database (component: EM TimesTen plug-in (Netty)). 
    (CVE-2022-41881)

  - Security-in-Depth issue in Oracle TimesTen In-Memory Database (component: EM TimesTen plug-in (Golang Go)).
    (CVE-2023-24532)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:timesten_in-memory_database");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_timesten_imdb_win_installed.nbin", "oracle_timesten_imdb_nix_installed.nbin");
  script_require_keys("installed_sw/Oracle TimesTen In-Memory Database");

  exit(0);
}

include('vcf.inc');

var app = 'Oracle TimesTen In-Memory Database';
var app_info = vcf::combined_get_app_info(app:app);

var constraints = [
  { 'min_version' : '22.0', 'fixed_version' : '22.1.1.7.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);