#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187745);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/10");

  script_cve_id("CVE-2022-37434");

  script_name(english:"Oracle TimesTen < 11.2.2.8.65, 22.x < 22.1.1.5.0 Buffer Overflow (January 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The Oracle TimesTen instance installed on the remote host is affected by a buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle TimesTen installed on the remote host is prior to 11.2.2.8.65 or 22.x prior to 22.1.1.5.0.
It is, therefore, affected by a buffer overflow vulnerability as referenced in the January 2023 CPU advisory

  - Vulnerability in Oracle TimesTen In-Memory Database (component: In-Memory Database (zlib)). Supported versions that 
    are affected are Prior to 11.2.2.8.65 and 22.x prior to 22.1.1.5.0. Easily exploitable vulnerability allows low
    privileged attacker with network access via Oracle Net to compromise Oracle TimesTen In-Memory Database. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash 
    (complete DOS) of Oracle TimesTen In-Memory Database.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/09");

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
  { 'min_version' : '0.0', 'fixed_version' : '11.2.2.8.65' },
  { 'min_version' : '18.0', 'fixed_version' : '22.1.1.5.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);