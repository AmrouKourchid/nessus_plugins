#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189185);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2023-2976", "CVE-2023-42503", "CVE-2023-44981");
  script_xref(name:"IAVA", value:"2024-A-0026-S");

  script_name(english:"Oracle Primavera Unifier (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera Unifier installed on the remote host are affected by multiple vulnerabilities as referenced in
the January 2024 CPU advisory.

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Platform
    (Google Guava)). Supported versions that are affected are 19.12.0-19.12.16, 20.12.0-20.12.16,
    21.12.0-21.12.17 and 22.12.0-22.12.11. Easily exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Primavera Unifier executes to compromise Primavera Unifier.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Primavera Unifier accessible data as well as unauthorized update, insert or delete access to
    some of Primavera Unifier accessible data. (CVE-2023-2976)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Platform
    (Apache Commons Compress)). Supported versions that are affected are 19.12.0-19.12.16, 20.12.0-20.12.16,
    21.12.0-21.12.17 and 22.12.0-22.12.11. Easily exploitable vulnerability allows unauthenticated attacker
    with logon to the infrastructure where Primavera Unifier executes to compromise Primavera Unifier.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS)
    of Primavera Unifier. (CVE-2023-42503)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Document
    Manager (Apache ZooKeeper)). Supported versions that are affected are 19.12.0-19.12.16, 20.12.0-20.12.16,
    21.12.0-21.12.17 and 22.12.0-22.12.11. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via HTTP to compromise Primavera Unifier. Successful attacks of this vulnerability can
    result in unauthorized read access to a subset of Primavera Unifier accessible data. (CVE-2023-44981)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44981");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_unifier.nbin");
  script_require_keys("installed_sw/Oracle Primavera Unifier", "www/weblogic");
  script_require_ports("Services/www", 8002);

  exit(0);
}

include('vcf.inc');
include('http.inc');

get_install_count(app_name:'Oracle Primavera Unifier', exit_if_zero:TRUE);

var port = get_http_port(default:8002);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

var app_info = vcf::get_app_info(app:'Oracle Primavera Unifier', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.16.10' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.16.14' },
  { 'min_version' : '21.12.0', 'fixed_version' : '21.12.17.1' },
  { 'min_version' : '22.12.0', 'fixed_version' : '22.12.12' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
