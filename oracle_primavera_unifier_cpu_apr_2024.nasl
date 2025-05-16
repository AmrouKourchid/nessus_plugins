#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193436);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2023-44487",
    "CVE-2023-50298",
    "CVE-2023-50386",
    "CVE-2024-25710",
    "CVE-2024-26308"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"IAVA", value:"2024-A-0234-S");

  script_name(english:"Oracle Primavera Unifier (April 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera Unifier installed on the remote host are affected by multiple vulnerabilities as referenced
in the April 2024 CPU advisory.

  - The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation
    can reset many streams quickly, as exploited in the wild in August through October 2023. (CVE-2023-44487)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Document
    Management (Apache Solr)). Supported versions that are affected are 19.12.0-19.12.16, 20.12.0-20.12.16,
    21.12.0-21.12.17, 22.12.0-22.12.12 and 23.12.0-23.12.3. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Primavera Unifier. Successful attacks of
    this vulnerability can result in unauthorized update, insert or delete access to some of Primavera
    Unifier accessible data as well as unauthorized read access to a subset of Primavera Unifier accessible
    data and unauthorized ability to cause a partial denial of service (partial DOS) of Primavera Unifier.
    (CVE-2023-50298)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Document
    Management (Apache Solr)). Supported versions that are affected are 19.12.0-19.12.16, 20.12.0-20.12.16,
    21.12.0-21.12.17, 22.12.0-22.12.12 and  23.12.0-23.12.3. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Primavera Unifier. Successful attacks of
    this vulnerability can result in unauthorized update, insert or delete access to some of Primavera
    Unifier accessible data as well as unauthorized read access to a subset of Primavera Unifier accessible
    data and unauthorized ability to cause a partial denial of service (partial DOS) of Primavera Unifier.
    (CVE-2023-50386)

  - Loop with Unreachable Exit Condition ('Infinite Loop') vulnerability in Apache Commons Compress. This
    issue affects Apache Commons Compress: from 1.3 through 1.25.0. Users are recommended to upgrade to
    version 1.26.0 which fixes the issue. (CVE-2024-25710)

  - Allocation of Resources Without Limits or Throttling vulnerability in Apache Commons Compress. This issue
    affects Apache Commons Compress: from 1.21 before 1.26. Users are recommended to upgrade to version 1.26,
    which fixes the issue. (CVE-2024-26308)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2024 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50386");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Solr Backup/Restore APIs RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/17");

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
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.16.11' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.16.15' },
  { 'min_version' : '21.12.0', 'fixed_version' : '21.12.17.2' },
  { 'min_version' : '22.12.0', 'fixed_version' : '22.12.13' },
  { 'min_version' : '23.12.0', 'fixed_version' : '23.12.4' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
