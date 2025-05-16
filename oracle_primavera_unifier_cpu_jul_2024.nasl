#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202594);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id("CVE-2024-21742", "CVE-2024-22262", "CVE-2024-23944");
  script_xref(name:"IAVA", value:"2024-A-0422");
  script_xref(name:"IAVA", value:"2024-A-0449-S");

  script_name(english:"Oracle Primavera Unifier (Jul 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera Unifier installed on the remote host are affected by multiple vulnerabilities as referenced in
the July 2024 CPU advisory.

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component:
    Integration (Apache James MIME4J)). Supported versions that are affected are 19.12.0-19.12.16,
    20.12.0-20.12.16, 21.12.0-21.12.17, 22.12.0-22.12.13 and 23.12.0-23.12.6. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Primavera Unifier. Successful
    attacks of this vulnerability can result in unauthorized update, insert or delete access to some of
    Primavera Unifier accessible data. (CVE-2024-21742)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Document
    Management (Spring Framework)). Supported versions that are affected are 22.12.0-22.12.13 and
    23.12.0-23.12.6. Easily exploitable vulnerability allows low privileged attacker with network access via
    HTTP to compromise Primavera Unifier. Successful attacks require human interaction from a person other
    than the attacker. Successful attacks of this vulnerability can result in unauthorized update, insert or
    delete access to some of Primavera Unifier accessible data as well as unauthorized read access to a subset
    of Primavera Unifier accessible data. (CVE-2024-22262)

  - Information disclosure in persistent watchers handling in Apache ZooKeeper due to missing ACL check. It
    allows an attacker to monitor child znodes by attaching a persistent watcher (addWatch command) to a
    parent which the attacker has already access to. ZooKeeper server doesn't do ACL check when the persistent
    watcher is triggered and as a consequence, the full path of znodes that a watch event gets triggered upon
    is exposed to the owner of the watcher. It's important to note that only the path is exposed by this
    vulnerability, not the data of znode, but since znode path can contain sensitive information like user
    name or login ID, this issue is potentially critical. Users are recommended to upgrade to version 3.9.2,
    3.8.4 which fixes the issue. (CVE-2024-23944)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2024 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21742");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.16.12' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.16.16' },
  { 'min_version' : '21.12.0', 'fixed_version' : '21.12.17.3' },
  { 'min_version' : '22.12.0', 'fixed_version' : '22.12.14' },
  { 'min_version' : '23.12.0', 'fixed_version' : '23.12.7' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
