#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183314);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id("CVE-2022-36944", "CVE-2022-45688", "CVE-2023-2976");
  script_xref(name:"IAVA", value:"2023-A-0556");
  script_xref(name:"IAVA", value:"2023-A-0559");
  script_xref(name:"IAVA", value:"2023-A-0563");

  script_name(english:"Oracle Primavera Gateway (October 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera Gateway installed on the remote host are affected by multiple vulnerabilities as referenced in
the October 2023 CPU advisory.

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering
    (component: Admin (JSON-java)). Supported versions that are affected are 19.12.0-19.12.17,
    20.12.0-20.12.12 and 21.12.0-21.12.10. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via HTTP to compromise Primavera Gateway. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of
    Primavera Gateway. (CVE-2022-45688)

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering
    (component: Admin (Google Guava)). Supported versions that are affected are 19.12.0-19.12.17,
    20.12.0-20.12.12 and 21.12.0-21.12.10. Easily exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Primavera Gateway executes to compromise Primavera Gateway.
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification
    access to critical data or all Primavera Gateway accessible data as well as unauthorized access to
    critical data or complete access to all Primavera Gateway accessible data. (CVE-2023-2976)

  - Security-in-Depth issue in the Primavera Gateway product of Oracle Construction and Engineering
    (component: Admin (Scala)). This vulnerability cannot be exploited in the context of this product.
    (CVE-2022-36944)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2023 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"CVSS vector from vendor advisory");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_gateway.nbin");
  script_require_keys("installed_sw/Oracle Primavera Gateway");
  script_require_ports("Services/www", 8006);

  exit(0);
}

include('vcf.inc');
include('http.inc');

get_install_count(app_name:'Oracle Primavera Gateway', exit_if_zero:TRUE);

var port = get_http_port(default:8006);

var app_info = vcf::get_app_info(app:'Oracle Primavera Gateway', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.18' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.13' },
  { 'min_version' : '21.12.0', 'fixed_version' : '21.12.11' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
