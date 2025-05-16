#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178484);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id(
    "CVE-2021-37533",
    "CVE-2022-48285",
    "CVE-2023-1370",
    "CVE-2023-20863"
  );
  script_xref(name:"IAVA", value:"2023-A-0362-S");
  script_xref(name:"IAVA", value:"2023-A-0559");

  script_name(english:"Oracle Primavera Gateway (Jul 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera Gateway installed on the remote host are affected by multiple vulnerabilities as referenced in
the July 2023 CPU advisory.

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (Apache Commons Net)). Supported versions that are affected are 18.8.0-18.8.15, 19.12.0-19.12.16,
    20.12.0-20.12.11 and 21.12.0-21.12.9. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via HTTP to compromise Primavera Gateway. Successful attacks require human interaction
    from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    access to critical data or complete access to all Primavera Gateway accessible data. (CVE-2021-37533)

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (JSZip)). Supported versions that are affected are 18.8.0-18.8.15, 19.12.0-19.12.16, 20.12.0-20.12.11 and
    21.12.0-21.12.9. Easily exploitable vulnerability allows unauthenticated attacker with network access via
    HTTP to compromise Primavera Gateway. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Primavera Gateway accessible data as well as unauthorized read
    access to a subset of Primavera Gateway accessible data and unauthorized ability to cause a partial denial
    of service (partial DOS) of Primavera Gateway. (CVE-2022-48285)

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (json-smart)). Supported versions that are affected are 18.8.0-18.8.15, 19.12.0-19.12.16, 20.12.0-20.12.11
    and 21.12.0-21.12.9. Easily exploitable vulnerability allows unauthenticated attacker with network access
    via HTTP to compromise Primavera Gateway. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Primavera Gateway.
    (CVE-2023-1370)

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (Spring Framework)). Supported versions that are affected are 18.8.0-18.8.15, 19.12.0-19.12.16,
    20.12.0-20.12.11 and 21.12.0-21.12.9. Easily exploitable vulnerability allows low privileged attacker with
    network access via HTTP to compromise Primavera Gateway. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Primavera
    Gateway. (CVE-2023-20863)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2023 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37533");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-48285");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/19");

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
  { 'min_version' : '18.8.0', 'fixed_version' : '18.8.16', 'fixed_display':'See vendor advisory' },
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.17' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.12' },
  { 'min_version' : '21.12.0', 'fixed_version' : '21.12.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
