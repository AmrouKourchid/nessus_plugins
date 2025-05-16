#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234550);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2024-7254", "CVE-2024-47554", "CVE-2024-57699");
  script_xref(name:"IAVA", value:"2025-A-0265");

  script_name(english:"Oracle Primavera Gateway (Apr 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera Gateway installed on the remote host are affected by multiple vulnerabilities as referenced
in the April 2025 CPU advisory.

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (Google Protobuf-Java)). Supported versions that are affected are 20.12.0-20.12.17 and 21.12.0-21.12.15.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Primavera Gateway. Successful attacks of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete DOS) of Primavera Gateway. (CVE-2024-7254)

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (json-smart)). Supported versions that are affected are 20.12.0-20.12.17 and 21.12.0-21.12.15. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Primavera Gateway. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    hang or frequently repeatable crash (complete DOS) of Primavera Gateway. (CVE-2024-57699)

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin
    (Apache Commons IO)). Supported versions that are affected are 20.12.0-20.12.17 and 21.12.0-21.12.15.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Primavera Gateway. Successful attacks require human interaction from a person other than the
    attacker. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial
    denial of service (partial DOS) of Primavera Gateway. (CVE-2024-47554)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7254");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-57699");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.17', 'fixed_display' : '20.12.17 (Patch 37735325)' },
  { 'min_version' : '21.12.0', 'fixed_version' : '21.12.15', 'fixed_display' : '21.12.15 (Patch 37735290)' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
