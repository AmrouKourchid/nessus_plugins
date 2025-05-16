#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193486);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/19");

  script_cve_id("CVE-2023-5072", "CVE-2024-26308");
  script_xref(name:"IAVA", value:"2024-A-0234-S");

  script_name(english:"Oracle Primavera Gateway (April 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera Gateway installed on the remote host are affected by multiple vulnerabilities as referenced in
the April 2024 CPU advisory.

  - Denial of Service in JSON-Java versions up to and including 20230618. A bug in the parser means that an
    input string of modest size can lead to indefinite amounts of memory being used. (CVE-2023-5072)

  - Allocation of Resources Without Limits or Throttling vulnerability in Apache Commons Compress. This issue
    affects Apache Commons Compress: from 1.21 before 1.26. Users are recommended to upgrade to version 1.26,
    which fixes the issue. (CVE-2024-26308)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2024 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5072");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.19' , 'fixed_display' : 'Upgrade to 19.12.19 with Patch 36383160' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.14' , 'fixed_display' : 'Upgrade to 20.12.14 with Patch 36383157' },
  { 'min_version' : '21.12.0', 'fixed_version' : '21.12.12', 'fixed_display' : 'Upgrade to 21.12.12 with Patch 36383139' },
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
