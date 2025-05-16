#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232287);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2025-25012");
  script_xref(name:"IAVB", value:"2025-B-0035-S");

  script_name(english:"Kibana 8.15.x < 8.17.3 (ESA_2025_06)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Kibana installed on the remote host is prior to 8.17.3. It is, therefore, affected by a vulnerability as
referenced in the ESA_2025_06 advisory.

  - Prototype pollution in Kibana leads to arbitrary code execution via a crafted file upload and specifically
    crafted HTTP requests.  In Kibana versions >= 8.15.0 and < 8.17.1, this is exploitable by users with the
    Viewer role. In Kibana versions 8.17.1 and 8.17.2 , this is only exploitable by users that have roles that
    contain all the following privileges: fleet-all, integrations-all, actions:execute-advanced-connectors
    (CVE-2025-25012)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://discuss.elastic.co/t/kibana-8-17-3-security-update-esa-2025-06/375441
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53693415");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kibana version 8.17.3 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:kibana");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kibana_web_detect.nbin");
  script_require_keys("installed_sw/Kibana");
  script_require_ports("Services/www", 5601);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app = 'Kibana';

get_install_count(app_name: 'Kibana', exit_if_zero: TRUE);

var port = get_http_port(default:5601);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '8.15.0', 'fixed_version' : '8.17.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);




vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);