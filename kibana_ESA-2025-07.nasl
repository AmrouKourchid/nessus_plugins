#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235659);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-25014");
  script_xref(name:"IAVB", value:"2025-B-0072");

  script_name(english:"Kibana 8.3.0 < 8.17.6 / 8.18.0 < 8.18.1 / 9.0.0 < 9.0.1 Arbitrary Code Execution (ESA-2025-07)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A Prototype pollution vulnerability in Kibana leads to arbitrary code execution via crafted HTTP requests to machine
learning and reporting endpoints.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://discuss.elastic.co/t/kibana-8-17-6-8-18-1-or-9-0-1-security-update-esa-2025-07/377868
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c2e226f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kibana version 8.17.6, 8.18.1, 9.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-25014");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:kibana");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kibana_web_detect.nbin");
  script_require_keys("installed_sw/Kibana", "Settings/ParanoidReport");
  script_require_ports("services/www", 5601);

  exit(0);
}

include('http.inc');
include('vcf.inc');

# we cannot check for workarounds on this product
if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_install_count(app_name: 'Kibana', exit_if_zero: TRUE);

var port = get_http_port(default:5601);

var app_info = vcf::get_app_info(app:'Kibana', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '8.3.0', 'fixed_version' : '8.17.6' },
  { 'min_version' : '8.18.0', 'fixed_version' : '8.18.1' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.1' },
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);