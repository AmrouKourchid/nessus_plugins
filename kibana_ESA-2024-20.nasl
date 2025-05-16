#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235658);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2024-11390");
  script_xref(name:"IAVB", value:"2025-B-0072");

  script_name(english:"Kibana 7.17.6 < 7.17.24 / 8.4.x < 8.12.0 XSS (ESA-2024-20)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Unrestricted upload of a file with dangerous type in Kibana can lead to arbitrary JavaScript execution in a victim's
browser (XSS) via crafted HTML and JavaScript files. The attacker must have access to the Synthetics app AND/OR have
access to write to the synthetics indices.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://discuss.elastic.co/t/kibana-7-17-24-and-8-12-0-security-update-esa-2024-20/377712
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7e92f0a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kibana version 7.17.24, 8.12.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11390");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:kibana");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kibana_web_detect.nbin");
  script_require_keys("installed_sw/Kibana");
  script_require_ports("services/www", 5601);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_install_count(app_name: 'Kibana', exit_if_zero: TRUE);

var port = get_http_port(default:5601);

var app_info = vcf::get_app_info(app:'Kibana', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '7.17.6', 'fixed_version' : '7.17.24' },
  { 'min_version' : '8.4.0', 'max_version':'8.11.4', 'fixed_version' : '8.12.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);