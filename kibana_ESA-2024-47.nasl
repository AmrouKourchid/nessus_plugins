#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235660);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-25016");
  script_xref(name:"IAVB", value:"2025-B-0072");

  script_name(english:"Kibana 7.17.x < 7.17.19 / 8.0.x < 8.13.0 File Upload (ESA-2024-47)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Unrestricted file upload in Kibana allows an authenticated attacker to compromise software integrity by uploading a
crafted malicious file due to insufficient server-side validation.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://discuss.elastic.co/t/kibana-7-17-19-and-8-13-0-security-update-esa-2024-47/377711
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39aa694e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kibana version 7.17.19, 8.13.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-25016");

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
  { 'min_version' : '7.17.0', 'fixed_version' : '7.17.19' },
  { 'min_version' : '8.0.0',  'max_version':'8.12.3', 'fixed_version' : '8.13.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);