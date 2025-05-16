#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213293);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/21");

  script_cve_id("CVE-2024-50623");
  script_xref(name:"IAVA", value:"2024-A-0825");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/01/03");

  script_name(english:"Cleo LexiCom < 5.8.0.21 Unrestricted File Upload/Download (CVE-2024-50623)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by an unrestricted file upload and download vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cleo LexiCom running on the remote host is prior to 5.8.0.21. It is, therefore, affected by an
unrestricted file upload and download vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.cleo.com/hc/en-us/articles/27140294267799-Cleo-Product-Security-Advisory-CVE-2024-50623
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77c778bb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cleo LexiCom version 5.8.0.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50623");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cleo:lexicom");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cleo_lexicom_detect.nbin");
  script_require_keys("installed_sw/Cleo LexiCom");
  script_require_ports("Services/www", 80, 8080, 443, 5080);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'Cleo LexiCom';
get_install_count(app_name:app, exit_if_zero:TRUE);

var constraints = [
  { 'fixed_version' : '5.8.0.21' }
];

var port = get_http_port(default:5080);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);