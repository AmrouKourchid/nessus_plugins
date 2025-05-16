#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234499);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2025-32372");
  script_xref(name:"IAVB", value:"2025-B-0055");

  script_name(english:"DNN < 9.13.8 DotNetNuke.Core Server-Side Request Forgery (CVE-2025-32372)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by a server-side request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of DNN (formerly DotNetNuke) running on the remote web server is
prior to 9.13.8. It is, therefore, affected by a server-side request forgery vulnerability:

  - DNN (formerly DotNetNuke) is an open-source web content management platform (CMS) in the Microsoft ecosystem. A
    bypass has been identified for the previously known vulnerability CVE-2017-0929, allowing unauthenticated attackers
    to execute arbitrary GET requests against target systems, including internal or adjacent networks. This
    vulnerability facilitates a semi-blind SSRF attack, allowing attackers to make the target server send requests to
    internal or external URLs without viewing the full responses. Potential impacts include internal network
    reconnaissance, bypassing firewalls. This vulnerability is fixed in 9.13.8. (CVE-2025-32372)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/dnnsoftware/Dnn.Platform/security/advisories/GHSA-3f7v-qx94-666m
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fdaf53f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DNN version 9.13.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:C/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32372");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dnnsoftware:dotnetnuke");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_keys("installed_sw/DNN");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'DNN';

get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:80, asp:TRUE);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '9.13.8' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
