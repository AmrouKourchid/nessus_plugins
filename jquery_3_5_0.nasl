#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182682);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2020-11023");
  script_xref(name:"IAVB", value:"2023-B-0076");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/13");

  script_name(english:"JQuery < 3.5.0 XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by cross site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"In JQuery version greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing <option> elements from
 untrusted sources - even after sanitizing it - to one of JQuery's DOM manipulation methods (i.e. .html(), .append(),
 and others) may execute untrusted code. 
 
Initial CVE-2020-23064 mentioned in the advisory has been deprecated as duplicate and replaced with CVE-2020-11023.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/");
  script_set_attribute(attribute:"see_also", value:"https://security.snyk.io/vuln/SNYK-JS-JQUERY-565129");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JQuery version 3.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jquery_detect.nasl");
  script_require_keys("installed_sw/jquery");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("vcf.inc");

var appname = 'jquery';

get_install_count(app_name:appname, exit_if_zero:TRUE);

var port = get_http_port(default:80);
var app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [{'min_version' : '1.0.3', 'fixed_version':'3.5.0'}];

# adding paranoid check, since the plugin is remote and is a open source product
vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  require_paranoia:TRUE,       
  flags:{xss:TRUE});
