#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(91100);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2016-4029", "CVE-2016-6634", "CVE-2016-6635");
  script_bugtraq_id(92355, 92390, 92400);

  script_name(english:"WordPress < 4.5.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.5.0.
It is, therefore, affected by the following vulnerabilities :

  - A server-side request forgery vulnerability exists due
    improper request handling between a user and the server.
    An attacker can exploit this, via a specially crafted
    request to the http.php script using octal or
    hexadecimal IP addresses, to bypass access restrictions
    and perform unintended actions. (CVE-2016-4029)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input to the
    'first_comment_author' parameter. A context-dependent
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2016-6634)

  - A cross-site request forgery vulnerability exists due to
    a failure to require multiple steps, explicit
    confirmation, or a unique token when making HTTP
    requests. An attacker can exploit this by convincing a
    user to follow a specially crafted link. (CVE-2016-6635)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/8473");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/8474");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/8475");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.5#Security");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6635");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [{ "fixed_version" : "4.5.0" }];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE, xsrf:TRUE}
);
