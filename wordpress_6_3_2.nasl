#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

# The descriptive text and package checks in this plugin were
# extracted from WordPress Security Advisory wordpress-6-3-2-maintenance-and-security-release.

include('compat.inc');

if (description)
{
  script_id(182976);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/06");

  script_cve_id("CVE-2023-5561", "CVE-2023-38000", "CVE-2023-39999");

  script_name(english:"WordPress 6.0 < 6.3.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by one or more vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wordpress Core installed on the remote host are affected by multiple vulnerabilities.

  - The Popup Builder WordPress plugin through 4.1.15 does not sanitise and escape some of its settings,
    which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks
    even when the unfiltered_html capability is disallowed (for example in multisite setup). (CVE-2023-5561)

  - Auth. Stored (contributor+) Cross-Site Scripting (XSS). (CVE-2023-38000)

  - Exposure of Sensitive Information to an Unauthorized Actor. (CVE-2023-39999)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://patchstack.com/articles/wordpress-core-6-3-2-security-update-technical-advisory?_s_id=cve
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?447a937b");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/download/releases/");
  # https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b5adc88");
  # https://make.wordpress.org/core/2023/10/06/wordpress-6-3-2-rc1-is-now-available/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69129a99");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-6-3-2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 6.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38000");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'WordPress';
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);

var app_info = vcf::get_app_info(app:'WordPress', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '6.0', 'fixed_version' : '6.3.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{xss:TRUE}
);
