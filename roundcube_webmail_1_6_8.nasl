#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205297);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/09");

  script_cve_id("CVE-2024-42008", "CVE-2024-42009", "CVE-2024-42010");
  script_xref(name:"IAVA", value:"2024-A-0470");

  script_name(english:"Roundcube Webmail 1.5.x < 1.5.8 / 1.6.x < 1.6.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running Roundcube Webmail version 1.5.x prior to 1.5.8 or 1.6.x prior to 1.6.8. It is, 
therefore, affected by multiple vulnerabilities.

  - A Cross-Site Scripting vulnerability in rcmail_action_mail_get->run() in Roundcube through 1.5.7 and 1.6.x
  through 1.6.7 allows a remote attacker to steal and send emails of a victim via a malicious e-mail
  attachment served with a dangerous Content-Type header. (CVE-2024-42008)

  - A Cross-Site Scripting vulnerability in Roundcube through 1.5.7 and 1.6.x through 1.6.7 allows a remote
  attacker to steal and send emails of a victim via a crafted e-mail message that abuses a Desanitization 
  issue in message_body() in program/actions/mail/show.php. (CVE-2024-42009)

  - mod_css_styles in Roundcube through 1.5.7 and 1.6.x through 1.6.7 allows a insufficiently filters 
  Cascading Style Sheets (CSS) token sequences in rendered e-mail messages, allowing a remote attacker to 
  obtain sensitive information. (CVE-2024-42010)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://roundcube.net/news/2024/08/04/security-updates-1.6.8-and-1.5.8");
  # https://www.sonarsource.com/blog/government-emails-at-risk-critical-cross-site-scripting-vulnerability-in-roundcube-webmail/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a3548ce");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Roundcube Webmail version 1.5.8, 1.6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42009");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:roundcube:webmail");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("roundcube_webmail_detect.nbin");
  script_require_keys("installed_sw/Roundcube Webmail");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'Roundcube Webmail';

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:'Roundcube Webmail', port:port, webapp:TRUE);

var constraints = [
  {'fixed_version': '1.5.8'},
  {'min_version': '1.6', 'fixed_version': '1.6.8'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE, 
  flags:{'xss':TRUE}
);
