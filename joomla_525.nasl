#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232605);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id("CVE-2025-22213");
  script_xref(name:"IAVA", value:"2025-A-0164-S");

  script_name(english:"Joomla 4.0.x < 4.4.12 / 5.0.x < 5.2.5 Joomla 5.2.5 Security & Bugfix Release (5922-joomla-5-2-5-security-bugfix-release)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 4.0.x prior to
4.4.12 or 5.0.x prior to 5.2.5. It is, therefore, affected by a vulnerability.

  - Inadequate checks in the Media Manager allowed users with edit privileges to change file extension to
    arbitrary extension, including .php and other potentially executable extensions. (CVE-2025-22213)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://developer.joomla.org/security-centre/961-20250301-core-malicious-file-uploads-via-media-managere-malicious-file-uploads-via-media-manager.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e17fc616");
  # https://www.joomla.org/announcements/release-news/5922-joomla-5-2-5-security-bugfix-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a16e5a1a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 4.4.12 / 5.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);

var app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '4.0.0', 'max_version' : '4.4.11', 'fixed_version' : '4.4.12' },
  { 'min_version' : '5.0.0', 'max_version' : '5.2.4', 'fixed_version' : '5.2.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
