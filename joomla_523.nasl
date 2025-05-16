#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214093);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id("CVE-2024-40749");
  script_xref(name:"IAVA", value:"2025-A-0016-S");

  script_name(english:"Joomla 3.9.x < 3.10.20 / 4.0.x < 4.4.10 / 5.0.x < 5.2.3 Joomla 5.2.3 Security & Bugfix Release (5919-joomla-5-2-3-security-bugfix-release)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 3.9.x prior to
3.10.20, 4.0.x prior to 4.4.10, or 5.0.x prior to 5.2.3. It is, therefore, affected by a vulnerability.

  - Improper Access Controls allows access to protected views. (CVE-2024-40749)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://developer.joomla.org/security-centre/954-20250101-core-xss-vectors-in-module-chromes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58642a0f");
  # https://developer.joomla.org/security-centre/955-20250102-core-xss-vector-in-the-id-attribute-of-menu-lists.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a413f79f");
  # https://developer.joomla.org/security-centre/956-20250103-core-read-acl-violation-in-multiple-core-views.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc7c0ab3");
  # https://www.joomla.org/announcements/release-news/5919-joomla-5-2-3-security-bugfix-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12621d43");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.10.20 / 4.4.10 / 5.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40749");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/14");

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
  { 'min_version' : '3.9.0', 'max_version' : '3.10.19', 'fixed_version' : '3.10.20' },
  { 'min_version' : '4.0.0', 'max_version' : '4.4.9', 'fixed_version' : '4.4.10' },
  { 'min_version' : '5.0.0', 'max_version' : '5.2.2', 'fixed_version' : '5.2.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
