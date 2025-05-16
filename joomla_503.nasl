#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190786);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2024-21722",
    "CVE-2024-21723",
    "CVE-2024-21724",
    "CVE-2024-21725",
    "CVE-2024-21726"
  );
  script_xref(name:"IAVA", value:"2024-A-0114-S");

  script_name(english:"Joomla 1.5.x < 3.10.15 / 4.0.x < 4.4.3 / 5.0.x < 5.0.3 Multiple Vulnerabilities (5904-joomla-5-0-3-and-4-4-3-security-and-bug-fix-release)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 1.5.x prior to
3.10.15, 4.0.x prior to 4.4.3, or 5.0.x prior to 5.0.3. It is, therefore, affected by multiple vulnerabilities.

  - The MFA management features did not properly terminate existing user sessions when a user's MFA methods
    have been modified. (CVE-2024-21722)

  - Inadequate parsing of URLs could result into an open redirect. (CVE-2024-21723)

  - Inadequate input validation for media selection fields lead to XSS vulnerabilities in various extensions.
    (CVE-2024-21724)

  - Inadequate escaping of mail addresses lead to XSS vulnerabilities in various components. (CVE-2024-21725)

  - Inadequate content filtering leads to XSS vulnerabilities in various components. (CVE-2024-21726)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5904-joomla-5-0-3-and-4-4-3-security-and-bug-fix-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b655eef4");
  # https://developer.joomla.org/security-centre/925-20240201-core-insufficient-session-expiration-in-mfa-management-views.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ba5c413");
  # https://developer.joomla.org/security-centre/926-20240202-core-open-redirect-in-installation-application.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6c5edaf");
  # https://developer.joomla.org/security-centre/927-20240203-core-xss-in-media-selection-fields.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c3c4fbe");
  # https://developer.joomla.org/security-centre/928-20240204-core-xss-in-mail-address-outputs.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f27a361c");
  # https://developer.joomla.org/security-centre/929-20240205-core-inadequate-content-filtering-within-the-filter-code.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f0d4add");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.10.15 / 4.4.3 / 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21724");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

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

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
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
  { 'min_version' : '1.5.0', 'max_version' : '3.10.14', 'fixed_version' : '3.10.15' },
  { 'min_version' : '4.0.0', 'max_version' : '4.4.2', 'fixed_version' : '4.4.3' },
  { 'min_version' : '5.0.0', 'max_version' : '5.0.2', 'fixed_version' : '5.0.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
