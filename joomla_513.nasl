#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206037);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id(
    "CVE-2024-27184",
    "CVE-2024-27185",
    "CVE-2024-27186",
    "CVE-2024-27187",
    "CVE-2024-40743"
  );
  script_xref(name:"IAVA", value:"2024-A-0516-S");

  script_name(english:"Joomla 3.0.x < 3.10.17 / 4.0.x < 4.4.7 / 5.0.x < 5.1.3 Multiple Vulnerabilities (5910-joomla-5-1-3-and-4-4-7-security-and-bug-fix-release)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 3.0.x prior to
3.10.17, 4.0.x prior to 4.4.7, or 5.0.x prior to 5.1.3. It is, therefore, affected by multiple vulnerabilities.

  - Inadequate validation of URLs could result into an invalid check whether an redirect URL is internal or
    not.. (CVE-2024-27184)

  - The pagination class includes arbitrary parameters in links, leading to cache poisoning attack vectors.
    (CVE-2024-27185)

  - The mail template feature lacks an escaping mechanism, causing XSS vectors in multiple extensions.
    (CVE-2024-27186)

  - Improper Access Controls allows backend users to overwrite their username when disallowed.
    (CVE-2024-27187)

  - The stripImages and stripIframes methods didn't properly process inputs, leading to XSS vectors.
    (CVE-2024-40743)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5910-joomla-5-1-3-and-4-4-7-security-and-bug-fix-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38aa3f4b");
  # https://developer.joomla.org/security-centre/941-20240801-core-inadequate-validation-of-internal-urls.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f665e51");
  # https://developer.joomla.org/security-centre/942-20240802-core-cache-poisoning-in-pagination.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b32173d4");
  # https://developer.joomla.org/security-centre/944-20240803-core-xss-in-html-mail-templates.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?017bf375");
  # https://developer.joomla.org/security-centre/945-20240804-core-improper-acl-for-backend-profile-view.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b58f35c9");
  # https://developer.joomla.org/security-centre/946-20240805-core-xss-vectors-in-outputfilter-strip-methods.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58447ab4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.10.17 / 4.4.7 / 5.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40743");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-27185");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/21");

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
  { 'min_version' : '3.0.0', 'max_version' : '3.10.16', 'fixed_version' : '3.10.17' },
  { 'min_version' : '4.0.0', 'max_version' : '4.4.6', 'fixed_version' : '4.4.7' },
  { 'min_version' : '5.0.0', 'max_version' : '5.1.2', 'fixed_version' : '5.1.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
