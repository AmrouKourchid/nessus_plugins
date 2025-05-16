#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202021);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/23");

  script_cve_id(
    "CVE-2024-21729",
    "CVE-2024-21730",
    "CVE-2024-21731",
    "CVE-2024-26278",
    "CVE-2024-26279"
  );
  script_xref(name:"IAVA", value:"2024-A-0384-S");

  script_name(english:"Joomla 3.0.x < 3.10.16 / 4.0.x < 4.4.6 / 5.0.x < 5.1.2 Multiple Vulnerabilities (5909-joomla-5-1-2-and-joomla-4-4-6-security-and-bug-fix-release)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 3.0.x prior to
3.10.16, 4.0.x prior to 4.4.6, or 5.0.x prior to 5.1.2. It is, therefore, affected by multiple vulnerabilities.

  - Inadequate input validation leads to XSS vulnerabilities in the accessiblemedia field. (CVE-2024-21729)

  - The fancyselect list field layout does not correctly escape inputs, leading to a self-XSS vector.
    (CVE-2024-21730)

  - Improper handling of input could lead to an XSS vector in the StringHelper::truncate method.
    (CVE-2024-21731)

  - The wrapper extensions do not correctly validate inputs, leading to XSS vectors. (CVE-2024-26279)

  - The Custom Fields component not correctly filter inputs, leading to a XSS vector. (CVE-2024-26278)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5909-joomla-5-1-2-and-joomla-4-4-6-security-and-bug-fix-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f77229a");
  # https://developer.joomla.org/security-centre/935-20240701-core-xss-in-accessible-media-selection-field
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0df99016");
  # https://developer.joomla.org/security-centre/936-20240702-core-self-xss-in-fancyselect-list-field-layout.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e473d4b");
  # https://developer.joomla.org/security-centre/937-20240703-core-xss-in-stringhelper-truncate-method.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b42ecf18");
  # https://developer.joomla.org/security-centre/938-20240704-core-xss-in-wrapper-extensions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ade6f6fc");
  # https://developer.joomla.org/security-centre/939-20240705-core-xss-in-com-fields-default-field-value.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72a9cc6e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.10.16 / 4.4.6 / 5.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26279");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/09");

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

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '3.0.0', 'max_version' : '3.10.15', 'fixed_version' : '3.10.16' },
  { 'min_version' : '4.0.0', 'max_version' : '4.4.5', 'fixed_version' : '4.4.6' },
  { 'min_version' : '5.0.0', 'max_version' : '5.1.1', 'fixed_version' : '5.1.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
