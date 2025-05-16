#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196999);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2024-34356");

  script_name(english:"TYPO3 9.0.0 < 9.5.48 ELTS / 10.0.0 < 10.4.45 ELTS / 11.0.0 < 11.5.37 / 12.0.0 < 12.4.15 / 13.0.0 < 13.1.1 XSS (TYPO3-CORE-SA-2024-008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote webserver is affected by a XSS vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of TYPO3 installed on the remote host is prior to 9.0.0 < 9.5.48 ELTS / 10.0.0 < 10.4.45 ELTS / 11.0.0 <
11.5.37 / 12.0.0 < 12.4.15 / 13.0.0 < 13.1.1. It is, therefore, affected by a vulnerability as referenced in the
TYPO3-CORE-SA-2024-008 advisory.

  - TYPO3 is an enterprise content management system. Starting in version 9.0.0 and prior to versions 9.5.48
    ELTS, 10.4.45 ELTS, 11.5.37 LTS, 12.4.15 LTS, and 13.1.1, the form manager backend module is vulnerable to
    cross-site scripting. Exploiting this vulnerability requires a valid backend user account with access to
    the form module. TYPO3 versions 9.5.48 ELTS, 10.4.45 ELTS, 11.5.37 LTS, 12.4.15 LTS, and 13.1.1 fix the
    problem described. (CVE-2024-34356)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://typo3.org/security/advisory/typo3-core-sa-2024-008");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 9.5.48 ELTS, 10.4.45 ELTS, 11.5.37, 12.4.15, 13.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34356");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("typo3_detect.nasl");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'TYPO3', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '9.0.0', 'max_version' : '9.5.47', 'fixed_version' : '9.5.48', 'fixed_display' : '9.5.48 ELTS' },
  { 'min_version' : '10.0.0', 'max_version' : '10.4.44', 'fixed_version' : '10.4.45', 'fixed_display' : '10.4.45 ELTS' },
  { 'min_version' : '11.0.0', 'max_version' : '11.5.36', 'fixed_version' : '11.5.37' },
  { 'min_version' : '12.0.0', 'max_version' : '12.4.14', 'fixed_version' : '12.4.15' },
  { 'min_version' : '13.0.0', 'max_version' : '13.1.0', 'fixed_version' : '13.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
