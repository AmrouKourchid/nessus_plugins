#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178776);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2023-38500");

  script_name(english:"TYPO3 8.7.42 < 8.7.53 ELTS / 9.5.29 < 9.5.42 ELTS / 10.4.19 < 10.4.39 ELTS / 11.3.2 < 11.5.30 / 12.0.0 < 12.4.4 XSS (TYPO3-CORE-SA-2023-002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote webserver is affected by a XSS vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of TYPO3 installed on the remote host is prior to 8.7.42 < 8.7.53 ELTS / 9.5.29 < 9.5.42 ELTS / 10.4.19 <
10.4.39 ELTS / 11.3.2 < 11.5.30 / 12.0.0 < 12.4.4. It is, therefore, affected by a vulnerability as referenced in the
TYPO3-CORE-SA-2023-002 advisory.

  - Due to an encoding issue in the serialization layer, malicious markup nested in a noscript element was not
    encoded correctly. noscript is disabled in the default configuration, but might have been enabled in
    custom scenarios. This allows bypassing the cross-site scripting mechanism of typo3/html-sanitizer.
    (CVE-2023-38500)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://typo3.org/security/advisory/typo3-core-sa-2023-002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 8.7.53 ELTS, 9.5.42 ELTS, 10.4.39 ELTS, 11.5.30, 12.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38500");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '8.7.42', 'max_version' : '8.7.52', 'fixed_version' : '8.7.53', 'fixed_display' : '8.7.53 ELTS' },
  { 'min_version' : '9.5.29', 'max_version' : '9.5.41', 'fixed_version' : '9.5.42', 'fixed_display' : '9.5.42 ELTS' },
  { 'min_version' : '10.4.19', 'max_version' : '10.4.38', 'fixed_version' : '10.4.39', 'fixed_display' : '10.4.39 ELTS' },
  { 'min_version' : '11.3.2', 'max_version' : '11.5.29', 'fixed_version' : '11.5.30' },
  { 'min_version' : '12.0.0', 'max_version' : '12.4.3', 'fixed_version' : '12.4.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
