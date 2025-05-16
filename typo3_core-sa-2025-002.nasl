#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214057);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/14");

  script_cve_id("CVE-2024-55892");

  script_name(english:"TYPO3 9.0.0 < 9.5.49 ELTS / 10.0.0 < 10.4.48 ELTS / 11.0.0 < 11.5.42 ELTS / 12.0.0 < 12.4.25 / 13.0.0 < 13.4.3 (TYPO3-CORE-SA-2025-002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote webserver is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of TYPO3 installed on the remote host is 9.0.0 prior to 9.5.49 ELTS / 10.0.0 prior to 10.4.48 ELTS / 11.0.0
prior to 11.5.42 ELTS / 12.0.0 prior to 12.4.25 / 13.0.0 prior to 13.4.3. It is, therefore, affected by a vulnerability
as referenced in the TYPO3-CORE-SA-2025-002 advisory.

  - Applications that use TYPO3\CMS\Core\Http\Uri to parse externally provided URLs (e.g., via a query
    parameter) and validate the host of the parsed URL may be vulnerable to open redirect or SSRF attacks if
    the URL is used after passing the validation checks. (CVE-2024-55892)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://typo3.org/security/advisory/typo3-core-sa-2025-002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 9.5.49 ELTS, 10.4.48 ELTS, 11.5.42 ELTS, 12.4.25, 13.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-55892");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("typo3_detect.nasl");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'TYPO3', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '9.0.0', 'max_version' : '9.5.48', 'fixed_version' : '9.5.49', 'fixed_display' : '9.5.49 ELTS' },
  { 'min_version' : '10.0.0', 'max_version' : '10.4.47', 'fixed_version' : '10.4.48', 'fixed_display' : '10.4.48 ELTS' },
  { 'min_version' : '11.0.0', 'max_version' : '11.5.41', 'fixed_version' : '11.5.42', 'fixed_display' : '11.5.42 ELTS' },
  { 'min_version' : '12.0.0', 'max_version' : '12.4.24', 'fixed_version' : '12.4.25' },
  { 'min_version' : '13.0.0', 'max_version' : '13.4.2', 'fixed_version' : '13.4.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
