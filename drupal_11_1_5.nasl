#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232982);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2025-31675");
  script_xref(name:"IAVA", value:"2025-A-0208");

  script_name(english:"Drupal 10.3.x < 10.3.14 / 10.4.x < 10.4.5 / 11.x < 11.0.13 / 11.1.x < 11.1.5 Drupal Vulnerability (SA-CORE-2025-004) ");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 10.3.x prior to
10.3.14, 10.4.x prior to 10.4.5, 11.x prior to 11.0.13, or 11.1.x prior to 11.1.5. It is, therefore, affected by a
vulnerability.

  - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in
    Drupal Drupal core allows Cross-Site Scripting (XSS).This issue affects Drupal core: from 8.0.0 before
    10.3.14, from 10.4.0 before 10.4.5, from 11.0.0 before 11.0.13, from 11.1.0 before 11.1.5.
    (CVE-2025-31675)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2025-004");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/10.3.14");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/10.4.5");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/11.0.13");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/11.1.5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 10.3.14 / 10.4.5 / 11.0.13 / 11.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-31675");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);

var app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '10.3.0', 'fixed_version' : '10.3.14' },
  { 'min_version' : '10.4.0', 'fixed_version' : '10.4.5' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.13' },
  { 'min_version' : '11.1.0', 'fixed_version' : '11.1.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
