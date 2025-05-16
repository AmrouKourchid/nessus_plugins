#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211656);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id(
    "CVE-2024-12393",
    "CVE-2024-55634",
    "CVE-2024-55635",
    "CVE-2024-55636",
    "CVE-2024-55637",
    "CVE-2024-55638"
  );
  script_xref(name:"IAVA", value:"2024-A-0797-S");

  script_name(english:"Drupal 7.x < 7.102 / 10.2.x < 10.2.11 / 10.3.x < 10.3.9 / 11.x < 11.0.8 Multiple Vulnerabilities (drupal-2024-11-20)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 7.x prior to 7.102,
10.2.x prior to 10.2.11, 10.3.x prior to 10.3.9, or 11.x prior to 11.0.8. It is, therefore, affected by multiple
vulnerabilities.

  - Deserialization of Untrusted Data vulnerability in Drupal Core allows Object Injection.This issue affects
    Drupal Core: from 7.0 before 7.102, from 8.0.0 before 10.2.11, from 10.3.0 before 10.3.9. (CVE-2024-55638)

  - Deserialization of Untrusted Data vulnerability in Drupal Core allows Object Injection.This issue affects
    Drupal Core: from 8.0.0 before 10.2.11, from 10.3.0 before 10.3.9, from 11.0.0 before 11.0.8.
    (CVE-2024-55636, CVE-2024-55637)

  - Improper Neutralization of Input During Web Page Generation (XSS or 'Cross-site Scripting') vulnerability
    in Drupal Core allows Cross-Site Scripting (XSS).This issue affects Drupal Core: from 7.0 before 7.102.
    (CVE-2024-55635)

  - A vulnerability in Drupal Core allows Privilege Escalation.This issue affects Drupal Core: from 8.0.0
    before 10.2.11, from 10.3.0 before 10.3.9, from 11.0.0 before 11.0.8. (CVE-2024-55634)

  - Improper Neutralization of Input During Web Page Generation (XSS or 'Cross-site Scripting') vulnerability
    in Drupal Core allows Cross-Site Scripting (XSS).This issue affects Drupal Core: from 8.8.0 before
    10.2.11, from 10.3.0 before 10.3.9, from 11.0.0 before 11.0.8. (CVE-2024-12393)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2024-008");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/10.2.11");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/10.3.9");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.102");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2023-11-01");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2024-007");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/11.0.8");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2024-006");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2024-005");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2024-004");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/3486109");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2024-003");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.102 / 10.2.11 / 10.3.9 / 11.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-55637");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-55638");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '7.0', 'fixed_version' : '7.102' },
  { 'min_version' : '10.2', 'fixed_version' : '10.2.11' },
  { 'min_version' : '10.3', 'fixed_version' : '10.3.9' },
  { 'min_version' : '11.0', 'fixed_version' : '11.0.8' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
