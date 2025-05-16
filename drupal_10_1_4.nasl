#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181691);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id("CVE-2023-5256");
  script_xref(name:"IAVA", value:"2023-A-0505-S");

  script_name(english:"Drupal 9.5.x < 9.5.11 / 10.x < 10.0.11 / 10.1.x < 10.1.4 Drupal Vulnerability (SA-CORE-2023-006) ");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 9.5.x prior to
9.5.11, 10.x prior to 10.0.11, or 10.1.x prior to 10.1.4. It is, therefore, affected by a vulnerability.

  - In certain scenarios, Drupal's JSON:API module will output error backtraces. With some configurations,
    this may cause sensitive information to be cached and made available to anonymous users, leading to
    privilege escalation. This vulnerability only affects sites with the JSON:API module enabled, and can be
    mitigated by uninstalling JSON:API. The core REST and contributed GraphQL modules are not affected. Drupal
    Steward partners have been made aware of this issue. Some platforms may provide mitigations. However, not
    all WAF configurations can mitigate the issue, so it is still recommended to update promptly to this
    security release if your site uses JSON:API. (SA-CORE-2023-006)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2023-006");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/10.0.11");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/10.1.4");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.5.11");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 9.5.11 / 10.0.11 / 10.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5256");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '9.5', 'fixed_version' : '9.5.11' },
  { 'min_version' : '10.0', 'fixed_version' : '10.0.11' },
  { 'min_version' : '10.1', 'fixed_version' : '10.1.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
