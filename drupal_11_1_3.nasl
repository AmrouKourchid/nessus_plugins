#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216497);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_name(english:"Drupal 10.3.x < 10.3.13 / 10.3.x < 10.3.13 / 10.4.x < 10.4.3 / 10.4.x < 10.4.3 / 11.x < 11.0.12 / 11.x < 11.0.12 / 11.1.x < 11.1.3 / 11.1.x < 11.1.3 Multiple Vulnerabilities (drupal-2025-02-19)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 10.3.x prior to
10.3.13, 10.3.x prior to 10.3.13, 10.4.x prior to 10.4.3, 10.4.x prior to 10.4.3, 11.x prior to 11.0.12, 11.x prior to
11.0.12, 11.1.x prior to 11.1.3, or 11.1.x prior to 11.1.3. It is, therefore, affected by multiple vulnerabilities.

  - Drupal core contains a potential PHP Object Injection vulnerability that (if combined with another
    exploit) could lead to Arbitrary File Inclusion. Techniques exist to escalate this attack to Remote Code
    Execution. It is not directly exploitable. This issue is mitigated by the fact that in order for it to be
    exploitable, a separate vulnerability must be present to allow an attacker to pass unsafe input to
    unserialize(). There are no such known exploits in Drupal core. (SA-CORE-2025-003)

  - Bulk operations allow authorized users to modify several nodes at once from the Content page
    (/admin/content). A site builder can also add bulk operations to other pages using Views. A bug in the
    core Actions system allows some users to modify some fields using bulk actions that they do not have
    permission to modify on individual nodes. This vulnerability is mitigated by the fact that an attacker
    must have permission to access /admin/content or other, custom views and to edit nodes. In particular, the
    bulk operations Make content sticky Make content unsticky Promote content to front page Publish content
    Remove content from front page Unpublish content now require the Administer content permission. (SA-
    CORE-2025-002)

  - Drupal core doesn't sufficiently filter error messages under certain circumstances, leading to a reflected
    Cross Site Scripting vulnerability (XSS). Sites are encouraged to update. There are not yet public
    documented steps to exploit this, but there may be soon given the nature of this issue. This issue is
    being protected by Drupal Steward. Sites that use Drupal Steward are already protected, but are still
    encouraged to upgrade in the near future. (SA-CORE-2025-001)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2025-003");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/10.3.13");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/10.4.3");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/11.0.12");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/11.1.3");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2023-11-01");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2025-002");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2025-001");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 10.3.13 / 10.3.13 / 10.4.3 / 10.4.3 / 11.0.12 / 11.0.12 / 11.1.3 / 11.1.3 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
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
  { 'min_version' : '10.3.0', 'fixed_version' : '10.3.13' },
  { 'min_version' : '10.3', 'fixed_version' : '10.3.13' },
  { 'min_version' : '10.4', 'fixed_version' : '10.4.3' },
  { 'min_version' : '10.4.0', 'fixed_version' : '10.4.3' },
  { 'min_version' : '11.0', 'fixed_version' : '11.0.12' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.12' },
  { 'min_version' : '11.1', 'fixed_version' : '11.1.3' },
  { 'min_version' : '11.1.0', 'fixed_version' : '11.1.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
