#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138877);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id(
    "CVE-2020-15695",
    "CVE-2020-15696",
    "CVE-2020-15697",
    "CVE-2020-15698",
    "CVE-2020-15699"
  );
  script_xref(name:"IAVA", value:"2020-A-0335-S");

  script_name(english:"Joomla 2.5.x < 3.9.20 Multiple Vulnerabilities (5814-joomla-3-9-20)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 2.5.x prior to
3.9.20. It is, therefore, affected by multiple vulnerabilities.

  - A missing token check in the ajax_install endpoint com_installer causes a CSRF vulnerability. (20200701)

  - Missing validation checks at the usergroups table object can result into an broken site configuration.
    (CVE-2020-15699)

  - A missing token check in the remove request section of com_privacy causes a CSRF vulnerability.
    (CVE-2020-15695)

  - Internal read-only fields in the User table class could be modified by users. (CVE-2020-15697)

  - Lack of input filtering and escaping allows XSS attacks in mod_random_image (CVE-2020-15696)

  - Inadequate filtering in the system information screen could expose redis or proxy credentials
    (CVE-2020-15698)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5814-joomla-3-9-20.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de6d8c21");
  # https://developer.joomla.org/security-centre/818-20200701-core-csrf-in-com-installer-ajax-install-endpoint.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8471b74");
  # https://developer.joomla.org/security-centre/819-20200702-core-missing-checks-can-lead-to-a-broken-usergroups-table-record.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85625409");
  # https://developer.joomla.org/security-centre/820-20200703-core-csrf-in-com-privacy-remove-request-feature.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f66a6109");
  # https://developer.joomla.org/security-centre/821-20200704-core-variable-tampering-via-user-table-class.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b146589b");
  # https://developer.joomla.org/security-centre/822-20200705-core-escape-mod-random-image-link.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ab0ce25");
  # https://developer.joomla.org/security-centre/823-20200706-core-system-information-screen-could-expose-redis-or-proxy-credentials.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726ee913");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '2.5.0', 'max_version' : '3.9.19', 'fixed_version' : '3.9.20' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xsrf':TRUE, 'xss':TRUE}
);
