#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135925);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2020-11889", "CVE-2020-11890", "CVE-2020-11891");
  script_xref(name:"IAVA", value:"2020-A-0168-S");

  script_name(english:"Joomla 2.5.x < 3.9.17 Multiple Vulnerabilities (5807-joomla-3-9-17)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 2.5.x prior to
3.9.17. It is, therefore, affected by multiple vulnerabilities.

  - An issue was discovered in Joomla! before 3.9.17. Incorrect ACL checks in the access level section of
    com_users allow the unauthorized deletion of usergroups. (CVE-2020-11889)

  - An issue was discovered in Joomla! before 3.9.17. Improper input validations in the usergroup table class
    could lead to a broken ACL configuration. (CVE-2020-11890)

  - An issue was discovered in Joomla! before 3.9.17. Incorrect ACL checks in the access level section of
    com_users allow the unauthorized editing of usergroups. (CVE-2020-11891)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5807-joomla-3-9-17.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83f655fa");
  # https://developer.joomla.org/security-centre/811-20200403-core-incorrect-access-control-in-com-users-access-level-deletion-function.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a7de80e");
  # https://developer.joomla.org/security-centre/810-20200402-core-missing-checks-for-the-root-usergroup-in-usergroup-table.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?415fd915");
  # https://developer.joomla.org/security-centre/809-20200401-core-incorrect-access-control-in-com-users-access-level-editing-function.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3f1c4fd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11891");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/23");

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
  { 'min_version' : '2.5.0', 'fixed_version' : '3.9.17' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
