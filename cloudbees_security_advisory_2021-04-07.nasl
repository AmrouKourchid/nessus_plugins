#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155586);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id(
    "CVE-2021-21639",
    "CVE-2021-21640",
    "CVE-2021-21641",
    "CVE-2021-22510",
    "CVE-2021-22511",
    "CVE-2021-22512",
    "CVE-2021-22513"
  );

  script_name(english:"Jenkins Enterprise and Operations Center < 2.222.43.0.4 / 2.249.30.0.4 / 2.277.2.3 Multiple Vulnerabilities (CloudBees Security Advisory 2021-04-07)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.222.x prior to
2.222.43.0.4, 2.249.x prior to 2.249.30.0.4, or 2.x prior to 2.277.2.3. It is, therefore, affected by multiple
vulnerabilities, including the following:

  - Reflected XSS vulnerability in Micro Focus Application Automation Tools Plugin - Jenkins plugin. The
    vulnerability affects all version 6.7 and earlier versions. (CVE-2021-22510)

  - Improper Certificate Validation vulnerability in Micro Focus Application Automation Tools Plugin - Jenkins
    plugin. The vulnerability affects version 6.7 and earlier versions. The vulnerability could allow
    unconditionally disabling of SSL/TLS certificates. (CVE-2021-22511)

  - Cross-Site Request Forgery (CSRF) vulnerability in Micro Focus Application Automation Tools Plugin -
    Jenkins plugin. The vulnerability affects version 6.7 and earlier versions. The vulnerability could allow
    form validation without permission checks. (CVE-2021-22512)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/cloudbees-security-advisory-2021-04-07");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.222.43.0.4, 2.249.30.0.4, 2.277.2.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22511");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-22513");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'min_version' : '2.222',  'fixed_version' : '2.222.43.0.4', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2.249',  'fixed_version' : '2.249.30.0.4', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.277.2.3',    'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xsrf':TRUE, 'xss':TRUE}
);
