#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153977);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2021-21670", "CVE-2021-21671");

  script_name(english:"Jenkins Enterprise and Operations Center < 2.249.31.0.6 / 2.277.40.0.1 / 2.289.2.2 Multiple Vulnerabilities (CloudBees Security Advisory 2021-06-30)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.x prior to
2.289.2.2, 2.249.x prior to 2.249.31.0.6, or 2.277.x prior to 2.277.40.0.1. It is, therefore, affected by multiple
vulnerabilities:

  - Vulnerable versions of Jenkins allow users to cancel queue items and abort builds of jobs for which they
    have Item/Cancel permission even when they do not have Item/Read permission. (CVE-2021-21670)

  - Vulnerable versions of Jenkins do not invalidate the previous session on login and is, therefore,
    vulnerable to session fixation attacks. (CVE-2021-21671)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/cloudbees-security-advisory-2021-06-30");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.249.31.0.6, 2.277.40.0.1, 2.289.2.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/11");

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
  { 'min_version' : '2.249',  'fixed_version' : '2.249.31.0.6', 'edition' : 'Enterprise' },
  { 'min_version' : '2.277',  'fixed_version' : '2.277.40.0.1', 'edition' : 'Enterprise' },
  { 'min_version' : '2',      'fixed_version' : '2.289.2.2',    'edition' : 'Enterprise', 'rolling_train' : TRUE },
  { 'min_version' : '2.249',  'fixed_version' : '2.249.31.0.6', 'edition' : 'Operations Center' },
  { 'min_version' : '2.277',  'fixed_version' : '2.277.40.0.1', 'edition' : 'Operations Center' },
  { 'min_version' : '2',      'fixed_version' : '2.289.2.2',    'edition' : 'Operations Center', 'rolling_train' : TRUE }
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
