#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197889);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2024-4184",
    "CVE-2024-4189",
    "CVE-2024-4211",
    "CVE-2024-4690",
    "CVE-2024-4691",
    "CVE-2024-4692",
    "CVE-2024-5273",
    "CVE-2024-28793"
  );
  script_xref(name:"JENKINS", value:"2024-05-24");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2024-05-24)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Jenkins Report Info Plugin 1.2 and earlier does not perform path validation of the workspace directory
    while serving report files, allowing attackers with Item/Configure permission to retrieve Surefire
    failures, PMD violations, Findbugs bugs, and Checkstyle errors on the controller file system by editing
    the workspace path. (CVE-2024-5273)

  - High Team Concert Git Plugin 2.0.4 and earlier does not escape the Rational Team Concert (RTC) server URI
    on the build page when showing changes. This results in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers able to configure jobs. Team Concert Git Plugin 2.0.5 escapes the Rational Team
    Concert (RTC) server URI on the build page when showing changes. (CVE-2024-28793)

  - High OpenText Application Automation Tools Plugin 24.1.0 and earlier does not configure its XML parsers to
    prevent XML external entity (XXE) attacks. This allows attackers able to control the input files for
    OpenText Application Automation Tools Plugin build steps and post-build steps to have Jenkins parse a
    crafted file that uses external entities for extraction of secrets from the Jenkins controller or server-
    side request forgery. OpenText Application Automation Tools Plugin 24.1.1-beta disables external entity
    resolution for its XML parsers. The fix is currently available only as a beta release. Beta releases will
    not appear in the regular update center but can be found in the experimental update center. For more
    information on how to install a beta release, see this documentation. (CVE-2024-4184, CVE-2024-4189,
    CVE-2024-4690)

  - Medium OpenText Application Automation Tools Plugin 24.1.0 and earlier does not perform permission checks
    in several HTTP endpoints. This allows attackers with Overall/Read permission to enumerate ALM jobs
    configurations, ALM Octane configurations and Service Virtualization configurations. OpenText Application
    Automation Tools Plugin 24.1.1-beta requires Item/Configure permission to enumerate ALM jobs
    configurations, ALM Octane configurations and Service Virtualization configurations. The fix is currently
    available only as a beta release. Beta releases will not appear in the regular update center but can be
    found in the experimental update center. For more information on how to install a beta release, see this
    documentation. (CVE-2024-4211, CVE-2024-4691, CVE-2024-4692)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2024-05-24");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - OpenText Application Automation Tools Plugin to version 24.1.1-beta or later
  - Report Info Plugin: See vendor advisory
  - Team Concert Git Plugin to version 2.0.5 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4690");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var constraints = [
    {'max_version' : '24.1.0', 'fixed_version' : '24.1.1', 'fixed_display' : '24.1.1-beta', 'plugin' : 'OpenText Application Automation Tools Plugin'},
    {'max_version' : '1.2', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Report Info Plugin'},
    {'max_version' : '2.0.4', 'fixed_version' : '2.0.5', 'plugin' : 'Team Concert Git Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
