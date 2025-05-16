#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178959);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2023-3414",
    "CVE-2023-3442",
    "CVE-2023-39152",
    "CVE-2023-39153",
    "CVE-2023-39154",
    "CVE-2023-39155",
    "CVE-2023-39156"
  );
  script_xref(name:"JENKINS", value:"2023-07-26");
  script_xref(name:"IAVA", value:"2023-A-0384-S");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2023-07-26)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Always-incorrect control flow implementation in Jenkins Gradle Plugin 2.8 may result in credentials not
    being masked (i.e., replaced with asterisks) in the build log in some circumstances. (CVE-2023-39152)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins GitLab Authentication Plugin 1.17.1 and
    earlier allows attackers to trick users into logging in to the attacker's account. (CVE-2023-39153)

  - Incorrect permission checks in Jenkins Qualys Web App Scanning Connector Plugin 2.0.10 and earlier allow
    attackers with global Item/Configure permission to connect to an attacker-specified URL using attacker-
    specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.
    (CVE-2023-39154)

  - Jenkins Chef Identity Plugin 2.0.3 and earlier does not mask the user.pem key form field, increasing the
    potential for attackers to observe and capture it. (CVE-2023-39155)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Bazaar Plugin 1.22 and earlier allows
    attackers to delete previously created Bazaar SCM tags. (CVE-2023-39156)

  - Medium ServiceNow DevOps Plugin 1.38.0 and earlier does not perform a permission check in a method
    implementing form validation. This allows attackers with Overall/Read permission to connect to an
    attacker-specified URL using attacker-specified credentials IDs obtained through another method, capturing
    credentials stored in Jenkins. Additionally, this form validation method does not require POST requests,
    resulting in a cross-site request forgery (CSRF) vulnerability. ServiceNow DevOps Plugin 1.38.1 requires
    POST requests and Overall/Administer permission for the affected form validation method. (CVE-2023-3414,
    CVE-2023-3442)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2023-07-26");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Bazaar Plugin: See vendor advisory
  - Chef Identity Plugin: See vendor advisory
  - GitLab Authentication Plugin to version 1.18 or later
  - Gradle Plugin to version 2.8.1 or later
  - Qualys Web App Scanning Connector Plugin to version 2.0.11 or later
  - ServiceNow DevOps Plugin to version 1.38.1 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3442");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var constraints = [
    {'max_version' : '1.22', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Bazaar Plugin'},
    {'max_version' : '2.0.3', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Chef Identity Plugin'},
    {'max_version' : '1.17.1', 'fixed_version' : '1.18', 'plugin' : 'GitLab Authentication Plugin'},
    {'max_version' : '2.8', 'fixed_version' : '2.8.1', 'plugin' : 'Gradle Plugin'},
    {'max_version' : '2.0.10', 'fixed_version' : '2.0.11', 'plugin' : 'Qualys Web App Scanning Connector Plugin'},
    {'max_version' : '1.38.0', 'fixed_version' : '1.38.1', 'plugin' : 'ServiceNow DevOps Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE}
);
