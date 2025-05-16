#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186836);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2023-5072",
    "CVE-2023-50764",
    "CVE-2023-50765",
    "CVE-2023-50766",
    "CVE-2023-50767",
    "CVE-2023-50768",
    "CVE-2023-50769",
    "CVE-2023-50770",
    "CVE-2023-50771",
    "CVE-2023-50772",
    "CVE-2023-50773",
    "CVE-2023-50774",
    "CVE-2023-50775",
    "CVE-2023-50776",
    "CVE-2023-50777",
    "CVE-2023-50778",
    "CVE-2023-50779"
  );
  script_xref(name:"JENKINS", value:"2023-12-13");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2023-12-13)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Denial of Service in JSON-Java versions up to and including 20230618. A bug in the parser means that an
    input string of modest size can lead to indefinite amounts of memory being used. (CVE-2023-5072)

  - Jenkins Scriptler Plugin 342.v6a_89fd40f466 and earlier does not restrict a file name query parameter in
    an HTTP endpoint, allowing attackers with Scriptler/Configure permission to delete arbitrary files on the
    Jenkins controller file system. (CVE-2023-50764)

  - A missing permission check in Jenkins Scriptler Plugin 342.v6a_89fd40f466 and earlier allows attackers
    with Overall/Read permission to read the contents of a Groovy script by knowing its ID. (CVE-2023-50765)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Nexus Platform Plugin 3.18.0-03 and earlier
    allows attackers to send an HTTP request to an attacker-specified URL and parse the response as XML.
    (CVE-2023-50766)

  - Missing permission checks in Jenkins Nexus Platform Plugin 3.18.0-03 and earlier allow attackers with
    Overall/Read permission to send an HTTP request to an attacker-specified URL and parse the response as
    XML. (CVE-2023-50767)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Nexus Platform Plugin 3.18.0-03 and earlier
    allows attackers to connect to an attacker-specified HTTP server using attacker-specified credentials IDs
    obtained through another method, capturing credentials stored in Jenkins. (CVE-2023-50768)

  - Missing permission checks in Jenkins Nexus Platform Plugin 3.18.0-03 and earlier allow attackers with
    Overall/Read permission to connect to an attacker-specified HTTP server using attacker-specified
    credentials IDs obtained through another method, capturing credentials stored in Jenkins. (CVE-2023-50769)

  - Jenkins OpenId Connect Authentication Plugin 2.6 and earlier stores a password of a local user account
    used as an anti-lockout feature in a recoverable format, allowing attackers with access to the Jenkins
    controller file system to recover the plain text password of that account, likely gaining administrator
    access to Jenkins. (CVE-2023-50770)

  - Jenkins OpenId Connect Authentication Plugin 2.6 and earlier improperly determines that a redirect URL
    after login is legitimately pointing to Jenkins, allowing attackers to perform phishing attacks.
    (CVE-2023-50771)

  - Jenkins Dingding JSON Pusher Plugin 2.0 and earlier stores access tokens unencrypted in job config.xml
    files on the Jenkins controller where they can be viewed by users with Item/Extended Read permission or
    access to the Jenkins controller file system. (CVE-2023-50772)

  - Jenkins Dingding JSON Pusher Plugin 2.0 and earlier does not mask access tokens displayed on the job
    configuration form, increasing the potential for attackers to observe and capture them. (CVE-2023-50773)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins HTMLResource Plugin 1.02 and earlier allows
    attackers to delete arbitrary files on the Jenkins controller file system. (CVE-2023-50774)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Deployment Dashboard Plugin 1.0.10 and
    earlier allows attackers to copy jobs. (CVE-2023-50775)

  - Jenkins PaaSLane Estimate Plugin 1.0.4 and earlier stores PaaSLane authentication tokens unencrypted in
    job config.xml files on the Jenkins controller where they can be viewed by users with Item/Extended Read
    permission or access to the Jenkins controller file system. (CVE-2023-50776)

  - Jenkins PaaSLane Estimate Plugin 1.0.4 and earlier does not mask PaaSLane authentication tokens displayed
    on the job configuration form, increasing the potential for attackers to observe and capture them.
    (CVE-2023-50777)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins PaaSLane Estimate Plugin 1.0.4 and earlier
    allows attackers to connect to an attacker-specified URL using an attacker-specified token.
    (CVE-2023-50778)

  - Missing permission checks in Jenkins PaaSLane Estimate Plugin 1.0.4 and earlier allow attackers with
    Overall/Read permission to connect to an attacker-specified URL using an attacker-specified token.
    (CVE-2023-50779)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2023-12-13");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Analysis Model API Plugin to version 11.13.0 or later
  - Deployment Dashboard Plugin: See vendor advisory
  - Dingding JSON Pusher Plugin: See vendor advisory
  - HTMLResource Plugin: See vendor advisory
  - Nexus Platform Plugin to version 3.18.1-01 or later
  - OpenId Connect Authentication Plugin: See vendor advisory
  - PaaSLane Estimate Plugin: See vendor advisory
  - Scriptler Plugin to version 344.v5a_ddb_5f9e685 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50778");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'max_version' : '11.11.0', 'fixed_version' : '11.13.0', 'plugin' : 'Analysis Model API Plugin'},
    {'max_version' : '1.0.10', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Deployment Dashboard Plugin'},
    {'max_version' : '2.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Dingding JSON Pusher Plugin'},
    {'max_version' : '1.02', 'fixed_display' : 'See vendor advisory', 'plugin' : 'HTMLResource Plugin'},
    {'max_version' : '3.18.0', 'fixed_version' : '3.18.1', 'fixed_display' : '3.18.1-01', 'plugin' : 'Nexus Platform Plugin'},
    {'max_version' : '2.6', 'fixed_display' : 'See vendor advisory', 'plugin' : 'OpenId Connect Authentication Plugin'},
    {'max_version' : '1.0.4', 'fixed_display' : 'See vendor advisory', 'plugin' : 'PaaSLane Estimate Plugin'},
    {'max_version' : '342', 'fixed_version' : '344', 'fixed_display' : '344.v5a_ddb_5f9e685', 'plugin' : 'Scriptler Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE}
);
