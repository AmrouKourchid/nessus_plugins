#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179363);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2022-34777",
    "CVE-2022-34778",
    "CVE-2022-34779",
    "CVE-2022-34780",
    "CVE-2022-34781",
    "CVE-2022-34782",
    "CVE-2022-34783",
    "CVE-2022-34784",
    "CVE-2022-34785",
    "CVE-2022-34786",
    "CVE-2022-34787",
    "CVE-2022-34788",
    "CVE-2022-34789",
    "CVE-2022-34790",
    "CVE-2022-34791",
    "CVE-2022-34792",
    "CVE-2022-34793",
    "CVE-2022-34794",
    "CVE-2022-34795",
    "CVE-2022-34796",
    "CVE-2022-34797",
    "CVE-2022-34798",
    "CVE-2022-34799",
    "CVE-2022-34800",
    "CVE-2022-34801",
    "CVE-2022-34802",
    "CVE-2022-34803",
    "CVE-2022-34804",
    "CVE-2022-34805",
    "CVE-2022-34806",
    "CVE-2022-34807",
    "CVE-2022-34808",
    "CVE-2022-34809",
    "CVE-2022-34810",
    "CVE-2022-34811",
    "CVE-2022-34812",
    "CVE-2022-34813",
    "CVE-2022-34814",
    "CVE-2022-34815",
    "CVE-2022-34816",
    "CVE-2022-34817",
    "CVE-2022-34818"
  );

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2022-06-30)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Jenkins GitLab Plugin 1.5.34 and earlier does not escape multiple fields inserted into the description of
    webhook-triggered builds, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by
    attackers with Item/Configure permission. (CVE-2022-34777)

  - Jenkins TestNG Results Plugin 554.va4a552116332 and earlier renders the unescaped test descriptions and
    exception messages provided in test results if certain job-level options are set, resulting in a cross-
    site scripting (XSS) vulnerability exploitable by attackers able to configure jobs or control test
    results. (CVE-2022-34778)

  - A missing permission check in Jenkins XebiaLabs XL Release Plugin 22.0.0 and earlier allows attackers with
    Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins. (CVE-2022-34779)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins XebiaLabs XL Release Plugin 22.0.0 and
    earlier allows attackers to connect to an attacker-specified HTTP server using attacker-specified
    credentials IDs obtained through another method, capturing credentials stored in Jenkins. (CVE-2022-34780)

  - Missing permission checks in Jenkins XebiaLabs XL Release Plugin 22.0.0 and earlier allow attackers with
    Overall/Read permission to connect to an attacker-specified HTTP server using attacker-specified
    credentials IDs obtained through another method, capturing credentials stored in Jenkins. (CVE-2022-34781)

  - An incorrect permission check in Jenkins requests-plugin Plugin 2.2.16 and earlier allows attackers with
    Overall/Read permission to view the list of pending requests. (CVE-2022-34782)

  - Jenkins Plot Plugin 2.1.10 and earlier does not escape plot descriptions, resulting in a stored cross-site
    scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-34783)

  - Jenkins build-metrics Plugin 1.3 does not escape the build description on one of its views, resulting in a
    stored cross-site scripting (XSS) vulnerability exploitable by attackers with Build/Update permission.
    (CVE-2022-34784)

  - Jenkins build-metrics Plugin 1.3 and earlier does not perform permission checks in multiple HTTP
    endpoints, allowing attackers with Overall/Read permission to obtain information about jobs otherwise
    inaccessible to them. (CVE-2022-34785)

  - Jenkins Rich Text Publisher Plugin 1.4 and earlier does not escape the HTML message set by its post-build
    step, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to
    configure jobs. (CVE-2022-34786)

  - Jenkins Project Inheritance Plugin 21.04.03 and earlier does not escape the reason a build is blocked in
    tooltips, resulting in a cross-site scripting (XSS) vulnerability exploitable by attackers able to control
    the reason a queue item is blocked. (CVE-2022-34787)

  - Jenkins Matrix Reloaded Plugin 1.1.3 and earlier does not escape the agent name in tooltips, resulting in
    a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Agent/Configure
    permission. (CVE-2022-34788)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Matrix Reloaded Plugin 1.1.3 and earlier
    allows attackers to rebuild previous matrix builds. (CVE-2022-34789)

  - Jenkins eXtreme Feedback Panel Plugin 2.0.1 and earlier does not escape the job names used in tooltips,
    resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with
    Item/Configure permission. (CVE-2022-34790)

  - Jenkins Validating Email Parameter Plugin 1.10 and earlier does not escape the name and description of its
    parameter type, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers
    with Item/Configure permission. (CVE-2022-34791)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Recipe Plugin 1.2 and earlier allows
    attackers to send an HTTP request to an attacker-specified URL and parse the response as XML.
    (CVE-2022-34792)

  - Jenkins Recipe Plugin 1.2 and earlier does not configure its XML parser to prevent XML external entity
    (XXE) attacks. (CVE-2022-34793)

  - Missing permission checks in Jenkins Recipe Plugin 1.2 and earlier allow attackers with Overall/Read
    permission to send an HTTP request to an attacker-specified URL and parse the response as XML.
    (CVE-2022-34794)

  - Jenkins Deployment Dashboard Plugin 1.0.10 and earlier does not escape environment names on its Deployment
    Dashboard view, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers
    with View/Configure permission. (CVE-2022-34795)

  - A missing permission check in Jenkins Deployment Dashboard Plugin 1.0.10 and earlier allows attackers with
    Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins. (CVE-2022-34796)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Deployment Dashboard Plugin 1.0.10 and
    earlier allows attackers to connect to an attacker-specified HTTP URL using attacker-specified
    credentials. (CVE-2022-34797)

  - Jenkins Deployment Dashboard Plugin 1.0.10 and earlier does not perform a permission check in several HTTP
    endpoints, allowing attackers with Overall/Read permission to connect to an attacker-specified HTTP URL
    using attacker-specified credentials. (CVE-2022-34798)

  - Jenkins Deployment Dashboard Plugin 1.0.10 and earlier stores a password unencrypted in its global
    configuration file on the Jenkins controller where it can be viewed by users with access to the Jenkins
    controller file system. (CVE-2022-34799)

  - Jenkins Build Notifications Plugin 1.5.0 and earlier stores tokens unencrypted in its global configuration
    files on the Jenkins controller where they can be viewed by users with access to the Jenkins controller
    file system. (CVE-2022-34800)

  - Jenkins Build Notifications Plugin 1.5.0 and earlier transmits tokens in plain text as part of the global
    Jenkins configuration form, potentially resulting in their exposure. (CVE-2022-34801)

  - Jenkins RocketChat Notifier Plugin 1.5.2 and earlier stores the login password and webhook token
    unencrypted in its global configuration file on the Jenkins controller where they can be viewed by users
    with access to the Jenkins controller file system. (CVE-2022-34802)

  - Jenkins OpsGenie Plugin 1.9 and earlier stores API keys unencrypted in its global configuration file and
    in job config.xml files on the Jenkins controller where they can be viewed by users with Extended Read
    permission (config.xml), or access to the Jenkins controller file system. (CVE-2022-34803)

  - Jenkins OpsGenie Plugin 1.9 and earlier transmits API keys in plain text as part of the global Jenkins
    configuration form and job configuration forms, potentially resulting in their exposure. (CVE-2022-34804)

  - Jenkins Skype notifier Plugin 1.1.0 and earlier stores a password unencrypted in its global configuration
    file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file
    system. (CVE-2022-34805)

  - Jenkins Jigomerge Plugin 0.9 and earlier stores passwords unencrypted in job config.xml files on the
    Jenkins controller where they can be viewed by users with Extended Read permission, or access to the
    Jenkins controller file system. (CVE-2022-34806)

  - Jenkins Elasticsearch Query Plugin 1.2 and earlier stores a password unencrypted in its global
    configuration file on the Jenkins controller where it can be viewed by users with access to the Jenkins
    controller file system. (CVE-2022-34807)

  - Jenkins Cisco Spark Plugin 1.1.1 and earlier stores bearer tokens unencrypted in its global configuration
    file on the Jenkins controller where they can be viewed by users with access to the Jenkins controller
    file system. (CVE-2022-34808)

  - Jenkins RQM Plugin 2.8 and earlier stores a password unencrypted in its global configuration file on the
    Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.
    (CVE-2022-34809)

  - A missing check in Jenkins RQM Plugin 2.8 and earlier allows attackers with Overall/Read permission to
    enumerate credentials IDs of credentials stored in Jenkins. (CVE-2022-34810)

  - A missing permission check in Jenkins XPath Configuration Viewer Plugin 1.1.1 and earlier allows attackers
    with Overall/Read permission to access the XPath Configuration Viewer page. (CVE-2022-34811)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins XPath Configuration Viewer Plugin 1.1.1 and
    earlier allows attackers to create and delete XPath expressions. (CVE-2022-34812)

  - A missing permission check in Jenkins XPath Configuration Viewer Plugin 1.1.1 and earlier allows attackers
    with Overall/Read permission to create and delete XPath expressions. (CVE-2022-34813)

  - Jenkins Request Rename Or Delete Plugin 1.1.0 and earlier does not correctly perform a permission check in
    an HTTP endpoint, allowing attackers with Overall/Read permission to view an administrative configuration
    page listing pending requests. (CVE-2022-34814)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Request Rename Or Delete Plugin 1.1.0 and
    earlier allows attackers to accept pending requests, thereby renaming or deleting jobs. (CVE-2022-34815)

  - Jenkins HPE Network Virtualization Plugin 1.0 stores passwords unencrypted in its global configuration
    file on the Jenkins controller where they can be viewed by users with access to the Jenkins controller
    file system. (CVE-2022-34816)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Failed Job Deactivator Plugin 1.2.1 and
    earlier allows attackers to disable jobs. (CVE-2022-34817)

  - Jenkins Failed Job Deactivator Plugin 1.2.1 and earlier does not perform permission checks in several
    views and HTTP endpoints, allowing attackers with Overall/Read permission to disable jobs.
    (CVE-2022-34818)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-06-30");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Build Notifications Plugin: See vendor advisory
  - build-metrics Plugin: See vendor advisory
  - Cisco Spark Plugin: See vendor advisory
  - Deployment Dashboard Plugin: See vendor advisory
  - Elasticsearch Query Plugin: See vendor advisory
  - eXtreme Feedback Panel Plugin: See vendor advisory
  - Failed Job Deactivator Plugin: See vendor advisory
  - GitLab Plugin to version 1.5.35 or later
  - hpe-network-virtualization Plugin: See vendor advisory
  - Jigomerge Plugin: See vendor advisory
  - Matrix Reloaded Plugin: See vendor advisory
  - OpsGenie Plugin: See vendor advisory
  - Plot Plugin: See vendor advisory
  - Project Inheritance Plugin: See vendor advisory
  - Recipe Plugin: See vendor advisory
  - Request Rename Or Delete Plugin: See vendor advisory
  - requests-plugin Plugin to version 2.2.17 or later
  - Rich Text Publisher Plugin: See vendor advisory
  - RocketChat Notifier Plugin: See vendor advisory
  - RQM Plugin: See vendor advisory
  - Skype notifier Plugin: See vendor advisory
  - TestNG Results Plugin to version 555.va0d5f66521e3 or later
  - Validating Email Parameter Plugin: See vendor advisory
  - XebiaLabs XL Release Plugin to version 22.0.1 or later
  - XPath Configuration Viewer Plugin: See vendor advisory

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34793");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
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
    {'max_version' : '1.5.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Build Notifications Plugin'},
    {'max_version' : '1.3', 'fixed_display' : 'See vendor advisory', 'plugin' : 'build-metrics Plugin'},
    {'max_version' : '1.1.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Cisco Spark Plugin'},
    {'max_version' : '1.0.10', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Deployment Dashboard Plugin'},
    {'max_version' : '1.2', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Elasticsearch Query Plugin'},
    {'max_version' : '2.0.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'eXtreme Feedback Panel Plugin'},
    {'max_version' : '1.2.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Failed Job Deactivator Plugin'},
    {'max_version' : '1.5.34', 'fixed_version' : '1.5.35', 'plugin' : 'GitLab Plugin'},
    {'max_version' : '1.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'hpe-network-virtualization Plugin'},
    {'max_version' : '0.9', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Jigomerge Plugin'},
    {'max_version' : '1.1.3', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Matrix Reloaded Plugin'},
    {'max_version' : '1.9', 'fixed_display' : 'See vendor advisory', 'plugin' : 'OpsGenie Plugin'},
    {'max_version' : '2.1.10', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Plot Plugin'},
    {'max_version' : '21.04.03', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Project Inheritance Plugin'},
    {'max_version' : '1.2', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Recipe Plugin'},
    {'max_version' : '1.1.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Request Rename Or Delete Plugin'},
    {'max_version' : '2.2.16', 'fixed_version' : '2.2.17', 'plugin' : 'requests-plugin Plugin'},
    {'max_version' : '1.4', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Rich Text Publisher Plugin'},
    {'max_version' : '1.5.2', 'fixed_display' : 'See vendor advisory', 'plugin' : 'RocketChat Notifier Plugin'},
    {'max_version' : '2.8', 'fixed_display' : 'See vendor advisory', 'plugin' : 'RQM Plugin'},
    {'max_version' : '1.1.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Skype notifier Plugin'},
    {'max_version' : '554', 'fixed_version' : '555', 'fixed_display' : '555.va0d5f66521e3', 'plugin' : 'TestNG Results Plugin'},
    {'max_version' : '1.10', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Validating Email Parameter Plugin'},
    {'max_version' : '22.0.0', 'fixed_version' : '22.0.1', 'plugin' : 'XebiaLabs XL Release Plugin'},
    {'max_version' : '1.1.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'XPath Configuration Viewer Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
