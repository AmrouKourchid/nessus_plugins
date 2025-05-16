#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210929);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/16");

  script_cve_id(
    "CVE-2022-46751",
    "CVE-2024-52549",
    "CVE-2024-52550",
    "CVE-2024-52551",
    "CVE-2024-52552",
    "CVE-2024-52553",
    "CVE-2024-52554"
  );
  script_xref(name:"JENKINS", value:"2024-11-13");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2024-11-13)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Jenkins Script Security Plugin 1367.vdf2fc45f229c and earlier, except 1365.1367.va_3b_b_89f8a_95b_ and
    1362.1364.v4cf2dc5d8776, does not perform a permission check in a method implementing form validation,
    allowing attackers with Overall/Read permission to check for the existence of files on the controller file
    system. (CVE-2024-52549)

  - Jenkins Pipeline: Groovy Plugin 3990.vd281dd77a_388 and earlier, except 3975.3977.v478dd9e956c3 does not
    check whether the main (Jenkinsfile) script for a rebuilt build is approved, allowing attackers with
    Item/Build permission to rebuild a previous build whose (Jenkinsfile) script is no longer approved.
    (CVE-2024-52550)

  - Jenkins Pipeline: Declarative Plugin 2.2214.vb_b_34b_2ea_9b_83 and earlier does not check whether the main
    (Jenkinsfile) script used to restart a build from a specific stage is approved, allowing attackers with
    Item/Build permission to restart a previous build whose (Jenkinsfile) script is no longer approved.
    (CVE-2024-52551)

  - Jenkins Authorize Project Plugin 1.7.2 and earlier evaluates a string containing the job name with
    JavaScript on the Authorization view, resulting in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers with Item/Configure permission. (CVE-2024-52552)

  - Jenkins OpenId Connect Authentication Plugin 4.418.vccc7061f5b_6d and earlier does not invalidate the
    previous session on login. (CVE-2024-52553)

  - Improper Restriction of XML External Entity Reference, XML Injection (aka Blind XPath Injection)
    vulnerability in Apache Software Foundation Apache Ivy.This issue affects any version of Apache Ivy prior
    to 2.5.2. When Apache Ivy prior to 2.5.2 parses XML files - either its own configuration, Ivy files or
    Apache Maven POMs - it will allow downloading external document type definitions and expand any entity
    references contained therein when used. This can be used to exfiltrate data, access resources only the
    machine running Ivy has access to or disturb the execution of Ivy in different ways. Starting with Ivy
    2.5.2 DTD processing is disabled by default except when parsing Maven POMs where the default is to allow
    DTD processing but only to include a DTD snippet shipping with Ivy that is needed to deal with existing
    Maven POMs that are not valid XML files but are nevertheless accepted by Maven. Access can be be made more
    lenient via newly introduced system properties where needed. Users of Ivy prior to version 2.5.2 can use
    Java system properties to restrict processing of external DTDs, see the section about JAXP Properties for
    External Access restrictions inside Oracle's Java API for XML Processing (JAXP) Security Guide.
    (CVE-2022-46751)

  - Jenkins Shared Library Version Override Plugin 17.v786074c9fce7 and earlier declares folder-scoped library
    overrides as trusted, so that they're not executed in the Script Security sandbox, allowing attackers with
    Item/Configure permission on a folder to configure a folder-scoped library override that runs without
    sandbox protection. (CVE-2024-52554)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2024-11-13");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Authorize Project Plugin to version 1.8.0 or later
  - IvyTrigger Plugin to version 1.02 or later
  - OpenId Connect Authentication Plugin to version 4.421.v5422614eb_e0a_ or later
  - Pipeline: Declarative Plugin to version 2.2218.v56d0cda_37c72 or later
  - Pipeline: Groovy Plugin to version 3993.v3e20a_37282f8 or later
  - Script Security Plugin to version 1368.vb_b_402e3547e7 or later
  - Shared Library Version Override Plugin to version 19.v3a_c975738d4a_ or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46751");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var constraints = [
    {'max_version' : '1.7.2', 'fixed_version' : '1.8.0', 'plugin' : 'Authorize Project Plugin'},
    {'max_version' : '1.01', 'fixed_version' : '1.02', 'plugin' : 'IvyTrigger Plugin'},
    {'max_version' : '4.418', 'fixed_version' : '4.421', 'fixed_display' : '4.421.v5422614eb_e0a_', 'plugin' : 'OpenId Connect Authentication Plugin'},
    {'max_version' : '2.2214', 'fixed_version' : '2.2218', 'fixed_display' : '2.2218.v56d0cda_37c72', 'plugin' : 'Pipeline: Declarative Plugin'},
    {'max_version' : '3990', 'fixed_version' : '3993', 'fixed_display' : '3993.v3e20a_37282f8', 'plugin' : 'Pipeline: Groovy Plugin'},
    {'max_version' : '1367', 'fixed_version' : '1368', 'fixed_display' : '1368.vb_b_402e3547e7', 'plugin' : 'Script Security Plugin'},
    {'max_version' : '17', 'fixed_version' : '19', 'fixed_display' : '19.v3a_c975738d4a_', 'plugin' : 'Shared Library Version Override Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
