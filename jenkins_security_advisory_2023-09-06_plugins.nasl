#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180576);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2022-46751",
    "CVE-2023-41930",
    "CVE-2023-41931",
    "CVE-2023-41932",
    "CVE-2023-41933",
    "CVE-2023-41934",
    "CVE-2023-41935",
    "CVE-2023-41936",
    "CVE-2023-41937",
    "CVE-2023-41938",
    "CVE-2023-41939",
    "CVE-2023-41940",
    "CVE-2023-41941",
    "CVE-2023-41942",
    "CVE-2023-41943",
    "CVE-2023-41944",
    "CVE-2023-41945",
    "CVE-2023-41946",
    "CVE-2023-41947"
  );
  script_xref(name:"JENKINS", value:"2023-09-06");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2023-09-06)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Jenkins Job Configuration History Plugin 1227.v7a_79fc4dc01f and earlier does not restrict the 'name'
    query parameter when rendering a history entry, allowing attackers to have Jenkins render a manipulated
    configuration history that was not created by the plugin. (CVE-2023-41930)

  - Jenkins Job Configuration History Plugin 1227.v7a_79fc4dc01f and earlier does not restrict 'timestamp'
    query parameters in multiple endpoints, allowing attackers with to delete attacker-specified directories
    on the Jenkins controller file system as long as they contain a file called 'history.xml'.
    (CVE-2023-41932)

  - Jenkins Job Configuration History Plugin 1227.v7a_79fc4dc01f and earlier does not configure its XML parser
    to prevent XML external entity (XXE) attacks. (CVE-2023-41933)

  - Jenkins Azure AD Plugin 396.v86ce29279947 and earlier, except 378.380.v545b_1154b_3fb_, uses a non-
    constant time comparison function when checking whether the provided and expected CSRF protection nonce
    are equal, potentially allowing attackers to use statistical methods to obtain a valid nonce.
    (CVE-2023-41935)

  - Jenkins Google Login Plugin 1.7 and earlier uses a non-constant time comparison function when checking
    whether the provided and expected token are equal, potentially allowing attackers to use statistical
    methods to obtain a valid token. (CVE-2023-41936)

  - Jenkins Bitbucket Push and Pull Request Plugin 2.4.0 through 2.8.3 (both inclusive) trusts values provided
    in the webhook payload, including certain URLs, and uses configured Bitbucket credentials to connect to
    those URLs, allowing attackers to capture Bitbucket credentials stored in Jenkins by sending a crafted
    webhook payload. (CVE-2023-41937)

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

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Ivy Plugin 2.5 and earlier allows attackers
    to delete disabled modules. (CVE-2023-41938)

  - Jenkins SSH2 Easy Plugin 1.4 and earlier does not verify that permissions configured to be granted are
    enabled, potentially allowing users formerly granted (typically optional permissions, like Overall/Manage)
    to access functionality they're no longer entitled to. (CVE-2023-41939)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins AWS CodeCommit Trigger Plugin 3.0.12 and
    earlier allows attackers to clear the SQS queue. (CVE-2023-41942)

  - Jenkins AWS CodeCommit Trigger Plugin 3.0.12 and earlier does not escape the queue name parameter passed
    to a form validation URL, when rendering an error message, resulting in an HTML injection vulnerability.
    (CVE-2023-41944)

  - Jenkins Assembla Auth Plugin 1.14 and earlier does not verify that the permissions it grants are enabled,
    resulting in users with EDIT permissions to be granted Overall/Manage and Overall/SystemRead permissions,
    even if those permissions are disabled and should not be granted. (CVE-2023-41945)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Frugal Testing Plugin 1.1 and earlier allows
    attackers to connect to Frugal Testing using attacker-specified credentials, and to retrieve test IDs and
    names from Frugal Testing, if a valid credential corresponds to the attacker-specified username.
    (CVE-2023-41946)

  - A missing permission check in Jenkins Frugal Testing Plugin 1.1 and earlier allows attackers with
    Overall/Read permission to connect to Frugal Testing using attacker-specified credentials.
    (CVE-2023-41947)

  - Path traversal allows exploiting XSS vulnerability in Job Configuration History Plugin (CVE-2023-41931)

  - Improper masking of credentials in Pipeline Maven Integration Plugin (CVE-2023-41934)

  - Stored XSS vulnerability in TAP Plugin (CVE-2023-41940)

  - Missing permission check in AWS CodeCommit Trigger Plugin allows enumerating credentials IDs
    (CVE-2023-41941)

  - CSRF vulnerability and missing permission check in AWS CodeCommit Trigger Plugin (CVE-2023-41943)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2023-09-06");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Assembla Auth Plugin: See vendor advisory
  - AWS CodeCommit Trigger Plugin: See vendor advisory
  - Azure AD Plugin: See vendor advisory
  - Bitbucket Push and Pull Request Plugin to version 2.8.4 or later
  - Frugal Testing Plugin: See vendor advisory
  - Google Login Plugin to version 1.8 or later
  - Ivy Plugin: See vendor advisory
  - Job Configuration History Plugin to version 1229.v3039470161a_d or later
  - Pipeline Maven Integration Plugin to version 1331.v003efa_fd6e81 or later
  - Qualys Container Scanning Connector Plugin to version 1.6.2.7 or later
  - SSH2 Easy Plugin to version 1.6 or later
  - TAP Plugin: See vendor advisory

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41945");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

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

include('vcf.inc');
include('vcf_extras.inc');
include('jenkins_plugin_mappings.inc');

var constraints = [
    {'max_version' : '1.14', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Assembla Auth Plugin'},
    {'max_version' : '3.0.12', 'fixed_display' : 'See vendor advisory', 'plugin' : 'AWS CodeCommit Trigger Plugin'},
    {'fixed_version' : '378.380', 'fixed_display' : '397.v907382dd9b_98 or 378.380.v545b_1154b_3fb_', 'plugin' : 'Azure AD Plugin'},
    {'min_version' : '379', 'max_version' : '396', 'fixed_version' : '397', 'fixed_display' : '397.v907382dd9b_98 or 378.380.v545b_1154b_3fb_', 'plugin' : 'Azure AD Plugin'},
    {'min_version' : '2.4.0', 'max_version' : '2.8.3', 'fixed_version' : '2.8.4', 'plugin' : 'Bitbucket Push and Pull Request Plugin'},
    {'max_version' : '1.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Frugal Testing Plugin'},
    {'max_version' : '1.7', 'fixed_version' : '1.8', 'plugin' : 'Google Login Plugin'},
    {'max_version' : '2.5', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Ivy Plugin'},
    {'max_version' : '1227', 'fixed_version' : '1229', 'fixed_display' : '1229.v3039470161a_d', 'plugin' : 'Job Configuration History Plugin'},
    {'max_version' : '1330', 'fixed_version' : '1331', 'fixed_display' : '1331.v003efa_fd6e81', 'plugin' : 'Pipeline Maven Integration Plugin'},
    {'max_version' : '1.6.2.6', 'fixed_version' : '1.6.2.7', 'plugin' : 'Qualys Container Scanning Connector Plugin'},
    {'max_version' : '1.4', 'fixed_version' : '1.6', 'plugin' : 'SSH2 Easy Plugin'},
    {'max_version' : '2.3', 'fixed_display' : 'See vendor advisory', 'plugin' : 'TAP Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
