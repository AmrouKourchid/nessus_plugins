##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163259);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2022-34170",
    "CVE-2022-34171",
    "CVE-2022-34172",
    "CVE-2022-34173",
    "CVE-2022-34174",
    "CVE-2022-34175",
    "CVE-2022-34176",
    "CVE-2022-34177",
    "CVE-2022-34178",
    "CVE-2022-34179",
    "CVE-2022-34180",
    "CVE-2022-34181",
    "CVE-2022-34182",
    "CVE-2022-34183",
    "CVE-2022-34184",
    "CVE-2022-34185",
    "CVE-2022-34186",
    "CVE-2022-34187",
    "CVE-2022-34188",
    "CVE-2022-34189",
    "CVE-2022-34190",
    "CVE-2022-34191",
    "CVE-2022-34192",
    "CVE-2022-34193",
    "CVE-2022-34194",
    "CVE-2022-34195",
    "CVE-2022-34196",
    "CVE-2022-34197",
    "CVE-2022-34198",
    "CVE-2022-34199",
    "CVE-2022-34200",
    "CVE-2022-34201",
    "CVE-2022-34202",
    "CVE-2022-34203",
    "CVE-2022-34204",
    "CVE-2022-34205",
    "CVE-2022-34206",
    "CVE-2022-34207",
    "CVE-2022-34208",
    "CVE-2022-34209",
    "CVE-2022-34210",
    "CVE-2022-34211",
    "CVE-2022-34212",
    "CVE-2022-34213"
  );

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2022-06-22)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Multiple cross-site scripting (XSS) vulnerabilities in Jenkins 2.355 and earlier, LTS 2.332.3 and earlier
    allow attackers to inject HTML and JavaScript into the Jenkins UI: SECURITY-2779 (CVE-2022-34170): Since
    Jenkins 2.320 and LTS 2.332.1, help icon tooltips no longer escape the feature name, effectively undoing
    the fix for SECURITY-1955. SECURITY-2761 (CVE-2022-34171): Since Jenkins 2.321 and LTS 2.332.1, the HTML
    output generated for new symbol-based SVG icons includes the title attribute of l:ionicon until Jenkins
    2.334 and alt attribute of l:icon since Jenkins 2.335 without further escaping. SECURITY-2776
    (CVE-2022-34172): Since Jenkins 2.340, symbol-based icons unescape previously escaped values of tooltip
    parameters. SECURITY-2780 (CVE-2022-34173): Since Jenkins 2.340, the tooltip of the build button in list
    views supports HTML without escaping the job display name. These vulnerabilities are known to be
    exploitable by attackers with Job/Configure permission. Jenkins 2.356, LTS 2.332.4 and LTS 2.346.1
    addresses these vulnerabilities: SECURITY-2779: The feature name in help icon tooltips is now escaped.
    SECURITY-2761: The title attribute of l:ionicon (Jenkins LTS 2.332.4) and alt attribute of l:icon (Jenkins
    2.356 and LTS 2.346.1) are escaped in the generated HTML output. SECURITY-2776: Symbol-based icons no
    longer unescape values of tooltip parameters. SECURITY-2780: The tooltip of the build button in list views
    is now escaped. No Jenkins LTS release is affected by SECURITY-2776 or SECURITY-2780, as these were not
    present in Jenkins 2.332.x and fixed in the 2.346.x line before 2.346.1. (CVE-2022-34170, CVE-2022-34171,
    CVE-2022-34172, CVE-2022-34173)

  - In Jenkins 2.355 and earlier, LTS 2.332.3 and earlier, an observable timing discrepancy on the login form
    allows distinguishing between login attempts with an invalid username, and login attempts with a valid
    username and wrong password, when using the Jenkins user database security realm. This allows attackers to
    determine the validity of attacker-specified usernames. Login attempts with an invalid username now
    validate a synthetic password to eliminate the timing discrepancy in Jenkins 2.356, LTS 2.332.4.
    (CVE-2022-34174)

  - Jenkins uses the Stapler web framework to render its UI views. These views are frequently composed of
    several view fragments, enabling plugins to extend existing views with more content. Before SECURITY-534
    was fixed in Jenkins 2.186 and LTS 2.176.2, attackers could in some cases directly access a view fragment
    containing sensitive information, bypassing any permission checks in the corresponding view. In Jenkins
    2.335 through 2.355 (both inclusive), the protection added for SECURITY-534 is disabled for some views. As
    a result, attackers could in very limited cases directly access a view fragment containing sensitive
    information, bypassing any permission checks in the corresponding view. As of publication, the Jenkins
    security team is unaware of any vulnerable view fragment across the Jenkins plugin ecosystem. Jenkins
    2.356 restores the protection for affected views. (CVE-2022-34175)

  - JUnit Plugin 1119.va_a_5e9068da_d7 and earlier does not escape descriptions of test results. This results
    in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Run/Update permission.
    JUnit Plugin 1119.1121.vc43d0fc45561 applies the configured markup formatter to descriptions of test
    results. (CVE-2022-34176)

  - Pipeline: Input Step Plugin 448.v37cea_9a_10a_70 and earlier allows Pipeline authors to specify file
    parameters for Pipeline input steps even though they are unsupported. Although the uploaded file is not
    copied to the workspace, Jenkins archives the file on the controller as part of build metadata using the
    parameter name without sanitization as a relative path inside a build-related directory. This allows
    attackers able to configure Pipelines to create or replace arbitrary files on the Jenkins controller file
    system with attacker-specified content. Pipeline: Input Step Plugin 449.v77f0e8b_845c4 prohibits use of
    file parameters for Pipeline input steps. Attempts to use them will fail Pipeline execution.
    (CVE-2022-34177)

  - Embeddable Build Status Plugin 2.0.3 allows specifying a link query parameter that build status badges
    will link to, without restricting possible values. This results in a reflected cross-site scripting (XSS)
    vulnerability. Embeddable Build Status Plugin 2.0.4 limits URLs to http and https protocols and correctly
    escapes the provided value. (CVE-2022-34178)

  - Embeddable Build Status Plugin 2.0.3 and earlier allows specifying a style query parameter that is used to
    choose a different SVG image style without restricting possible values. This results in a relative path
    traversal vulnerability, allowing attackers without Overall/Read permission to specify paths to other SVG
    images on the Jenkins controller file system. Embeddable Build Status Plugin 2.0.4 restricts the style
    query parameter to one of the three legal values. (CVE-2022-34179)

  - Embeddable Build Status Plugin 2.0.3 and earlier does not correctly perform the ViewStatus permission
    check in the HTTP endpoint it provides for unprotected status badge access. This allows attackers
    without any permissions to obtain the build status badge icon for any attacker-specified job and/or build.
    Embeddable Build Status Plugin 2.0.4 requires ViewStatus permission to obtain the build status badge icon.
    (CVE-2022-34180)

  - xUnit Plugin 3.0.8 and earlier implements an agent-to-controller message that creates a user-specified
    directory if it doesn't exist, and parsing files inside it as test results. This allows attackers able to
    control agent processes to create an arbitrary directory on the Jenkins controller or to obtain test
    results from existing files in an attacker-specified directory. xUnit Plugin 3.1.0 changes the message
    type from agent-to-controller to controller-to-agent, preventing execution on the controller.
    (CVE-2022-34181)

  - Nested View Plugin 1.20 through 1.25 (both inclusive) does not escape search parameters. This results in a
    reflected cross-site scripting (XSS) vulnerability. Nested View Plugin 1.26 escapes search parameters.
    (CVE-2022-34182)

  - Multiple plugins do not escape the name and description of the parameter types they provide: Agent Server
    Parameter 1.1 and earlier (SECURITY-2731 / CVE-2022-34183) CRX Content Package Deployer 1.9 and earlier
    (SECURITY-2727 / CVE-2022-34184) Date Parameter Plugin 0.0.4 and earlier (SECURITY-2711 / CVE-2022-34185)
    Dynamic Extended Choice Parameter 1.0.1 and earlier (SECURITY-2712 / CVE-2022-34186) Filesystem List
    Parameter 0.0.7 and earlier (SECURITY-2716 / CVE-2022-34187) Hidden Parameter Plugin 0.0.4 and earlier
    (SECURITY-2755 / CVE-2022-34188) Image Tag Parameter 1.10 and earlier (SECURITY-2721 / CVE-2022-34189)
    Maven Metadata for CI server 2.1 and earlier (SECURITY-2714 / CVE-2022-34190) NS-ND Integration
    Performance Publisher 4.8.0.77 and earlier (SECURITY-2736 / CVE-2022-34191) ontrack Jenkins 4.0.0 and
    earlier (SECURITY-2733 / CVE-2022-34192) Package Version 1.0.1 and earlier (SECURITY-2735 /
    CVE-2022-34193) Readonly Parameter 1.0.0 and earlier (SECURITY-2719 / CVE-2022-34194) Repository Connector
    2.2.0 and earlier (SECURITY-2666 / CVE-2022-34195) REST List Parameter Plugin 1.5.2 and earlier
    (SECURITY-2730 / CVE-2022-34196) Sauce OnDemand 1.204 and earlier (SECURITY-2724 / CVE-2022-34197) Stash
    Branch Parameter 0.3.0 and earlier (SECURITY-2725 / CVE-2022-34198) This results in stored cross-site
    scripting (XSS) vulnerabilites exploitable by attackers with Item/Configure permission. Exploitation of
    these vulnerabilities requires that parameters are listed on another page, like the Build With
    Parameters and Parameters pages provided by Jenkins (core), and that those pages are not hardened to
    prevent exploitation. Jenkins (core) has prevented exploitation of vulnerabilities of this kind on the
    Build With Parameters and Parameters pages since 2.44 and LTS 2.32.2 as part of the SECURITY-353 /
    CVE-2017-2601 fix. Additionally, several plugins have previously been updated to list parameters in a way
    that prevents exploitation by default, see SECURITY-2617 in the 2022-04-12 security advisory for a list.
    The following plugins have been updated to escape the name and description of the parameter types they
    provide in the versions specified: REST List Parameter Plugin 1.6.0 Hidden Parameter Plugin 0.0.5 As of
    publication of this advisory, there is no fix available for the following plugins: Agent Server Parameter
    1.1 and earlier (SECURITY-2731 / CVE-2022-34183) CRX Content Package Deployer 1.9 and earlier
    (SECURITY-2727 / CVE-2022-34184) Date Parameter Plugin 0.0.4 and earlier (SECURITY-2711 / CVE-2022-34185)
    Dynamic Extended Choice Parameter 1.0.1 and earlier (SECURITY-2712 / CVE-2022-34186) Filesystem List
    Parameter 0.0.7 and earlier (SECURITY-2716 / CVE-2022-34187) Image Tag Parameter 1.10 and earlier
    (SECURITY-2721 / CVE-2022-34189) Maven Metadata for CI server 2.1 and earlier (SECURITY-2714 /
    CVE-2022-34190) NS-ND Integration Performance Publisher 4.8.0.77 and earlier (SECURITY-2736 /
    CVE-2022-34191) ontrack Jenkins 4.0.0 and earlier (SECURITY-2733 / CVE-2022-34192) Package Version 1.0.1
    and earlier (SECURITY-2735 / CVE-2022-34193) Readonly Parameter 1.0.0 and earlier (SECURITY-2719 /
    CVE-2022-34194) Repository Connector 2.2.0 and earlier (SECURITY-2666 / CVE-2022-34195) Sauce OnDemand
    1.204 and earlier (SECURITY-2724 / CVE-2022-34197) Stash Branch Parameter 0.3.0 and earlier (SECURITY-2725
    / CVE-2022-34198) (CVE-2022-34183, CVE-2022-34184, CVE-2022-34185, CVE-2022-34186, CVE-2022-34187,
    CVE-2022-34188, CVE-2022-34189, CVE-2022-34190, CVE-2022-34191, CVE-2022-34192, CVE-2022-34193,
    CVE-2022-34194, CVE-2022-34195, CVE-2022-34196, CVE-2022-34197, CVE-2022-34198)

  - Convertigo Mobile Platform Plugin 1.1 and earlier stores passwords unencrypted in job config.xml files on
    the Jenkins controller as part of its configuration. These passwords can be viewed by users with
    Item/Extended Read permission or access to the Jenkins controller file system. As of publication of this
    advisory, there is no fix. (CVE-2022-34199)

  - Convertigo Mobile Platform Plugin 1.1 and earlier does not perform a permission check in a method
    implementing form validation. This allows attackers with Overall/Read permission to connect to an
    attacker-specified URL. Additionally, this form validation method does not require POST requests,
    resulting in a cross-site request forgery (CSRF) vulnerability. As of publication of this advisory, there
    is no fix. (CVE-2022-34200, CVE-2022-34201)

  - EasyQA Plugin 1.0 and earlier stores user passwords unencrypted in its global configuration file
    EasyQAPluginProperties.xml on the Jenkins controller as part of its configuration. These passwords can be
    viewed by users with access to the Jenkins controller file system. As of publication of this advisory,
    there is no fix. (CVE-2022-34202)

  - EasyQA Plugin 1.0 and earlier does not perform a permission check in a method implementing form
    validation. This allows attackers with Overall/Read permission to connect to an attacker-specified HTTP
    server. Additionally, this form validation method does not require POST requests, resulting in a cross-
    site request forgery (CSRF) vulnerability. As of publication of this advisory, there is no fix.
    (CVE-2022-34203, CVE-2022-34204)

  - Jianliao Notification Plugin 1.1 and earlier does not perform a permission check in a method implementing
    form validation. This allows attackers with Overall/Read permission to send HTTP POST requests to an
    attacker-specified URL. Additionally, this form validation method does not require POST requests,
    resulting in a cross-site request forgery (CSRF) vulnerability. As of publication of this advisory, there
    is no fix. (CVE-2022-34205, CVE-2022-34206)

  - Beaker builder Plugin 1.10 and earlier does not perform a permission check in a method implementing form
    validation. This allows attackers with Overall/Read permission to connect to an attacker-specified URL.
    Additionally, this form validation method does not require POST requests, resulting in a cross-site
    request forgery (CSRF) vulnerability. As of publication of this advisory, there is no fix.
    (CVE-2022-34207, CVE-2022-34208)

  - ThreadFix Plugin 1.5.4 and earlier does not perform a permission check in a method implementing form
    validation. This allows attackers with Overall/Read permission to connect to an attacker-specified URL.
    Additionally, this form validation method does not require POST requests, resulting in a cross-site
    request forgery (CSRF) vulnerability. As of publication of this advisory, there is no fix.
    (CVE-2022-34209, CVE-2022-34210)

  - vRealize Orchestrator Plugin 3.0 and earlier does not perform a permission check in an HTTP endpoint. This
    allows attackers with Overall/Read permission to send an HTTP POST request to an attacker-specified URL.
    Additionally, this HTTP endpoint does not require POST requests, resulting in a cross-site request forgery
    (CSRF) vulnerability. As of publication of this advisory, there is no fix. (CVE-2022-34211,
    CVE-2022-34212)

  - Squash TM Publisher (Squash4Jenkins) Plugin 1.0.0 and earlier stores passwords unencrypted in its global
    configuration file org.jenkinsci.squashtm.core.SquashTMPublisher.xml on the Jenkins controller as part of
    its configuration. These passwords can be viewed by users with access to the Jenkins controller file
    system. As of publication of this advisory, there is no fix. (CVE-2022-34213)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-06-22");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Agent Server Parameter Plugin: See vendor advisory
  - Beaker builder Plugin: See vendor advisory
  - Convertigo Mobile Platform Plugin: See vendor advisory
  - CRX Content Package Deployer Plugin: See vendor advisory
  - Date Parameter Plugin: See vendor advisory
  - Dynamic Extended Choice Parameter Plugin: See vendor advisory
  - EasyQA Plugin: See vendor advisory
  - Embeddable Build Status Plugin to version 2.0.4 or later
  - Filesystem List Parameter Plugin: See vendor advisory
  - Hidden Parameter Plugin to version 0.0.5 or later
  - Image Tag Parameter Plugin: See vendor advisory
  - Jianliao Notification Plugin: See vendor advisory
  - JUnit Plugin to version 1119.1121.vc43d0fc45561 or later
  - Maven Metadata Plugin for Jenkins CI server Plugin: See vendor advisory
  - Nested View Plugin to version 1.26 or later
  - NS-ND Integration Performance Publisher Plugin: See vendor advisory
  - ontrack Jenkins Plugin: See vendor advisory
  - Package Version Plugin: See vendor advisory
  - Pipeline: Input Step Plugin to version 449.v77f0e8b_845c4 or later
  - Readonly Parameter Plugin: See vendor advisory
  - Repository Connector Plugin: See vendor advisory
  - REST List Parameter Plugin to version 1.6.0 or later
  - Sauce OnDemand Plugin: See vendor advisory
  - Squash TM Publisher (Squash4Jenkins) Plugin: See vendor advisory
  - Stash Branch Parameter Plugin: See vendor advisory
  - ThreadFix Plugin: See vendor advisory
  - vRealize Orchestrator Plugin: See vendor advisory
  - xUnit Plugin to version 3.1.0 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34203");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-34181");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var constraints = [
    {'max_version' : '1.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Agent Server Parameter Plugin'},
    {'max_version' : '1.10', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Beaker builder Plugin'},
    {'max_version' : '1.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Convertigo Mobile Platform Plugin'},
    {'max_version' : '1.9', 'fixed_display' : 'See vendor advisory', 'plugin' : 'CRX Content Package Deployer Plugin'},
    {'max_version' : '0.0.4', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Date Parameter Plugin'},
    {'max_version' : '1.0.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Dynamic Extended Choice Parameter Plugin'},
    {'max_version' : '1.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'EasyQA Plugin'},
    {'max_version' : '2.0.3', 'fixed_version' : '2.0.4', 'plugin' : 'Embeddable Build Status Plugin'},
    {'max_version' : '0.0.7', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Filesystem List Parameter Plugin'},
    {'max_version' : '0.0.4', 'fixed_version' : '0.0.5', 'plugin' : 'Hidden Parameter Plugin'},
    {'max_version' : '1.10', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Image Tag Parameter Plugin'},
    {'max_version' : '1.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Jianliao Notification Plugin'},
    {'max_version' : '1119', 'fixed_version' : '1119.1121', 'fixed_display' : '1119.1121.vc43d0fc45561', 'plugin' : 'JUnit Plugin'},
    {'max_version' : '2.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Maven Metadata Plugin for Jenkins CI server Plugin'},
    {'max_version' : '1.25', 'fixed_version' : '1.26', 'plugin' : 'Nested View Plugin'},
    {'max_version' : '4.8.0.77', 'fixed_display' : 'See vendor advisory', 'plugin' : 'NS-ND Integration Performance Publisher Plugin'},
    {'max_version' : '4.0.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'ontrack Jenkins Plugin'},
    {'max_version' : '1.0.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Package Version Plugin'},
    {'max_version' : '448', 'fixed_version' : '449', 'fixed_display' : '449.v77f0e8b_845c4', 'plugin' : 'Pipeline: Input Step Plugin'},
    {'max_version' : '1.0.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Readonly Parameter Plugin'},
    {'max_version' : '2.2.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Repository Connector Plugin'},
    {'max_version' : '1.5.2', 'fixed_version' : '1.6.0', 'plugin' : 'REST List Parameter Plugin'},
    {'max_version' : '1.204', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Sauce OnDemand Plugin'},
    {'max_version' : '1.0.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Squash TM Publisher (Squash4Jenkins) Plugin'},
    {'max_version' : '0.3.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Stash Branch Parameter Plugin'},
    {'max_version' : '1.5.4', 'fixed_display' : 'See vendor advisory', 'plugin' : 'ThreadFix Plugin'},
    {'max_version' : '3.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'vRealize Orchestrator Plugin'},
    {'max_version' : '3.0.8', 'fixed_version' : '3.1.0', 'plugin' : 'xUnit Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
