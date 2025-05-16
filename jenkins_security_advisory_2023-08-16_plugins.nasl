#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180006);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2023-4301",
    "CVE-2023-4302",
    "CVE-2023-4303",
    "CVE-2023-40336",
    "CVE-2023-40337",
    "CVE-2023-40338",
    "CVE-2023-40339",
    "CVE-2023-40340",
    "CVE-2023-40341",
    "CVE-2023-40342",
    "CVE-2023-40343",
    "CVE-2023-40344",
    "CVE-2023-40345",
    "CVE-2023-40346",
    "CVE-2023-40347",
    "CVE-2023-40348",
    "CVE-2023-40349",
    "CVE-2023-40350",
    "CVE-2023-40351"
  );
  script_xref(name:"JENKINS", value:"2023-08-16");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2023-08-16)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - High Folders Plugin 6.846.v23698686f0f6 and earlier does not require POST requests for an HTTP endpoint,
    resulting in a cross-site request forgery (CSRF) vulnerability. This vulnerability allows attackers to
    copy an item, which could potentially automatically approve unsandboxed scripts and allow the execution of
    unsafe scripts. An improvement added in Script Security Plugin 1265.va_fb_290b_4b_d34 and
    1251.1253.v4e638b_e3b_221 prevents automatic approval of unsandboxed scripts when administrators copy
    jobs, significantly reducing the impact of this vulnerability. Folders Plugin 6.848.ve3b_fd7839a_81
    requires POST requests for the affected HTTP endpoint. (CVE-2023-40336)

  - Medium Folders Plugin 6.846.v23698686f0f6 and earlier does not require POST requests for an HTTP endpoint,
    resulting in a cross-site request forgery (CSRF) vulnerability. This vulnerability allows attackers to
    copy a view inside a folder. Folders Plugin 6.848.ve3b_fd7839a_81 requires POST requests for the affected
    HTTP endpoint. (CVE-2023-40337)

  - Medium Folders Plugin displays an error message when attempting to access the Scan Organization Folder Log
    if no logs are available. In Folders Plugin 6.846.v23698686f0f6 and earlier, this error message includes
    the absolute path of a log file, exposing information about the Jenkins controller file system. Folders
    Plugin 6.848.ve3b_fd7839a_81 does not display the absolute path of a log file in the error message.
    (CVE-2023-40338)

  - Medium Config File Provider Plugin 952.va_544a_6234b_46 and earlier does not mask (i.e., replace with
    asterisks) credentials specified in configuration files when they're written to the build log. Config File
    Provider Plugin 953.v0432a_802e4d2 masks credentials configured in configuration files if they appear in
    the build log. (CVE-2023-40339)

  - Medium NodeJS Plugin integrates with Config File Provider Plugin to specify custom NPM settings, including
    credentials for authentication, in a Npm config file. NodeJS Plugin 1.6.0 and earlier does not properly
    mask (i.e., replace with asterisks) credentials specified in the Npm config file in Pipeline build logs.
    NodeJS Plugin 1.6.0.1 masks credentials specified in the Npm config file in Pipeline build logs.
    (CVE-2023-40340)

  - Medium Blue Ocean Plugin 1.27.5 and earlier does not require POST requests for an HTTP endpoint, resulting
    in a cross-site request forgery (CSRF) vulnerability. This vulnerability allows attackers to connect to an
    attacker-specified URL, capturing GitHub credentials associated with an attacker-specified job. This issue
    is due to an incomplete fix of SECURITY-2502. Blue Ocean Plugin 1.27.5.1 uses the configured SCM URL,
    instead of a user-specified URL provided as a parameter to the HTTP endpoint. (CVE-2023-40341)

  - Medium Fortify Plugin 22.1.38 and earlier does not perform permission checks in several HTTP endpoints.
    This allows attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-
    specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.
    Additionally, these HTTP endpoints do not require POST requests, resulting in a cross-site request forgery
    (CSRF) vulnerability. Fortify Plugin 22.2.39 requires POST requests and the appropriate permissions for
    the affected HTTP endpoints. (CVE-2023-4301, CVE-2023-4302)

  - Medium Fortify Plugin 22.1.38 and earlier does not escape the error message for a form validation method.
    This results in an HTML injection vulnerability. Since Jenkins 2.275 and LTS 2.263.2, a security hardening
    for form validation responses prevents JavaScript execution, so no scripts can be injected. Fortify Plugin
    22.2.39 removes HTML tags from the error message. (CVE-2023-4303)

  - High Flaky Test Handler Plugin 1.2.2 and earlier does not escape JUnit test contents when showing them on
    the Jenkins UI. This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers
    able to control JUnit report file contents. Flaky Test Handler Plugin 1.2.3 escapes JUnit test contents
    when showing them on the Jenkins UI. (CVE-2023-40342)

  - Low Tuleap Authentication Plugin 1.1.20 and earlier does not use a constant-time comparison when checking
    whether two authentication tokens are equal. This could potentially allow attackers to use statistical
    methods to obtain a valid authentication token. Tuleap Authentication Plugin 1.1.21 uses a constant-time
    comparison when validating authentication tokens. (CVE-2023-40343)

  - Medium Delphix Plugin 3.0.2 and earlier does not perform a permission check in an HTTP endpoint. This
    allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in
    Jenkins. Those can be used as part of an attack to capture the credentials using another vulnerability. An
    enumeration of credentials IDs in Delphix Plugin 3.0.3 requires the appropriate permissions.
    (CVE-2023-40344)

  - Medium Delphix Plugin 3.0.2 and earlier does not set the appropriate context for credentials lookup,
    allowing the use of System-scoped credentials otherwise reserved for the global configuration. This allows
    attackers with Overall/Read permission to access and capture credentials they are not entitled to. Delphix
    Plugin 3.0.3 defines the appropriate context for credentials lookup. (CVE-2023-40345)

  - High Shortcut Job Plugin 0.4 and earlier does not escape the shortcut redirection URL. This results in a
    stored cross-site scripting (XSS) vulnerability exploitable by attackers able to configure shortcut jobs.
    Shortcut Job Plugin 0.5 escapes the shortcut redirection URL. (CVE-2023-40346)

  - Medium Maven Artifact ChoiceListProvider (Nexus) Plugin 1.14 and earlier does not set the appropriate
    context for credentials lookup, allowing the use of System-scoped credentials otherwise reserved for the
    global configuration. This allows attackers with Item/Configure permission to access and capture
    credentials they are not entitled to. As of publication of this advisory, there is no fix. Learn why we
    announce this. (CVE-2023-40347)

  - Medium Gogs Plugin provides a webhook endpoint at /gogs-webhook that can be used to trigger builds of
    jobs. In Gogs Plugin 1.0.15 and earlier, an option to specify a Gogs secret for this webhook is provided,
    but not enabled by default. This allows unauthenticated attackers to trigger builds of jobs corresponding
    to the attacker-specified job name. Additionally, the output of the webhook endpoint includes whether a
    job corresponding to the attacker-specified job name exists, even if the attacker has no permission to
    access it. As of publication of this advisory, there is no fix. Learn why we announce this.
    (CVE-2023-40348, CVE-2023-40349)

  - High Docker Swarm Plugin processes Docker responses to generate the Docker Swarm Dashboard view. Docker
    Swarm Plugin 1.11 and earlier does not escape values returned from Docker before inserting them into the
    Docker Swarm Dashboard view. This results in a stored cross-site scripting (XSS) vulnerability exploitable
    by attackers able to control responses from Docker. As of publication of this advisory, there is no fix.
    Learn why we announce this. (CVE-2023-40350)

  - Medium Favorite View Plugin 5.v77a_37f62782d and earlier does not require POST requests for an HTTP
    endpoint, resulting in a cross-site request forgery (CSRF) vulnerability. This vulnerability allows
    attackers to add or remove views from another user's favorite views tab bar. As of publication of this
    advisory, there is no fix. Learn why we announce this. (CVE-2023-40351)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2023-08-16");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Blue Ocean Plugin to version 1.27.5.1 or later
  - Config File Provider Plugin to version 953.v0432a_802e4d2 or later
  - Delphix Plugin to version 3.0.3 or later
  - Docker Swarm Plugin: See vendor advisory
  - Favorite View Plugin: See vendor advisory
  - Flaky Test Handler Plugin to version 1.2.3 or later
  - Folders Plugin to version 6.848.ve3b_fd7839a_81 or later
  - Fortify Plugin to version 22.2.39 or later
  - Gogs Plugin: See vendor advisory
  - Maven Artifact ChoiceListProvider (Nexus) Plugin: See vendor advisory
  - NodeJS Plugin to version 1.6.0.1 or later
  - Shortcut Job Plugin to version 0.5 or later
  - Tuleap Authentication Plugin to version 1.1.21 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40341");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/21");

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
    {'max_version' : '1.27.5', 'fixed_version' : '1.27.5.1', 'plugin' : 'Blue Ocean Plugin'},
    {'max_version' : '952', 'fixed_version' : '953', 'fixed_display' : '953.v0432a_802e4d2', 'plugin' : 'Config File Provider Plugin'},
    {'max_version' : '3.0.2', 'fixed_version' : '3.0.3', 'plugin' : 'Delphix Plugin'},
    {'max_version' : '1.11', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Docker Swarm Plugin'},
    {'max_version' : '5', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Favorite View Plugin'},
    {'max_version' : '1.2.2', 'fixed_version' : '1.2.3', 'plugin' : 'Flaky Test Handler Plugin'},
    {'max_version' : '6.846', 'fixed_version' : '6.848', 'fixed_display' : '6.848.ve3b_fd7839a_81', 'plugin' : 'Folders Plugin'},
    {'max_version' : '22.1.38', 'fixed_version' : '22.2.39', 'plugin' : 'Fortify Plugin'},
    {'max_version' : '1.0.15', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Gogs Plugin'},
    {'max_version' : '1.14', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Maven Artifact ChoiceListProvider (Nexus) Plugin'},
    {'max_version' : '1.6.0', 'fixed_version' : '1.6.0.1', 'plugin' : 'NodeJS Plugin'},
    {'max_version' : '0.4', 'fixed_version' : '0.5', 'plugin' : 'Shortcut Job Plugin'},
    {'max_version' : '1.1.20', 'fixed_version' : '1.1.21', 'plugin' : 'Tuleap Authentication Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
