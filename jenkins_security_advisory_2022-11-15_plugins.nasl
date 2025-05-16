#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179362);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2022-33980",
    "CVE-2022-38666",
    "CVE-2022-45379",
    "CVE-2022-45380",
    "CVE-2022-45381",
    "CVE-2022-45382",
    "CVE-2022-45383",
    "CVE-2022-45384",
    "CVE-2022-45385",
    "CVE-2022-45386",
    "CVE-2022-45387",
    "CVE-2022-45388",
    "CVE-2022-45389",
    "CVE-2022-45390",
    "CVE-2022-45391",
    "CVE-2022-45392",
    "CVE-2022-45393",
    "CVE-2022-45394",
    "CVE-2022-45395",
    "CVE-2022-45396",
    "CVE-2022-45397",
    "CVE-2022-45398",
    "CVE-2022-45399",
    "CVE-2022-45400",
    "CVE-2022-45401"
  );

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2022-11-15)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Jenkins Script Security Plugin 1189.vb_a_b_7c8fd5fde and earlier stores whole-script approvals as the
    SHA-1 hash of the script, making it vulnerable to collision attacks. (CVE-2022-45379)

  - Jenkins JUnit Plugin 1159.v0b_396e1e07dd and earlier converts HTTP(S) URLs in test report output to
    clickable links in an unsafe manner, resulting in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers with Item/Configure permission. (CVE-2022-45380)

  - Apache Commons Configuration performs variable interpolation, allowing properties to be dynamically
    evaluated and expanded. The standard format for interpolation is ${prefix:name}, where prefix is used
    to locate an instance of org.apache.commons.configuration2.interpol.Lookup that performs the
    interpolation. Starting with version 2.4 and continuing through 2.7, the set of default Lookup instances
    included interpolators that could result in arbitrary code execution or contact with remote servers. These
    lookups are: - script - execute expressions using the JVM script execution engine (javax.script) - dns
    - resolve dns records - url - load values from urls, including from remote servers Applications using
    the interpolation defaults in the affected versions may be vulnerable to remote code execution or
    unintentional contact with remote servers if untrusted configuration values are used. Users are
    recommended to upgrade to Apache Commons Configuration 2.8.0, which disables the problematic interpolators
    by default. (CVE-2022-33980)

  - Jenkins Pipeline Utility Steps Plugin 2.13.1 and earlier does not restrict the set of enabled prefix
    interpolators and bundles versions of Apache Commons Configuration library that enable the 'file:' prefix
    interpolator by default, allowing attackers able to configure Pipelines to read arbitrary files from the
    Jenkins controller file system. (CVE-2022-45381)

  - Jenkins Naginator Plugin 1.18.1 and earlier does not escape display names of source builds in builds that
    were triggered via Retry action, resulting in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers able to edit build display names. (CVE-2022-45382)

  - An incorrect permission check in Jenkins Support Core Plugin 1206.v14049fa_b_d860 and earlier allows
    attackers with Support/DownloadBundle permission to download a previously created support bundle
    containing information limited to users with Overall/Administer permission. (CVE-2022-45383)

  - Jenkins Reverse Proxy Auth Plugin 1.7.3 and earlier stores the LDAP manager password unencrypted in the
    global config.xml file on the Jenkins controller where it can be viewed by attackers with access to the
    Jenkins controller file system. (CVE-2022-45384)

  - A missing permission check in Jenkins CloudBees Docker Hub/Registry Notification Plugin 2.6.2 and earlier
    allows unauthenticated attackers to trigger builds of jobs corresponding to the attacker-specified
    repository. (CVE-2022-45385)

  - Jenkins NS-ND Integration Performance Publisher Plugin 4.8.0.143 and earlier stores passwords unencrypted
    in job config.xml files on the Jenkins controller where they can be viewed by attackers with Extended Read
    permission, or access to the Jenkins controller file system. (CVE-2022-45392)

  - Jenkins NS-ND Integration Performance Publisher Plugin 4.8.0.143 and earlier globally and unconditionally
    disables SSL/TLS certificate and hostname validation for the entire Jenkins controller JVM.
    (CVE-2022-45391)

  - Jenkins NS-ND Integration Performance Publisher Plugin 4.8.0.146 and earlier unconditionally disables
    SSL/TLS certificate and hostname validation for several features. (CVE-2022-38666)

  - Jenkins Violations Plugin 0.7.11 and earlier does not configure its XML parser to prevent XML external
    entity (XXE) attacks. (CVE-2022-45386)

  - Jenkins BART Plugin 1.0.3 and earlier does not escape the parsed content of build logs before rendering it
    on the Jenkins UI, resulting in a stored cross-site scripting (XSS) vulnerability. (CVE-2022-45387)

  - Jenkins Config Rotator Plugin 2.0.1 and earlier does not restrict a file name query parameter in an HTTP
    endpoint, allowing unauthenticated attackers to read arbitrary files with '.xml' extension on the Jenkins
    controller file system. (CVE-2022-45388)

  - A missing permission check in Jenkins XP-Dev Plugin 1.0 and earlier allows unauthenticated attackers to
    trigger builds of jobs corresponding to an attacker-specified repository. (CVE-2022-45389)

  - A missing permission check in Jenkins loader.io Plugin 1.0.1 and earlier allows attackers with
    Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins. (CVE-2022-45390)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Delete log Plugin 1.0 and earlier allows
    attackers to delete build logs. (CVE-2022-45393)

  - A missing permission check in Jenkins Delete log Plugin 1.0 and earlier allows attackers with Item/Read
    permission to delete build logs. (CVE-2022-45394)

  - Jenkins CCCC Plugin 0.6 and earlier does not configure its XML parser to prevent XML external entity (XXE)
    attacks. (CVE-2022-45395)

  - Jenkins SourceMonitor Plugin 0.2 and earlier does not configure its XML parser to prevent XML external
    entity (XXE) attacks. (CVE-2022-45396)

  - Jenkins OSF Builder Suite : : XML Linter Plugin 1.0.2 and earlier does not configure its XML parser to
    prevent XML external entity (XXE) attacks. (CVE-2022-45397)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Cluster Statistics Plugin 0.4.6 and earlier
    allows attackers to delete recorded Jenkins Cluster Statistics. (CVE-2022-45398)

  - A missing permission check in Jenkins Cluster Statistics Plugin 0.4.6 and earlier allows attackers to
    delete recorded Jenkins Cluster Statistics. (CVE-2022-45399)

  - Jenkins JAPEX Plugin 1.7 and earlier does not configure its XML parser to prevent XML external entity
    (XXE) attacks. (CVE-2022-45400)

  - Jenkins Associated Files Plugin 0.2.1 and earlier does not escape names of associated files, resulting in
    a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission.
    (CVE-2022-45401)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-11-15");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Associated Files Plugin: See vendor advisory
  - BART Plugin: See vendor advisory
  - CCCC Plugin: See vendor advisory
  - CloudBees Docker Hub/Registry Notification Plugin to version 2.6.2.1 or later
  - Cluster Statistics Plugin: See vendor advisory
  - Config Rotator Plugin: See vendor advisory
  - Delete log Plugin: See vendor advisory
  - JAPEX Plugin: See vendor advisory
  - JUnit Plugin to version 1160.vf1f01a_a_ea_b_7f or later
  - loader.io Plugin: See vendor advisory
  - Naginator Plugin to version 1.18.2 or later
  - NS-ND Integration Performance Publisher Plugin: See vendor advisory
  - OSF Builder Suite : : XML Linter Plugin: See vendor advisory
  - Pipeline Utility Steps Plugin to version 2.13.2 or later
  - Reverse Proxy Auth Plugin to version 1.7.4 or later
  - Script Security Plugin to version 1190.v65867a_a_47126 or later
  - SourceMonitor Plugin: See vendor advisory
  - Support Core Plugin to version 1206.1208.v9b_7a_1d48db_0f or later
  - Violations Plugin: See vendor advisory
  - XP-Dev Plugin: See vendor advisory

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33980");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-45400");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
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
    {'max_version' : '0.2.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Associated Files Plugin'},
    {'max_version' : '1.0.3', 'fixed_display' : 'See vendor advisory', 'plugin' : 'BART Plugin'},
    {'max_version' : '0.6', 'fixed_display' : 'See vendor advisory', 'plugin' : 'CCCC Plugin'},
    {'max_version' : '2.6.2', 'fixed_version' : '2.6.2.1', 'plugin' : 'CloudBees Docker Hub/Registry Notification Plugin'},
    {'max_version' : '0.4.6', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Cluster Statistics Plugin'},
    {'max_version' : '2.0.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Config Rotator Plugin'},
    {'max_version' : '1.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Delete log Plugin'},
    {'max_version' : '1.7', 'fixed_display' : 'See vendor advisory', 'plugin' : 'JAPEX Plugin'},
    {'max_version' : '1159', 'fixed_version' : '1160', 'fixed_display' : '1160.vf1f01a_a_ea_b_7f', 'plugin' : 'JUnit Plugin'},
    {'max_version' : '1.0.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'loader.io Plugin'},
    {'max_version' : '1.18.1', 'fixed_version' : '1.18.2', 'plugin' : 'Naginator Plugin'},
    {'max_version' : '4.8.0.146', 'fixed_display' : 'See vendor advisory', 'plugin' : 'NS-ND Integration Performance Publisher Plugin'},
    {'max_version' : '1.0.2', 'fixed_display' : 'See vendor advisory', 'plugin' : 'OSF Builder Suite : : XML Linter Plugin'},
    {'max_version' : '2.13.1', 'fixed_version' : '2.13.2', 'plugin' : 'Pipeline Utility Steps Plugin'},
    {'max_version' : '1.7.3', 'fixed_version' : '1.7.4', 'plugin' : 'Reverse Proxy Auth Plugin'},
    {'max_version' : '1189', 'fixed_version' : '1190', 'fixed_display' : '1190.v65867a_a_47126', 'plugin' : 'Script Security Plugin'},
    {'max_version' : '0.2', 'fixed_display' : 'See vendor advisory', 'plugin' : 'SourceMonitor Plugin'},
    {'max_version' : '1206', 'fixed_version' : '1206.1208', 'fixed_display' : '1206.1208.v9b_7a_1d48db_0f', 'plugin' : 'Support Core Plugin'},
    {'max_version' : '0.7.11', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Violations Plugin'},
    {'max_version' : '1.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'XP-Dev Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
