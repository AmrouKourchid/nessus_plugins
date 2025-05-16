#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189462);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2023-6147",
    "CVE-2023-6148",
    "CVE-2024-23899",
    "CVE-2024-23900",
    "CVE-2024-23901",
    "CVE-2024-23902",
    "CVE-2024-23903",
    "CVE-2024-23904",
    "CVE-2024-23905"
  );
  script_xref(name:"JENKINS", value:"2024-01-24");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2024-01-24)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Jenkins Git server Plugin 99.va_0826a_b_cdfa_d and earlier does not disable a feature of its command
    parser that replaces an '@' character followed by a file path in an argument with the file's contents,
    allowing attackers with Overall/Read permission to read content from arbitrary files on the Jenkins
    controller file system. (CVE-2024-23899)

  - Jenkins Matrix Project Plugin 822.v01b_8c85d16d2 and earlier does not sanitize user-defined axis names of
    multi-configuration projects, allowing attackers with Item/Configure permission to create or replace any
    config.xml files on the Jenkins controller file system with content not controllable by the attackers.
    (CVE-2024-23900)

  - Jenkins GitLab Branch Source Plugin 684.vea_fa_7c1e2fe3 and earlier unconditionally discovers projects
    that are shared with the configured owner group, allowing attackers to configure and share a project,
    resulting in a crafted Pipeline being built by Jenkins during the next scan of the group. (CVE-2024-23901)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins GitLab Branch Source Plugin
    684.vea_fa_7c1e2fe3 and earlier allows attackers to connect to an attacker-specified URL. (CVE-2024-23902)

  - Jenkins GitLab Branch Source Plugin 684.vea_fa_7c1e2fe3 and earlier uses a non-constant time comparison
    function when checking whether the provided and expected webhook token are equal, potentially allowing
    attackers to use statistical methods to obtain a valid webhook token. (CVE-2024-23903)

  - Qualys Jenkins Plugin for Policy Compliance prior to version and including 1.0.5 was identified to be
    affected by a security flaw, which was missing a permission check while performing a connectivity check to
    Qualys Cloud Services. This allowed any user with login access and access to configure or edit jobs to
    utilize the plugin to configure a potential rouge endpoint via which it was possible to control response
    for certain request which could be injected with XSS payloads leading to XSS while processing the response
    data (CVE-2023-6148)

  - Qualys Jenkins Plugin for Policy Compliance prior to version and including 1.0.5 was identified to be
    affected by a security flaw, which was missing a permission check while performing a connectivity check to
    Qualys Cloud Services. This allowed any user with login access to configure or edit jobs to utilize the
    plugin and configure potential a rouge endpoint via which it was possible to control response for certain
    request which could be injected with XXE payloads leading to XXE while processing the response data
    (CVE-2023-6147)

  - Jenkins Red Hat Dependency Analytics Plugin 0.7.1 and earlier programmatically disables Content-Security-
    Policy protection for user-generated content in workspaces, archived artifacts, etc. that Jenkins offers
    for download. (CVE-2024-23905)

  - Jenkins Log Command Plugin 1.0.2 and earlier does not disable a feature of its command parser that
    replaces an '@' character followed by a file path in an argument with the file's contents, allowing
    unauthenticated attackers to read content from arbitrary files on the Jenkins controller file system.
    (CVE-2024-23904)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2024-01-24");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Git server Plugin to version 99.101.v720e86326c09 or later
  - GitLab Branch Source Plugin to version 688.v5fa_356ee8520 or later
  - Log Command Plugin: See vendor advisory
  - Matrix Project Plugin to version 822.824.v14451b_c0fd42 or later
  - Qualys Policy Compliance Scanning Connector Plugin to version 1.0.6 or later
  - Red Hat Dependency Analytics Plugin to version 0.9.0 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23904");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
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
    {'max_version' : '99', 'fixed_version' : '99.101', 'fixed_display' : '99.101.v720e86326c09', 'plugin' : 'Git server Plugin'},
    {'max_version' : '684', 'fixed_version' : '688', 'fixed_display' : '688.v5fa_356ee8520', 'plugin' : 'GitLab Branch Source Plugin'},
    {'max_version' : '1.0.2', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Log Command Plugin'},
    {'max_version' : '822', 'fixed_version' : '822.824', 'fixed_display' : '822.824.v14451b_c0fd42', 'plugin' : 'Matrix Project Plugin'},
    {'max_version' : '1.0.5', 'fixed_version' : '1.0.6', 'plugin' : 'Qualys Policy Compliance Scanning Connector Plugin'},
    {'max_version' : '0.7.1', 'fixed_version' : '0.9.0', 'plugin' : 'Red Hat Dependency Analytics Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
