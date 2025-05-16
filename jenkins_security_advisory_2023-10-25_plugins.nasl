#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183879);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2023-46650",
    "CVE-2023-46651",
    "CVE-2023-46652",
    "CVE-2023-46653",
    "CVE-2023-46654",
    "CVE-2023-46655",
    "CVE-2023-46656",
    "CVE-2023-46657",
    "CVE-2023-46658",
    "CVE-2023-46659",
    "CVE-2023-46660"
  );
  script_xref(name:"JENKINS", value:"2023-10-25");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2023-10-25)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - High GitHub Plugin 1.37.3 and earlier does not escape the GitHub project URL on the build page when
    showing changes. This results in a stored cross-site scripting (XSS) vulnerability exploitable by
    attackers with Item/Configure permission. GitHub Plugin 1.37.3.1 escapes GitHub project URL on the build
    page when showing changes. (CVE-2023-46650)

  - Medium Warnings Plugin 10.5.0 and earlier does not set the appropriate context for credentials lookup,
    allowing the use of system-scoped credentials otherwise reserved for the global configuration. This allows
    attackers with Item/Configure permission to access and capture credentials they are not entitled to.
    Warnings Plugin 10.5.1 defines the appropriate context for credentials lookup. (CVE-2023-46651)

  - Medium lambdatest-automation Plugin 1.20.9 and earlier does not perform a permission check in an HTTP
    endpoint. This allows attackers with Overall/Read permission to enumerate credentials IDs of LAMBDATEST
    credentials stored in Jenkins. Those can be used as part of an attack to capture the credentials using
    another vulnerability. An enumeration of credentials IDs in lambdatest-automation Plugin 1.20.10 requires
    Overall/Administer permission. (CVE-2023-46652)

  - Low lambdatest-automation Plugin 1.20.10 and earlier logs LAMBDATEST Credentials access token at the INFO
    level. This can result in accidental exposure of the token through the default system log. lambdatest-
    automation Plugin 1.21.0 no longer logs LAMBDATEST Credentials access token. (CVE-2023-46653)

  - High In CloudBees CD Plugin, artifacts that were previously copied from an agent to the controller are
    deleted after publishing by the 'CloudBees CD - Publish Artifact' post-build step. CloudBees CD Plugin
    1.1.32 and earlier follows symbolic links to locations outside of the expected directory during this
    cleanup process. This allows attackers able to configure jobs to delete arbitrary files on the Jenkins
    controller file system. CloudBees CD Plugin 1.1.33 deletes symbolic links without following them.
    (CVE-2023-46654)

  - Medium CloudBees CD Plugin temporarily copies files from an agent workspace to the controller in
    preparation for publishing them in the 'CloudBees CD - Publish Artifact' post-build step. CloudBees CD
    Plugin 1.1.32 and earlier follows symbolic links to locations outside of the temporary directory on the
    controller when collecting the list of files to publish. This allows attackers able to configure jobs to
    publish arbitrary files from the Jenkins controller file system to the previously configured CloudBees CD
    server. CloudBees CD Plugin 1.1.33 ensures that only files located within the expected directory are
    published. (CVE-2023-46655)

  - Low Multibranch Scan Webhook Trigger Plugin 1.0.9 and earlier does not use a constant-time comparison when
    checking whether the provided and expected webhook token are equal. This could potentially allow attackers
    to use statistical methods to obtain a valid webhook token. As of publication of this advisory, there is
    no fix. Learn why we announce this. (CVE-2023-46656)

  - Low Gogs Plugin 1.0.15 and earlier does not use a constant-time comparison when checking whether the
    provided and expected webhook token are equal. This could potentially allow attackers to use statistical
    methods to obtain a valid webhook token. As of publication of this advisory, there is no fix. Learn why we
    announce this. (CVE-2023-46657)

  - Low MSTeams Webhook Trigger Plugin 0.1.1 and earlier does not use a constant-time comparison when checking
    whether the provided and expected webhook token are equal. This could potentially allow attackers to use
    statistical methods to obtain a valid webhook token. As of publication of this advisory, there is no fix.
    Learn why we announce this. (CVE-2023-46658)

  - High Edgewall Trac Plugin 1.13 and earlier does not escape the Trac website URL on the build page. This
    results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Item/Configure
    permission. As of publication of this advisory, there is no fix. Learn why we announce this.
    (CVE-2023-46659)

  - Low Zanata Plugin 0.6 and earlier does not use a constant-time comparison when checking whether the
    provided and expected webhook token hashes are equal. This could potentially allow attackers to use
    statistical methods to obtain a valid webhook token. As of publication of this advisory, there is no fix.
    Learn why we announce this. (CVE-2023-46660)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2023-10-25");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - CloudBees CD Plugin to version 1.1.33 or later
  - Edgewall Trac Plugin: See vendor advisory
  - GitHub Plugin to version 1.37.3.1 or later
  - Gogs Plugin: See vendor advisory
  - lambdatest-automation Plugin to version 1.20.10 / 1.21.0 or later
  - MSTeams Webhook Trigger Plugin: See vendor advisory
  - Multibranch Scan Webhook Trigger Plugin: See vendor advisory
  - Warnings Plugin to version 10.5.1 or later
  - Zanata Plugin: See vendor advisory

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46654");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/25");

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
    {'max_version' : '1.1.32', 'fixed_version' : '1.1.33', 'plugin' : 'CloudBees CD Plugin'},
    {'max_version' : '1.13', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Edgewall Trac Plugin'},
    {'max_version' : '1.37.3', 'fixed_version' : '1.37.3.1', 'plugin' : 'GitHub Plugin'},
    {'max_version' : '1.0.15', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Gogs Plugin'},
    {'min_version' : '1.20.9', 'fixed_version' : '1.20.10', 'fixed_display' : '1.20.10 / 1.21.0', 'plugin' : 'lambdatest-automation Plugin'},
    {'max_version' : '0.1.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'MSTeams Webhook Trigger Plugin'},
    {'max_version' : '1.0.9', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Multibranch Scan Webhook Trigger Plugin'},
    {'max_version' : '10.5.0', 'fixed_version' : '10.5.1', 'plugin' : 'Warnings Plugin'},
    {'max_version' : '0.6', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Zanata Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
