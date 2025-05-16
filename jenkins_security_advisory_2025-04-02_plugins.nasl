#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233778);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_cve_id(
    "CVE-2025-31722",
    "CVE-2025-31723",
    "CVE-2025-31724",
    "CVE-2025-31725",
    "CVE-2025-31726",
    "CVE-2025-31727",
    "CVE-2025-31728"
  );
  script_xref(name:"JENKINS", value:"2025-04-02");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2025-04-02)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - In Jenkins Templating Engine Plugin 2.5.3 and earlier, libraries defined in folders are not subject to
    sandbox protection, allowing attackers with Item/Configure permission to execute arbitrary code in the
    context of the Jenkins controller JVM. (CVE-2025-31722)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Simple Queue Plugin 1.4.6 and earlier allows
    attackers to change and reset the build queue order. (CVE-2025-31723)

  - Jenkins Cadence vManager Plugin 4.0.0-282.v5096a_c2db_275 and earlier stores Verisium Manager vAPI keys
    unencrypted in job config.xml files on the Jenkins controller where they can be viewed by users with
    Extended Read permission, or access to the Jenkins controller file system. (CVE-2025-31724)

  - Jenkins monitor-remote-job Plugin 1.0 stores passwords unencrypted in job config.xml files on the Jenkins
    controller where they can be viewed by users with Extended Read permission, or access to the Jenkins
    controller file system. (CVE-2025-31725)

  - Jenkins Stack Hammer Plugin 1.0.6 and earlier stores Stack Hammer API keys unencrypted in job config.xml
    files on the Jenkins controller where they can be viewed by users with Extended Read permission, or access
    to the Jenkins controller file system. (CVE-2025-31726)

  - Jenkins AsakusaSatellite Plugin 0.1.1 and earlier stores AsakusaSatellite API keys unencrypted in job
    config.xml files on the Jenkins controller where they can be viewed by users with Item/Extended Read
    permission or access to the Jenkins controller file system. (CVE-2025-31727)

  - Jenkins AsakusaSatellite Plugin 0.1.1 and earlier does not mask AsakusaSatellite API keys displayed on the
    job configuration form, increasing the potential for attackers to observe and capture them.
    (CVE-2025-31728)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2025-04-02");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - AsakusaSatellite Plugin: See vendor advisory
  - Cadence vManager Plugin to version 4.0.1-286.v9e25a_740b_a_48 or later
  - monitor-remote-job Plugin: See vendor advisory
  - Simple Queue Plugin to version 1.4.7 or later
  - Stack Hammer Plugin: See vendor advisory
  - Templating Engine Plugin to version 2.5.4 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-31722");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var constraints = [
    {'max_version' : '0.1.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'AsakusaSatellite Plugin'},
    {'max_version' : '4.0.0', 'fixed_version' : '4.0.1', 'fixed_display' : '4.0.1-286.v9e25a_740b_a_48', 'plugin' : 'Cadence vManager Plugin'},
    {'max_version' : '1.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'monitor-remote-job Plugin'},
    {'max_version' : '1.4.6', 'fixed_version' : '1.4.7', 'plugin' : 'Simple Queue Plugin'},
    {'max_version' : '1.0.6', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Stack Hammer Plugin'},
    {'max_version' : '2.5.3', 'fixed_version' : '2.5.4', 'plugin' : 'Templating Engine Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE}
);
