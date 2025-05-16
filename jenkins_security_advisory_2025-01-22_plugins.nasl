#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214537);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/24");

  script_cve_id(
    "CVE-2025-0142",
    "CVE-2025-24397",
    "CVE-2025-24398",
    "CVE-2025-24399",
    "CVE-2025-24400",
    "CVE-2025-24401",
    "CVE-2025-24402",
    "CVE-2025-24403"
  );
  script_xref(name:"JENKINS", value:"2025-01-22");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2025-01-22)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Jenkins OpenId Connect Authentication Plugin 4.452.v2849b_d3945fa_ and earlier, except
    4.438.440.v3f5f201de5dc, treats usernames as case-insensitive, allowing attackers on Jenkins instances
    configured with a case-sensitive OpenID Connect provider to log in as any user by providing a username
    that differs only in letter case, potentially gaining administrator access to Jenkins. (CVE-2025-24399)

  - Jenkins Eiffel Broadcaster Plugin 2.8.0 through 2.10.2 (both inclusive) uses the credential ID as the
    cache key during signing operations, allowing attackers able to create a credential with the same ID as a
    legitimate one in a different credentials store to sign an event published to RabbitMQ with the legitimate
    credentials. (CVE-2025-24400)

  - Jenkins Folder-based Authorization Strategy Plugin 217.vd5b_18537403e and earlier does not verify that
    permissions configured to be granted are enabled, potentially allowing users formerly granted (typically
    optional permissions, like Overall/Manage) to access functionality they're no longer entitled to.
    (CVE-2025-24401)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Azure Service Fabric Plugin 1.6 and earlier
    allows attackers to connect to a Service Fabric URL using attacker-specified credentials IDs obtained
    through another method. (CVE-2025-24402)

  - Cleartext storage of sensitive information in the Zoom Jenkins bot plugin before version 1.6 may allow an
    authenticated user to conduct a disclosure of information via network access. Users can update to the
    latest version at https://plugins.jenkins.io/zoom/releases/. (CVE-2025-0142)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2025-01-22");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Azure Service Fabric Plugin: See vendor advisory
  - Bitbucket Server Integration Plugin to version 4.1.4 or later
  - Eiffel Broadcaster Plugin to version 2.10.3 or later
  - Folder-based Authorization Strategy Plugin: See vendor advisory
  - GitLab Plugin to version 1.9.7 or later
  - OpenId Connect Authentication Plugin to version 4.453.v4d7765c854f4 or later
  - Zoom Plugin to version 1.4 / 1.6 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24398");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-24399");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"former");
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
    {'max_version' : '1.6', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Azure Service Fabric Plugin'},
    {'max_version' : '4.1.3', 'fixed_version' : '4.1.4', 'plugin' : 'Bitbucket Server Integration Plugin'},
    {'max_version' : '2.10.2', 'fixed_version' : '2.10.3', 'plugin' : 'Eiffel Broadcaster Plugin'},
    {'max_version' : '217', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Folder-based Authorization Strategy Plugin'},
    {'max_version' : '1.9.6', 'fixed_version' : '1.9.7', 'plugin' : 'GitLab Plugin'},
    {'max_version' : '4.452', 'fixed_version' : '4.453', 'fixed_display' : '4.453.v4d7765c854f4', 'plugin' : 'OpenId Connect Authentication Plugin'},
    {'max_version' : '1.5', 'fixed_display' : '1.6', 'plugin' : 'Zoom Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE}
);
