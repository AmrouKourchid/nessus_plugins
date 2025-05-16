#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179064);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2022-46682",
    "CVE-2022-46683",
    "CVE-2022-46684",
    "CVE-2022-46685",
    "CVE-2022-46686",
    "CVE-2022-46687",
    "CVE-2022-46688"
  );

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2022-12-07)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Jenkins Plot Plugin 2.1.11 and earlier does not configure its XML parser to prevent XML external entity
    (XXE) attacks. (CVE-2022-46682)

  - Jenkins Google Login Plugin 1.4 through 1.6 (both inclusive) improperly determines that a redirect URL
    after login is legitimately pointing to Jenkins. (CVE-2022-46683)

  - Jenkins Checkmarx Plugin 2022.3.3 and earlier does not escape values returned from the Checkmarx service
    API before inserting them into HTML reports, resulting in a stored cross-site scripting (XSS)
    vulnerability. (CVE-2022-46684)

  - In Jenkins Gitea Plugin 1.4.4 and earlier, the implementation of Gitea personal access tokens did not
    support credentials masking, potentially exposing them through the build log. (CVE-2022-46685)

  - Jenkins Custom Build Properties Plugin 2.79.vc095ccc85094 and earlier does not escape property values and
    build display names on the Custom Build Properties and Build Summary pages, resulting in a stored
    cross-site scripting (XSS) vulnerability exploitable by attackers able to set or change these values.
    (CVE-2022-46686)

  - Jenkins Spring Config Plugin 2.0.0 and earlier does not escape build display names shown on the Spring
    Config view, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able
    to change build display names. (CVE-2022-46687)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Sonar Gerrit Plugin 377.v8f3808963dc5 and
    earlier allows attackers to have Jenkins connect to Gerrit servers (previously configured by Jenkins
    administrators) using attacker-specified credentials IDs obtained through another method, potentially
    capturing credentials stored in Jenkins. (CVE-2022-46688)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.jenkins.io/security/advisory/2022-12-07/");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Checkmarx Plugin to version 2022.4.3
  - Custom Build Properties Plugin to version 2.82.v16d5b_d3590c7
  - Gitea Plugin to version 1.4.5
  - Google Login Plugin to version 1.7
  - Plot Plugin to version 2.1.12
  - Sonar Gerrit Plugin: See vendor advisory
  - Spring Config Plugin to version 2.0.1

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/31");

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
    {'max_version' : '2022.3.3', 'fixed_version' : '2022.4.3', 'plugin' : 'Checkmarx Plugin'},
    {'max_version' : '2.79', 'fixed_version' : '2.82', 'fixed_display' : '2.82.v16d5b_d3590c7', 'plugin' : 'Custom Build Properties Plugin'},
    {'max_version' : '1.4.4', 'fixed_version' : '1.4.5', 'plugin' : 'Gitea Plugin'},
    {'max_version' : '1.6', 'fixed_version' : '1.7', 'plugin' : 'Google Login Plugin'},
    {'max_version' : '2.1.11', 'fixed_version' : '2.1.12', 'plugin' : 'Plot Plugin'},
    {'max_version' : '377', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Sonar Gerrit Plugin'},
    {'max_version' : '2.0.0', 'fixed_version' : '2.0.1', 'plugin' : 'Spring Config Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
