#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181840);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2023-43499",
    "CVE-2023-43500",
    "CVE-2023-43501",
    "CVE-2023-43502"
  );
  script_xref(name:"JENKINS", value:"2023-09-20");

  script_name(english:"Jenkins Plugins Multiple Vulnerabilities (2023-09-20)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Jenkins plugins running on the remote web server is
affected by multiple vulnerabilities:

  - Jenkins Build Failure Analyzer Plugin 2.4.1 and earlier does not escape Failure Cause names in build logs,
    resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to create or
    update Failure Causes. (CVE-2023-43499)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Build Failure Analyzer Plugin 2.4.1 and
    earlier allows attackers to connect to an attacker-specified hostname and port using attacker-specified
    username and password. (CVE-2023-43500)

  - A missing permission check in Jenkins Build Failure Analyzer Plugin 2.4.1 and earlier allows attackers
    with Overall/Read permission to connect to an attacker-specified hostname and port using attacker-
    specified username and password. (CVE-2023-43501)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Build Failure Analyzer Plugin 2.4.1 and
    earlier allows attackers to delete Failure Causes. (CVE-2023-43502)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2023-09-20");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
- Build Failure Analyzer Plugin to version 2.4.2 or later
See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-43500");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/25");

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
    {'max_version' : '2.4.1', 'fixed_version' : '2.4.2', 'plugin' : 'Build Failure Analyzer Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
