#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211917);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/28");

  script_cve_id("CVE-2024-47855", "CVE-2024-54003", "CVE-2024-54004");
  script_xref(name:"JENKINS", value:"2024-11-27");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2024-11-27)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - util/JSONTokener.java in JSON-lib before 3.1.0 mishandles an unbalanced comment string. (CVE-2024-47855)

  - Jenkins Simple Queue Plugin 1.4.4 and earlier does not escape the view name, resulting in a stored cross-
    site scripting (XSS) vulnerability exploitable by attackers with View/Create permission. (CVE-2024-54003)

  - Jenkins Filesystem List Parameter Plugin 0.0.14 and earlier does not restrict the path used for the File
    system objects list Parameter, allowing attackers with Item/Configure permission to enumerate file names
    on the Jenkins controller file system. (CVE-2024-54004)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2024-11-27");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Filesystem List Parameter Plugin to version 0.0.15 or later
  - Simple Queue Plugin to version 1.4.5 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-54003");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
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
    {'max_version' : '0.0.14', 'fixed_version' : '0.0.15', 'plugin' : 'Filesystem List Parameter Plugin'},
    {'max_version' : '1.4.4', 'fixed_version' : '1.4.5', 'plugin' : 'Simple Queue Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
