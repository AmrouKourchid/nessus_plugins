#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189463);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/19");

  script_cve_id("CVE-2024-23897", "CVE-2024-23898");
  script_xref(name:"JENKINS", value:"2024-01-24");
  script_xref(name:"IAVA", value:"2024-A-0057-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/09");

  script_name(english:"Jenkins LTS < 2.426.3 / Jenkins weekly < 2.442 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of Jenkins running on the remote web server is Jenkins
LTS prior to 2.426.3 or Jenkins weekly prior to 2.442. It is, therefore, affected by multiple vulnerabilities:

  - Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser
    that replaces an '@' character followed by a file path in an argument with the file's contents, allowing
    unauthenticated attackers to read arbitrary files on the Jenkins controller file system. (CVE-2024-23897)

  - Jenkins 2.217 through 2.441 (both inclusive), LTS 2.222.1 through 2.426.2 (both inclusive) does not
    perform origin validation of requests made through the CLI WebSocket endpoint, resulting in a cross-site
    WebSocket hijacking (CSWSH) vulnerability, allowing attackers to execute CLI commands on the Jenkins
    controller. (CVE-2024-23898)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2024-01-24");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.442 or later, or Jenkins LTS to version 2.426.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23898");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-23897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var constraints = [
  { 'max_version' : '2.441', 'fixed_version' : '2.442', 'edition' : 'Open Source' },
  { 'max_version' : '2.426.2', 'fixed_version' : '2.426.3', 'edition' : 'Open Source LTS' }
];

var app_info = vcf::combined_get_app_info(app:'Jenkins');

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
