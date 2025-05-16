#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233779);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2025-31720", "CVE-2025-31721");
  script_xref(name:"JENKINS", value:"2025-04-02");
  script_xref(name:"IAVA", value:"2025-A-0220");

  script_name(english:"Jenkins LTS < 2.492.3 / Jenkins weekly < 2.504 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of Jenkins running on the remote web server is Jenkins
LTS prior to 2.492.3 or Jenkins weekly prior to 2.504. It is, therefore, affected by multiple vulnerabilities:

  - A missing permission check in Jenkins 2.503 and earlier, LTS 2.492.2 and earlier allows attackers with
    Computer/Create permission but without Computer/Configure permission to copy an agent, gaining access to
    encrypted secrets in its configuration. (CVE-2025-31721)

  - A missing permission check in Jenkins 2.503 and earlier, LTS 2.492.2 and earlier allows attackers with
    Computer/Create permission but without Computer/Extended Read permission to copy an agent, gaining access
    to its configuration. (CVE-2025-31720)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2025-04-02");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.504 or later, or Jenkins LTS to version 2.492.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-31721");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/02");

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

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var constraints = [
  { 'max_version' : '2.503', 'fixed_version' : '2.504', 'edition' : 'Open Source' },
  { 'max_version' : '2.492.2', 'fixed_version' : '2.492.3', 'edition' : 'Open Source LTS' }
];

var app_info = vcf::combined_get_app_info(app:'Jenkins');

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
