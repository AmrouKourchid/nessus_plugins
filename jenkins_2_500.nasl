#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227562);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id(
    "CVE-2025-27622",
    "CVE-2025-27623",
    "CVE-2025-27624",
    "CVE-2025-27625"
  );
  script_xref(name:"JENKINS", value:"2025-03-05");

  script_name(english:"Jenkins LTS < 2.492.2 / Jenkins weekly < 2.500 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of Jenkins running on the remote web server is Jenkins
LTS prior to 2.492.2 or Jenkins weekly prior to 2.500. It is, therefore, affected by multiple vulnerabilities:

  - Medium Jenkins 2.499 and earlier, LTS 2.492.1 and earlier does not require POST requests for the HTTP
    endpoint toggling collapsed/expanded status of sidepanel widgets (e.g., Build Queue and Build Executor
    Status widgets), resulting in a cross-site request forgery (CSRF) vulnerability. This vulnerability allows
    attackers to have users toggle their collapsed/expanded status of sidepanel widgets. Additionally, as the
    API accepts any string as the identifier of the panel ID to be toggled, attacker-controlled content can be
    stored in the victim's user profile in Jenkins. Jenkins 2.500, LTS 2.492.2 requires POST requests for the
    affected HTTP endpoint. (CVE-2025-27624)

  - Medium Jenkins 2.499 and earlier, LTS 2.492.1 and earlier does not redact encrypted values of secrets when
    accessing config.xml of agents via REST API or CLI. This allows attackers with Agent/Extended Read
    permission to view encrypted values of secrets. This issue is related to SECURITY-266 in the 2016-05-11
    security advisory. Jenkins 2.500, LTS 2.492.2 redacts the encrypted values of secrets stored in agent
    config.xml accessed via REST API or CLI for users lacking Agent/Configure permission. (CVE-2025-27622)

  - Medium Jenkins 2.499 and earlier, LTS 2.492.1 and earlier does not redact encrypted values of secrets when
    accessing config.xml of views via REST API or CLI. This allows attackers with View/Read permission to view
    encrypted values of secrets. This issue is related to SECURITY-266 in the 2016-05-11 security advisory.
    Jenkins 2.500, LTS 2.492.2 redacts the encrypted values of secrets stored in view config.xml accessed via
    REST API or CLI for users lacking View/Configure permission. (CVE-2025-27623)

  - Medium Various features in Jenkins redirect users to partially user-controlled URLs inside Jenkins. To
    prevent open redirect vulnerabilities, Jenkins limits redirections to safe URLs (neither absolute nor
    scheme-relative/network-path reference). In Jenkins 2.499 and earlier, LTS 2.492.1 and earlier, redirects
    starting with backslash (\) characters are considered safe. This allows attackers to perform phishing
    attacks by having users go to a Jenkins URL that will forward them to a different site, because browsers
    interpret these characters as part of scheme-relative redirects. Jenkins 2.500, LTS 2.492.2 considers
    redirects to URLs starting with backslash (\) characters to be unsafe, rejecting such redirects.
    (CVE-2025-27625)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2025-03-05");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.500 or later, or Jenkins LTS to version 2.492.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

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

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var constraints = [
  { 'max_version' : '2.499', 'fixed_version' : '2.500', 'edition' : 'Open Source' },
  { 'max_version' : '2.492.1', 'fixed_version' : '2.492.2', 'edition' : 'Open Source LTS' }
];

var app_info = vcf::combined_get_app_info(app:'Jenkins');

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xsrf':TRUE}
);
