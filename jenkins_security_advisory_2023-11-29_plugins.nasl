#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186420);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2023-49652",
    "CVE-2023-49653",
    "CVE-2023-49654",
    "CVE-2023-49655",
    "CVE-2023-49656",
    "CVE-2023-49673",
    "CVE-2023-49674"
  );
  script_xref(name:"JENKINS", value:"2023-11-29");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2023-11-29)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Medium Jira Plugin 3.11 and earlier does not set the appropriate context for credentials lookup, allowing
    the use of system-scoped credentials otherwise reserved for the global configuration. This allows
    attackers with Item/Configure permission to access and capture credentials they are not entitled to. Jira
    Plugin 3.12 defines the appropriate context for credentials lookup. (CVE-2023-49653)

  - Medium Google Compute Engine Plugin 4.550.vb_327fca_3db_11 and earlier does not correctly perform
    permission checks in multiple HTTP endpoints. This allows attackers with global Item/Configure permission
    (while lacking Item/Configure permission on any particular job) to do the following: Enumerate system-
    scoped credentials IDs of credentials stored in Jenkins. Those can be used as part of an attack to capture
    the credentials using another vulnerability. Connect to Google Cloud Platform using attacker-specified
    credentials IDs obtained through another method, to obtain information about existing projects. Google
    Compute Engine Plugin 4.551.v5a_4dc98f6962 requires Overall/Administer permission for the affected HTTP
    endpoints. (CVE-2023-49652)

  - High MATLAB Plugin determines whether a user-specified directory on the Jenkins controller is the location
    of a MATLAB installation by parsing an XML file in that directory. MATLAB Plugin 2.11.0 and earlier does
    not perform permission checks in several HTTP endpoints implementing related form validation.
    Additionally, these HTTP endpoints do not require POST requests, resulting in a cross-site request forgery
    (CSRF) vulnerability. Additionally, the plugin does not configure its XML parser to prevent XML external
    entity (XXE) attacks. This allows attackers able to create files on the Jenkins controller file system to
    have Jenkins parse a crafted XML document that uses external entities for extraction of secrets from the
    Jenkins controller or server-side request forgery. MATLAB Plugin 2.11.1 configures its XML parser to
    prevent XML external entity (XXE) attacks. Additionally, POST requests and Item/Configure permission are
    required for the affected HTTP endpoints. (CVE-2023-49654, CVE-2023-49655, CVE-2023-49656)

  - Medium NeuVector Vulnerability Scanner Plugin 1.22 and earlier does not perform a permission check in a
    connection test HTTP endpoint. This allows attackers with Overall/Read permission to connect to an
    attacker-specified hostname and port using attacker-specified username and password. Additionally, this
    HTTP endpoint does not require POST requests, resulting in a cross-site request forgery (CSRF)
    vulnerability. NeuVector Vulnerability Scanner Plugin 2.2 requires POST requests and Overall/Administer
    permission for the affected HTTP endpoint. (CVE-2023-49673, CVE-2023-49674)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2023-11-29");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Google Compute Engine Plugin to version 4.551.v5a_4dc98f6962 or later
  - Jira Plugin to version 3.12 or later
  - MATLAB Plugin to version 2.11.1 or later
  - NeuVector Vulnerability Scanner Plugin to version 2.2 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49673");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-49656");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/29");

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
    {'max_version' : '4.550', 'fixed_version' : '4.551', 'fixed_display' : '4.551.v5a_4dc98f6962', 'plugin' : 'Google Compute Engine Plugin'},
    {'max_version' : '3.11', 'fixed_version' : '3.12', 'plugin' : 'Jira Plugin'},
    {'max_version' : '2.11.0', 'fixed_version' : '2.11.1', 'plugin' : 'MATLAB Plugin'},
    {'max_version' : '1.22', 'fixed_version' : '2.2', 'plugin' : 'NeuVector Vulnerability Scanner Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE}
);
