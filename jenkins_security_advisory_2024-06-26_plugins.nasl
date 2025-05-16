#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201047);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/02");

  script_cve_id("CVE-2024-39458", "CVE-2024-39459", "CVE-2024-39460");
  script_xref(name:"JENKINS", value:"2024-06-26");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2024-06-26)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Low Structs Plugin provides utility functionality used, e.g., in Pipeline to instantiate and configure
    build steps, typically before their execution. When Structs Plugin 337.v1b_04ea_4df7c8 and earlier fails
    to configure a build step, it logs a warning message containing diagnostic information that may contain
    secrets passed as step parameters. This can result in accidental exposure of secrets through the default
    system log. Structs Plugin 338.v848422169819 inspects the types of actual parameters before logging these
    warning messages, and limits detailed diagnostic information to FINE level log messages if secrets are
    involved. These log messages are not displayed in the default Jenkins system log. (CVE-2024-39458)

  - Medium When creating secret file credentials Plain Credentials Plugin 182.v468b_97b_9dcb_8 and earlier
    attempts to decrypt the content of the file to check if it constitutes a valid encrypted secret. In rare
    cases the file content matches the expected format of an encrypted secret, and the file content will be
    stored unencrypted (only Base64 encoded) on the Jenkins controller file system. These credentials can be
    viewed by users with access to the Jenkins controller file system (global credentials) or with
    Item/Extended Read permission (folder-scoped credentials). Secret file credentials stored unencrypted are
    unusable, as they would be decrypted during their use. Any successfully used secret file credentials are
    therefore unaffected. Plain Credentials Plugin 183.va_de8f1dd5a_2b_ no longer attempts to decrypt the
    content of the file when creating secret file credentials. (CVE-2024-39459)

  - Medium Bitbucket Branch Source Plugin 886.v44cf5e4ecec5 and earlier prints the Bitbucket OAuth access
    token as part of the Bitbucket URL in the build log in some cases. Bitbucket Branch Source Plugin
    887.va_d359b_3d2d8d does not include the Bitbucket OAuth access token as part of the Bitbucket URL in the
    build log. (CVE-2024-39460)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2024-06-26");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Bitbucket Branch Source Plugin to version 887.va_d359b_3d2d8d or later
  - Plain Credentials Plugin to version 183.va_de8f1dd5a_2b_ or later
  - Structs Plugin to version 338.v848422169819 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39460");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/26");

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
    {'max_version' : '886', 'fixed_version' : '887', 'fixed_display' : '887.va_d359b_3d2d8d', 'plugin' : 'Bitbucket Branch Source Plugin'},
    {'max_version' : '182', 'fixed_version' : '183', 'fixed_display' : '183.va_de8f1dd5a_2b_', 'plugin' : 'Plain Credentials Plugin'},
    {'max_version' : '337', 'fixed_version' : '338', 'fixed_display' : '338.v848422169819', 'plugin' : 'Structs Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
