#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208097);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/24");

  script_cve_id("CVE-2024-47805", "CVE-2024-47806", "CVE-2024-47807");
  script_xref(name:"JENKINS", value:"2024-10-02");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2024-10-02)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Jenkins Credentials Plugin 1380.va_435002fa_924 and earlier, except 1371.1373.v4eb_fa_b_7161e9, does not
    redact encrypted values of credentials using the `SecretBytes` type when accessing item `config.xml` via
    REST API or CLI. (CVE-2024-47805)

  - Jenkins OpenId Connect Authentication Plugin 4.354.v321ce67a_1de8 and earlier does not check the `aud`
    (Audience) claim of an ID Token, allowing attackers to subvert the authentication flow, potentially
    gaining administrator access to Jenkins. (CVE-2024-47806)

  - Jenkins OpenId Connect Authentication Plugin 4.354.v321ce67a_1de8 and earlier does not check the `iss`
    (Issuer) claim of an ID Token, allowing attackers to subvert the authentication flow, potentially gaining
    administrator access to Jenkins. (CVE-2024-47807)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2024-10-02");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Credentials Plugin to version 1381.v2c3a_12074da_b_ or later
  - OpenId Connect Authentication Plugin to version 4.355.v3a_fb_fca_b_96d4 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var constraints = [
    {'max_version' : '1380', 'fixed_version' : '1381', 'fixed_display' : '1381.v2c3a_12074da_b_', 'plugin' : 'Credentials Plugin'},
    {'max_version' : '4.354', 'fixed_version' : '4.355', 'fixed_display' : '4.355.v3a_fb_fca_b_96d4', 'plugin' : 'OpenId Connect Authentication Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
