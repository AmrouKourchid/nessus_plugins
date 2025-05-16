#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213705);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/10");

  script_cve_id("CVE-2023-46234");

  script_name(english:"Atlassian Confluence 7.11.x < 7.19.29 / 7.20.x < 8.5.17 / 8.6.x < 8.9.8 / 9.0.x < 9.1.1 (CONFSERVER-98021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-98021 advisory.

  - browserify-sign is a package to duplicate the functionality of node's crypto public key functions, much of
    this is based on Fedor Indutny's work on indutny/tls.js. An upper bound check issue in `dsaVerify`
    function allows an attacker to construct signatures that can be successfully verified by any public key,
    thus leading to a signature forgery attack. All places in this project that involve DSA verification of
    user-input signatures will be affected by this vulnerability. This issue has been patched in version
    4.2.2. (CVE-2023-46234)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-98021");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.29, 8.5.17, 8.9.8, 9.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46234");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl", "confluence_nix_installed.nbin", "confluence_win_installed.nbin");
  script_require_keys("installed_sw/Atlassian Confluence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian Confluence');

var constraints = [
  { 'min_version' : '7.11.0', 'fixed_version' : '7.19.29' },
  { 'min_version' : '7.20.0', 'fixed_version' : '8.5.17' },
  { 'min_version' : '8.6.0', 'fixed_version' : '8.9.8' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
