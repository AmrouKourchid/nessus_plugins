#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201037);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/20");

  script_cve_id("CVE-2024-21685");
  script_xref(name:"IAVA", value:"2024-A-0366");

  script_name(english:"Atlassian Jira < 9.4.21 / 9.12.x < 9.12.8 / 9.15.x < 9.16.0 (JRASERVER-77713)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira Server running on the remote host is affected by a vulnerability as referenced in the
JRASERVER-77713 advisory.

  - This High severity Information Disclosure vulnerability was introduced in versions 9.4.0, 9.12.0, and
    9.15.0 of Jira Core Data Center. This Information Disclosure vulnerability, with a CVSS Score of 7.4,
    allows an unauthenticated attacker to view sensitive information via an Information Disclosure
    vulnerability which has high impact to confidentiality, no impact to integrity, no impact to availability,
    and requires user interaction. Atlassian recommends that Jira Core Data Center customers upgrade to latest
    version, if you are unable to do so, upgrade your instance to one of the specified supported fixed
    versions: Jira Core Data Center 9.4: Upgrade to a release greater than or equal to 9.4.21 Jira Core Data
    Center 9.12: Upgrade to a release greater than or equal to 9.12.8 Jira Core Data Center 9.16: Upgrade to a
    release greater than or equal to 9.16.0 See the release notes. You can download the latest version of Jira
    Core Data Center from the download center. This vulnerability was found internally. (CVE-2024-21685)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://confluence.atlassian.com/security/security-bulletin-june-18-2024-1409286211.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30218332");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-77713");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 9.4.21, 9.12.8, 9.16.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21685");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

var constraints = [
  { 'fixed_version' : '9.4.21', 'fixed_display' : '9.4.21 / 9.12.8 / 9.16.0' },
  { 'min_version' : '9.10.0', 'fixed_version' : '9.12.8', 'fixed_display' : '9.12.8 / 9.16.0' },
  { 'min_version' : '9.13.0', 'fixed_version' : '9.16.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
