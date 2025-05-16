#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201113);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/20");

  script_cve_id("CVE-2024-21685");
  script_xref(name:"IAVA", value:"2024-A-0366");

  script_name(english:"Atlassian Jira Service Management Data Center and Server < 5.4.21 / 5.12.x < 5.12.8 / 5.15.x < 5.16.0 (JSDSERVER-15309)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira Service Management Data Center and Server (Jira Service Desk) host is missing a security
update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira Service Management Data Center and Server (Jira Service Desk) running on the remote host
is affected by a vulnerability as referenced in the JSDSERVER-15309 advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-15309");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira Service Management Data Center and Server version 5.4.21, 5.12.8, 5.16.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21685");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_desk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "jira_service_desk_installed_win.nbin", "jira_service_desk_installed_nix.nbin");
  script_require_keys("installed_sw/JIRA Service Desk Application");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'JIRA Service Desk Application');

var constraints = [
  { 'min_version' : '0.0', 'max_version' : '4.21', 'fixed_display' : '5.4.21' },
  { 'min_version' : '4.22', 'max_version' : '4.22.6', 'fixed_display' : '5.4.21' },
  { 'equal' : '5.0', 'fixed_display' : '5.4.21' },
  { 'min_version' : '5.1', 'max_version' : '5.1.1', 'fixed_display' : '5.4.21' },
  { 'min_version' : '5.2', 'max_version' : '5.2.1', 'fixed_display' : '5.4.21' },
  { 'min_version' : '5.3', 'max_version' : '5.3.1', 'fixed_display' : '5.4.21' },
  { 'min_version' : '5.4', 'max_version' : '5.4.20', 'fixed_display' : '5.4.21' },
  { 'min_version' : '5.5', 'max_version' : '5.5.1', 'fixed_display' : '5.12.8' },
  { 'min_version' : '5.6', 'max_version' : '5.6.2', 'fixed_display' : '5.12.8' },
  { 'min_version' : '5.7', 'max_version' : '5.7.2', 'fixed_display' : '5.12.8' },
  { 'min_version' : '5.8', 'max_version' : '5.8.2', 'fixed_display' : '5.12.8' },
  { 'min_version' : '5.9', 'max_version' : '5.9.2', 'fixed_display' : '5.12.8' },
  { 'min_version' : '5.10', 'max_version' : '5.10.2', 'fixed_display' : '5.12.8' },
  { 'min_version' : '5.11', 'max_version' : '5.11.3', 'fixed_display' : '5.12.8' },
  { 'min_version' : '5.12', 'max_version' : '5.12.7', 'fixed_display' : '5.12.8' },
  { 'min_version' : '5.13', 'max_version' : '5.13.2', 'fixed_display' : '5.16.0 (Data Center Only)' },
  { 'min_version' : '5.14', 'max_version' : '5.14.2', 'fixed_display' : '5.16.0 (Data Center Only)' },
  { 'min_version' : '5.15', 'max_version' : '5.15.3', 'fixed_display' : '5.16.0 (Data Center Only)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
