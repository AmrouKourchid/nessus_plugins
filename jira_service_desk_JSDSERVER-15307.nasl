#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197935);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2024-22257");
  script_xref(name:"IAVA", value:"2024-A-0305-S");
  script_xref(name:"IAVA", value:"2024-A-0366");

  script_name(english:"Atlassian Jira Service Management Data Center and Server < 5.4.20 / 5.5.x < 5.12.7 / 5.13.x < 5.15.2 Broken Access Control (JSDSERVER-15307)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira Service Management Data Center and Server (Jira Service Desk) host is missing a security
update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira Service Management Data Center and Server (Jira Service Desk) running on the remote host
is affected by a vulnerability as referenced in the JSDSERVER-15307 advisory.

  - In Spring Security, versions 5.7.x prior to 5.7.12, 5.8.x prior to 5.8.11, versions 6.0.x prior to 6.0.9,
    versions 6.1.x prior to 6.1.8, versions 6.2.x prior to 6.2.3, an application is possible vulnerable to
    broken access control when it directly uses the AuthenticatedVoter#vote passing a null Authentication
    parameter. (CVE-2024-22257)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-15307");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira Service Management Data Center and Server version 5.4.20, 5.12.7, 5.15.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_desk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "jira_service_desk_installed_win.nbin", "jira_service_desk_installed_nix.nbin");
  script_require_keys("installed_sw/JIRA Service Desk Application");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'JIRA Service Desk Application');

var constraints = [
  { 'min_version' : '0.0', 'max_version' : '4.21', 'fixed_display' : '5.4.20' },
  { 'min_version' : '4.22', 'max_version' : '4.22.6', 'fixed_display' : '5.4.20' },
  { 'equal' : '5.0', 'fixed_display' : '5.4.20' },
  { 'min_version' : '5.1', 'max_version' : '5.1.1', 'fixed_display' : '5.4.20' },
  { 'min_version' : '5.2', 'max_version' : '5.2.1', 'fixed_display' : '5.4.20' },
  { 'min_version' : '5.3', 'max_version' : '5.3.1', 'fixed_display' : '5.4.20' },
  { 'min_version' : '5.4', 'max_version' : '5.4.19', 'fixed_display' : '5.4.20' },
  { 'min_version' : '5.5', 'max_version' : '5.5.1', 'fixed_display' : '5.12.7' },
  { 'min_version' : '5.6', 'max_version' : '5.6.2', 'fixed_display' : '5.12.7' },
  { 'min_version' : '5.7', 'max_version' : '5.7.2', 'fixed_display' : '5.12.7' },
  { 'min_version' : '5.8', 'max_version' : '5.8.2', 'fixed_display' : '5.12.7' },
  { 'min_version' : '5.9', 'max_version' : '5.9.2', 'fixed_display' : '5.12.7' },
  { 'min_version' : '5.10', 'max_version' : '5.10.2', 'fixed_display' : '5.12.7' },
  { 'min_version' : '5.11', 'max_version' : '5.11.3', 'fixed_display' : '5.12.7' },
  { 'min_version' : '5.12', 'max_version' : '5.12.6', 'fixed_display' : '5.12.7' },
  { 'min_version' : '5.13', 'max_version' : '5.13.1', 'fixed_display' : '5.15.2 (Data Center Only)' },
  { 'min_version' : '5.14', 'max_version' : '5.14.2', 'fixed_display' : '5.15.2 (Data Center Only)' },
  { 'min_version' : '5.15', 'max_version' : '5.15.1', 'fixed_display' : '5.15.2 (Data Center Only)' },
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
