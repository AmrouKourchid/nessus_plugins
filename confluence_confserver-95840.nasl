#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201089);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/28");

  script_cve_id("CVE-2024-22257");
  script_xref(name:"IAVA", value:"2024-A-0366");

  script_name(english:"Atlassian Confluence 1.0.1 < 7.19.22 / 7.20.x < 8.5.9 / 8.6.x < 8.9.1 (CONFSERVER-95840)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-95840 advisory.

  - In Spring Security, versions 5.7.x prior to 5.7.12, 5.8.x prior to 5.8.11, versions 6.0.x prior to 6.0.9,
    versions 6.1.x prior to 6.1.8, versions 6.2.x prior to 6.2.3, an application is possible vulnerable to
    broken access control when it directly uses the AuthenticatedVoter#vote passing a null Authentication
    parameter. (CVE-2024-22257)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-95840");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.22, 8.5.9, 8.9.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl", "confluence_nix_installed.nbin", "confluence_win_installed.nbin");
  script_require_keys("installed_sw/Atlassian Confluence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian Confluence');

var constraints = [
  { 'min_version' : '1.0.1  ', 'max_version' : '7.16', 'fixed_display' : '7.19.22' },
  { 'min_version' : '7.17', 'max_version' : '7.17.5', 'fixed_display' : '7.19.22' },
  { 'min_version' : '7.18', 'max_version' : '7.18.3', 'fixed_display' : '7.19.22' },
  { 'min_version' : '7.19', 'max_version' : '7.19.21', 'fixed_display' : '7.19.22'},
  { 'min_version' : '7.20', 'max_version' : '7.20.3', 'fixed_display' : '8.5.9' },
  { 'min_version' : '8.0', 'max_version' : '8.0.4', 'fixed_display' : '8.5.9' },
  { 'min_version' : '8.1', 'max_version' : '8.1.4', 'fixed_display' : '8.5.9' },
  { 'min_version' : '8.2', 'max_version' : '8.2.3', 'fixed_display' : '8.5.9' },
  { 'min_version' : '8.3', 'max_version' : '8.3.4', 'fixed_display' : '8.5.9' },
  { 'min_version' : '8.4', 'max_version' : '8.4.5', 'fixed_display' : '8.5.9' }, 
  { 'min_version' : '8.5', 'max_version' : '8.5.8', 'fixed_display' : '8.5.9'},
  { 'min_version' : '8.6', 'max_version' : '8.6.2', 'fixed_display' : '8.9.1 (Data Center Only)' },
  { 'min_version' : '8.7', 'max_version' : '8.7.2', 'fixed_display' : '8.9.1 (Data Center Only)' },
  { 'min_version' : '8.8', 'max_version' : '8.8.1', 'fixed_display' : '8.9.1 (Data Center Only)' },
  { 'min_version' : '8.9', 'fixed_version' : '8.9.1', 'fixed_display' : '8.9.1 (Data Center Only)' }    
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
