#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205309);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/12");

  script_cve_id("CVE-2023-22025");

  script_name(english:"Atlassian Confluence < 7.19.25 / 7.20.x < 8.5.12 / 8.6.x < 8.9.4 (CONFSERVER-96135)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-96135 advisory.

  - This High severity Third-Party Dependency vulnerability was introduced in versions 7.0.1 of Confluence 
    Data Center and Server, allows an unauthenticated attacker to expose assets in your environment 
    susceptible to exploitation which has high impact to confidentiality, high impact to integrity, no 
    impact to availability, and requires no user interaction. (CVE-2023-22025)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-96135");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.25, 8.5.12, 8.9.4 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22025");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
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
  { 'max_version' : '7.17.5', 'fixed_display' : '7.19.25 / 8.5.12 / 8.9.4' },
  { 'min_version' : '7.18.0', 'max_version' : '7.18.3', 'fixed_display' : '7.19.25 / 8.5.12 / 8.9.4' },
  { 'min_version' : '7.19.0', 'fixed_version' : '7.19.25', 'fixed_display' : '7.19.25 / 8.5.12 / 8.9.4' },
  { 'min_version' : '7.20.0', 'max_version' : '7.20.3', 'fixed_display' : '8.5.12 / 8.9.4' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.4', 'fixed_display' : '8.5.12 / 8.9.4' },
  { 'min_version' : '8.1.0', 'max_version' : '8.1.4', 'fixed_display' : '8.5.12 / 8.9.4' },
  { 'min_version' : '8.2.0', 'max_version' : '8.2.3', 'fixed_display' : '8.5.12 / 8.9.4' },
  { 'min_version' : '8.3.0', 'max_version' : '8.3.4', 'fixed_display' : '8.5.12 / 8.9.4' },
  { 'min_version' : '8.4.0', 'max_version' : '8.4.5', 'fixed_display' : '8.5.12 / 8.9.4' },
  { 'min_version' : '8.5.0', 'fixed_version' : '8.5.12', 'fixed_display' : '8.5.12 / 8.9.4' },
  { 'min_version' : '8.6.0', 'max_version' : '8.6.2', 'fixed_display' : '8.9.4 (Data Center Only)' },
  { 'min_version' : '8.7.0', 'max_version' : '8.7.2', 'fixed_display' : '8.9.4 (Data Center Only)' },
  { 'min_version' : '8.8.0', 'max_version' : '8.8.1', 'fixed_display' : '8.9.4 (Data Center Only)' },
  { 'min_version' : '8.9.0', 'fixed_version' : '8.9.4', 'fixed_display' : '8.9.4 (Data Center Only)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_NOTE
);
