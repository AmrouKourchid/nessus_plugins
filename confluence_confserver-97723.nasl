#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209139);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/16");

  script_cve_id("CVE-2024-29857");

  script_name(english:"Atlassian Confluence < 7.19.26 / 7.20.x < 8.5.12 / 8.6.x < 8.9.4 / 9.0.1 (CONFSERVER-97723)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-97723 advisory.

  - An issue was discovered in ECCurve.java and ECCurve.cs in Bouncy Castle Java (BC Java) before 1.78, BC
    Java LTS before 2.73.6, BC-FJA before 1.0.2.5, and BC C# .Net before 2.3.1. Importing an EC certificate
    with crafted F2m parameters can lead to excessive CPU consumption during the evaluation of the curve
    parameters. (CVE-2024-29857)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-97723");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.26, 8.5.12, 8.9.4, 9.0.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29857");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/16");

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
  { 'fixed_version' : '7.19.25', 'fixed_display' : '7.19.25 / 8.5.12 / 8.9.4 / 9.0.1' },
  { 'min_version' : '7.20.0', 'max_version' : '7.20.3', 'fixed_display' : '8.5.12 / 8.9.4 / 9.0.1' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.4', 'fixed_display' : '8.5.12 / 8.9.4 / 9.0.1' },
  { 'min_version' : '8.1.0', 'max_version' : '8.1.4', 'fixed_display' : '8.5.12 / 8.9.4 / 9.0.1' },
  { 'min_version' : '8.2.0', 'max_version' : '8.2.3', 'fixed_display' : '8.5.12 / 8.9.4 / 9.0.1' },
  { 'min_version' : '8.3.0', 'max_version' : '8.3.2', 'fixed_display' : '8.5.12 / 8.9.4 / 9.0.1' },
  { 'min_version' : '8.4.0', 'max_version' : '8.4.2', 'fixed_display' : '8.5.12 / 8.9.4 / 9.0.1' },
  { 'min_version' : '8.5.0', 'fixed_version' : '8.5.12', 'fixed_display' : '8.5.12 / 8.9.4 / 9.0.1' },
  { 'min_version' : '8.9.1', 'fixed_version' : '8.9.4', 'fixed_display' : '8.9.4 / 9.0.1 (Data Center Only)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);