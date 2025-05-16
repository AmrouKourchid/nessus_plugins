#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188071);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2024-21672");
  script_xref(name:"IAVA", value:"2024-A-0025-S");

  script_name(english:"Atlassian Confluence < 7.19.18 / 8.0.x < 8.5.5 / 8.6.x < 8.7.2 (CONFSERVER-94064)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-94064 advisory.

  - RCE in Confluence Data Center and Server (CVE-2024-21672)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-94064");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.18, 8.5.5, 8.7.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21672");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

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
  { 'min_version' : '7.13.0', 'fixed_version' : '7.13.21', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '7.19.0', 'fixed_version' : '7.19.18'},
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.5', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '8.1.0', 'fixed_version' : '8.1.5', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '8.2.0', 'fixed_version' : '8.2.4', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '8.3.0', 'fixed_version' : '8.3.5', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '8.4.0', 'fixed_version' : '8.4.6', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '8.5.0', 'fixed_version' : '8.5.5' },
  { 'min_version' : '8.6.0', 'fixed_version' : '8.6.3' , 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '8.7.0', 'fixed_version' : '8.7.2' }
  ];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
