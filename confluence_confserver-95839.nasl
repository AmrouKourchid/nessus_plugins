#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197937);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/02");

  script_cve_id("CVE-2023-45859");
  script_xref(name:"IAVA", value:"2024-A-0305-S");
  script_xref(name:"IAVA", value:"2024-A-0366");

  script_name(english:"Atlassian Confluence 5.5 < 7.19.22 / 7.20.x < 8.5.9 / 8.6.x < 8.9.0 MPC (CONFSERVER-95839)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a missing permission check 
vulnerability as referenced in the CONFSERVER-95839 advisory.

  - In Hazelcast through 4.1.10, 4.2 through 4.2.8, 5.0 through 5.0.5, 5.1 through 5.1.7, 5.2 through 5.2.4,
    and 5.3 through 5.3.2, some client operations don't check permissions properly, allowing authenticated
    users to access data stored in the cluster. (CVE-2023-45859)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-95839");
  script_set_attribute(attribute:"see_also", value:"https://confluence.atlassian.com/doc/confluence-release-notes-327.html");
  script_set_attribute(attribute:"see_also", value:"https://www.atlassian.com/software/confluence/download-archives");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.22, 8.5.9, 8.9.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/27");

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
  { 'min_version' : '5.5', 'max_version' : '7.16', 'fixed_display' : '7.19.22' },
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
  { 'min_version' : '8.6', 'fixed_version' : '8.6.2', 'fixed_display' : '8.9.0 (Data Center Only)' },
  { 'min_version' : '8.7', 'fixed_version' : '8.7.2', 'fixed_display' : '8.9.0 (Data Center Only)' },
  { 'min_version' : '8.8', 'fixed_version' : '8.8.1', 'fixed_display' : '8.9.0 (Data Center Only)' }  
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
