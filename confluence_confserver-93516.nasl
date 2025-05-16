#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189240);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2023-22526");
  script_xref(name:"IAVA", value:"2024-A-0025-S");

  script_name(english:"Atlassian Confluence < 7.19.17 / 8.0.x < 8.5.5 / 8.6.x < 8.7.2 (CONFSERVER-93516)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-93516 advisory.

  - This High severity RCE (Remote Code Execution) vulnerability was introduced in version 7.19.0 of
    Confluence Data Center. This RCE (Remote Code Execution) vulnerability, with a CVSS Score of 7.2, allows
    an authenticated attacker to execute arbitrary code which has high impact to confidentiality, high impact
    to integrity, high impact to availability, and requires no user interaction. Atlassian recommends that
    Confluence Data Center customers upgrade to latest version, if you are unable to do so, upgrade your
    instance to one of the specified supported fixed versions: Confluence Data Center and Server 7.19: Upgrade
    to a release 7.19.17, or any higher 7.19.x release Confluence Data Center and Server 8.5: Upgrade to a
    release 8.5.5 or any higher 8.5.x release Confluence Data Center and Server 8.7: Upgrade to a release
    8.7.2 or any higher release See the release notes ([https://confluence.atlassian.com/doc/confluence-
    release-notes-327.html]). You can download the latest version of Confluence Data Center from the download
    center ([https://www.atlassian.com/software/confluence/download-archives]). This vulnerability was
    discovered by m1sn0w and reported via our Bug Bounty program (CVE-2023-22526)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-93516");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.17, 8.5.5, 8.7.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22526");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/19");

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
  { 'min_version' : '7.19.0', 'fixed_version' : '7.19.17'},
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
