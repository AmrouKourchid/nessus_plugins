#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202700);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id("CVE-2024-21686");
  script_xref(name:"IAVA", value:"2024-A-0412");

  script_name(english:"Atlassian Confluence < 7.19.22 / 7.20.x < 8.5.9 / 8.6.x < 8.9.1 XSS (CONFSERVER-96134)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-96134 advisory.

  - This High severity Stored XSS vulnerability was introduced in versions 7.13 of Confluence Data Center and
    Server. This Stored XSS vulnerability, with a CVSS Score of 7.3, allows an authenticated attacker to
    execute arbitrary HTML or JavaScript code on a victims browser which has high impact to confidentiality,
    high impact to integrity, no impact to availability, and requires user interaction. Atlassian recommends
    that Confluence Data Center and Server customers upgrade to latest version, if you are unable to do so,
    upgrade your instance to one of the specified supported fixed versions listed on this CVE See the release
    notes (https://confluence.atlassian.com/doc/confluence-release-notes-327.html). You can download the
    latest version of Confluence Data Center and Server from the download center
    (https://www.atlassian.com/software/confluence/download-archives). This vulnerability was reported via our
    Bug Bounty program. (CVE-2024-21686)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-96134");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.22, 8.5.9, 8.9.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21686");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl", "confluence_nix_installed.nbin", "confluence_win_installed.nbin");
  script_require_keys("installed_sw/Atlassian Confluence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian Confluence');

var constraints = [
  { 'max_version' : '7.17.5', 'fixed_display' : '7.19.22 / 8.5.9 / 8.9.1' },
  { 'min_version' : '7.18.0', 'max_version' : '7.18.3', 'fixed_display' : '7.19.22 / 8.5.9 / 8.9.1' },
  { 'min_version' : '7.19.0', 'fixed_version' : '7.19.22', 'fixed_display' : '7.19.22 / 8.5.9 / 8.9.1' },
  { 'min_version' : '7.20.0', 'max_version' : '7.20.3', 'fixed_display' : '8.5.9 / 8.9.1' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.4', 'fixed_display' : '8.5.9 / 8.9.1' },
  { 'min_version' : '8.1.0', 'max_version' : '8.1.4', 'fixed_display' : '8.5.9 / 8.9.1' },
  { 'min_version' : '8.2.0', 'max_version' : '8.2.3', 'fixed_display' : '8.5.9 / 8.9.1' },
  { 'min_version' : '8.3.0', 'max_version' : '8.3.4', 'fixed_display' : '8.5.9 / 8.9.1' },
  { 'min_version' : '8.4.0', 'max_version' : '8.4.5', 'fixed_display' : '8.5.9 / 8.9.1' },
  { 'min_version' : '8.5.0', 'fixed_version' : '8.5.9', 'fixed_display' : '8.5.9 / 8.9.1' },
  { 'min_version' : '8.6.0', 'max_version' : '8.6.2', 'fixed_display' : '8.9.1 (Data Center Only)' },
  { 'min_version' : '8.7.0', 'max_version' : '8.7.2', 'fixed_display' : '8.9.1 (Data Center Only)' },
  { 'min_version' : '8.8.0', 'max_version' : '8.8.1', 'fixed_display' : '8.9.1 (Data Center Only)' },
  { 'min_version' : '8.9.0', 'fixed_version' : '8.9.1', 'fixed_display' : '8.9.1 (Data Center Only)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
