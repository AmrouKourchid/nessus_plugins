#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187978);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2021-31684");

  script_name(english:"Atlassian Confluence < 7.19.17 / 7.20.x < 8.3.4 / 8.4.x < 8.4.5 / 8.5.x < 8.5.4 / 8.6.x < 8.6.2 / 8.7.x < 8.7.1 (CONFSERVER-93361)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-93361 advisory.

  - A vulnerability was discovered in the indexOf function of JSONParserByteArray in JSON Smart versions 1.3
    and 2.4 which causes a denial of service (DOS) via a crafted web request. (CVE-2021-31684)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-93361");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.17, 8.3.4, 8.4.5, 8.5.4, 8.6.2, 8.7.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31684");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/12");

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
  { 'fixed_version' : '7.19.17', 'fixed_display' : '7.19.17 / 8.3.4 / 8.4.5 / 8.5.4 / 8.6.2 / 8.7.1' },
  { 'min_version' : '7.20.0', 'fixed_version' : '8.3.4' },
  { 'min_version' : '8.4.0', 'fixed_version' : '8.4.5' },
  { 'min_version' : '8.5.0', 'fixed_version' : '8.5.4' },
  { 'min_version' : '8.6.0', 'fixed_version' : '8.6.2' },
  { 'min_version' : '8.7.0', 'fixed_version' : '8.7.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
