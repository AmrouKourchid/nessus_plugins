#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140767);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2020-14179");
  script_xref(name:"IAVA", value:"2020-A-0432");

  script_name(english:"Atlassian Jira < 8.5.8 / 8.6.0 < 8.11.1 Sensitive Data Exposure (JRASERVER-71536)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a sensitive data exposure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian Jira hosted on the remote web server is prior
to 8.5.8 or 8.6.x < 8.11.1. It is, therefore, affected by a sensitive data exposure vulnerability that allows remote,
unauthenticated attackers to view custom field names and custom SLA names due to a vulnerability in the
/secure/QueryComponent!Default.jspa endpoint.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-71536");
  # https://confluence.atlassian.com/jiracore/issues-resolved-in-8-5-8-1021233891.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5d86526");
  # https://confluence.atlassian.com/jirasoftware/issues-resolved-in-8-11-1-1018767316.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3936f10b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.5.8, 8.11.1, 8.12.0 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14179");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

constraints = [
  { 'min_version' : '0', 'fixed_version' : '8.5.8' },
  { 'min_version' : '8.6.0', 'fixed_version' : '8.11.1', 'fixed_display' : '8.11.1 / 8.12.0' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
