#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110775);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_cve_id("CVE-2017-9506");

  script_name(english:"Atlassian Jira < 7.2.15 OAuth Plugin IconUriServlet Internal Network Resource Disclosure CSRF");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application is affected by an
internal network resource disclosure (CSRF) vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of
Atlassian JIRA hosted on the remote web server is prior to 7.2.15. 
It is, therefore, affected by a internal network resource disclosure
(CSRF) vulnerability in the OAuth plugin IconUriServlet.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://ecosystem.atlassian.net/browse/OAUTH-344");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jira version 7.2.15 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9506");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

if (get_kb_item('Settings/PCI_DSS')) sig_seg = 2;
else sig_seg = 3;

vcf::check_granularity(app_info:app_info, sig_segments:sig_seg);

constraints = [
  { 'min_version' : '1.0.0', 'fixed_version' : '7.2.15' },
  { 'min_version' : '7.3.0', 'fixed_version' : '7.3.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xsrf':TRUE});
