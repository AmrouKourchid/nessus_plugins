#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182237);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_name(english:"Atlassian JIRA SEoL (3.0.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Atlassian JIRA is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, Atlassian JIRA is 3.0.x. It is, therefore, no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  # https://web.archive.org/web/20100209033738/http://confluence.atlassian.com/display/Support/Atlassian+Support+End+of+Life+Policy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9aab4d87");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Atlassian JIRA that is currently supported.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");
  script_set_attribute(attribute:"seol_date", value:"2006/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('ucf.inc');

var app = 'Atlassian JIRA';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { max_branch : '3.0', min_branch : '3.0', seol : 20061103 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
