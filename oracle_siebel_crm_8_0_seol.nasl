#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206106);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_name(english:"Oracle Siebel CRM SEoL (8.0.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Oracle Siebel CRM is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, Oracle Siebel CRM is 8.0.x. It is, therefore, no longer maintained by its
vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  # https://www.oracle.com/us/support/library/lifetime-support-applications-069216.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3022d1d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Oracle Siebel CRM that is currently supported.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/22");
  script_set_attribute(attribute:"seol_date", value:"2015/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:siebel_crm");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_siebel_server_installed.nasl");
  script_require_keys("installed_sw/Oracle Siebel Server");

  exit(0);
}

include('ucf.inc');

var app = 'Oracle Siebel Server';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { branch : '8.0', seol : 20150131 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
