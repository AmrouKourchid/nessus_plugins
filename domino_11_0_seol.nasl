#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206783);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_name(english:"HCLTech Domino SEoL (11.0.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of HCLTech Domino is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, HCLTech Domino is 11.0.x. It is, therefore, no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  # https://support.hcltechsw.com/csm?id=kb_article&sysparm_article=KB0114064
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53e04cd2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of HCLTech Domino that is currently supported.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/09");
  script_set_attribute(attribute:"seol_date", value:"2025/06/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hcltech:domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hcltech:domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("lotus_domino_installed.nasl", "domino_installed.nasl");
  script_require_keys("installed_sw/IBM Domino");

  exit(0);
}

include('ucf.inc');

var app = 'IBM Domino';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { max_branch : '11.0', min_branch : '11.0', seol : 20250626 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
