#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213884);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/10");

  script_name(english:"WinZip SEoL (26.0.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of WinZip is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, WinZip is 26.0.x. It is, therefore, no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.winzip.com/en/support/product-lifecycle-policy/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of WinZip that is currently supported.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/10");
  script_set_attribute(attribute:"seol_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winzip:winzip");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("winzip_installed.nbin");
  script_require_keys("installed_sw/winzip");

  exit(0);
}

include('ucf.inc');

var app = 'winzip';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { max_branch : '26.0', min_branch : '26.0', seol : 20240910 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
