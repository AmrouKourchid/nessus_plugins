#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182306);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_name(english:"VMware Carbon Black App Control SEoL (8.8.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of VMware Carbon Black App Control is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, VMware Carbon Black App Control is 8.8.x. It is, therefore, no longer maintained by its vendor
or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  # https://docs.vmware.com/en/VMware-Carbon-Black-App-Control/8.9/cb-ac-oer/GUID-21E6E704-237F-4415-8B50-DE380C6D9ECA.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f06474");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of VMware Carbon Black App Control that is currently supported.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");
  script_set_attribute(attribute:"seol_date", value:"2025/06/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:carbonblack:protection");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:carbon_black_app_control");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_carbon_black_app_control_web_console_detect.nbin", "vmware_carbon_black_app_control_win_installed.nbin");
  script_require_keys("installed_sw/VMware Carbon Black App Control");

  exit(0);
}

include('ucf.inc');

var app = 'VMware Carbon Black App Control';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { max_branch : '8.8', min_branch : '8.8', seol : 20250601 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
