#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207075);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_name(english:"Chef Infra Client SEoL (16.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Chef Infra Client is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, Chef Infra Client is 16.x or earlier. It is, therefore, no longer maintained by its
vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://docs.chef.io/versions/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Chef Infra Client that is currently supported.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/12");
  script_set_attribute(attribute:"seol_date", value:"2022/11/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:chef:chef");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("chef_infra_client_win_installed.nbin","chef_infra_client_nix_installed.nbin","chef_infra_client_web_detect.nbin");
  script_require_keys("installed_sw/Chef Infra Client");

  exit(0);
}

include('ucf.inc');

var app = 'Chef Infra Client';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:1);

var constraints = [
  { branch : '16', seol : 20221130 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
