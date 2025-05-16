#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182320);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_name(english:"OpenSSL SEoL (3.0.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of OpenSSL is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, OpenSSL is 3.0.x. It is, therefore, no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/policies/releasestrat.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities-3.0.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of OpenSSL that is currently supported.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");
  script_set_attribute(attribute:"seol_date", value:"2026/09/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('ucf.inc');

var app = 'OpenSSL';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { max_branch : '3.0', min_branch : '3.0', seol : 20260907 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
