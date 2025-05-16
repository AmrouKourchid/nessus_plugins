#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213787);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/10");

  script_name(english:"Mozilla Firefox SEoL (43.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Mozilla Firefox is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, Mozilla Firefox version install on the remote host has reached end of support. 
It is, therefore, no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");

  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/firefox/releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Mozilla Firefox that is currently supported.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/10");
  script_set_attribute(attribute:"seol_date", value:"2016/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl","macosx_firefox_installed.nasl");
  script_require_keys("installed_sw/Mozilla Firefox");

  exit(0);
}

include('ucf.inc');

var app = 'Mozilla Firefox';

var app_info = vcf::combined_get_app_info(app:app);

if (app_info['sw_edition'] == "ESR")
    audit(AUDIT_NOT_INST, "Standard Release (Non-ESR) "+app);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
{ max_branch : '43', min_branch : '43', seol : 20160126 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
