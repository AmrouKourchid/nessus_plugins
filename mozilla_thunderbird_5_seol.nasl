#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213740);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_name(english:"Mozilla Thunderbird SEoL (5.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Mozilla Thunderbird is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, Mozilla Thunderbird version install on the remote host has reached end of support. 
It is, therefore, no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");

  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/Thunderbird/releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Mozilla Thunderbird that is currently supported.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/10");
  script_set_attribute(attribute:"seol_date", value:"2011/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");  
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl","macosx_thunderbird_installed.nasl");
  script_require_keys("installed_sw/Mozilla Thunderbird");

  exit(0);
}

include('ucf.inc');

var app = 'Mozilla Thunderbird';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
{ max_branch : '5', min_branch : '5', seol : 20110301 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
