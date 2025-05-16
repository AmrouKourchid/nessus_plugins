#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192806);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_name(english:"VMware Fusion SEoL (5.0.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of VMware Fusion is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, VMware Fusion is 5.0.x. It is, therefore, no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://lifecycle.vmware.com/#/?advancedFilter=checkbox_sup");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of VMware Fusion that is currently supported.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/02");
  script_set_attribute(attribute:"seol_date", value:"2014/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("installed_sw/VMware Fusion");

  exit(0);
}

include('ucf.inc');

var app = 'VMware Fusion';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { branch : '5', seol : 20140823 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
