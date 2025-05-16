#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190127);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/08");

  script_name(english:"AnyDesk < 8.0.0 Invalidated Signing Certificate (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A security update as been issued by the vendor advising their code signing certificate has changed on product versions
less than 8.0.0 on macOS. The vendor recommends updating to the latest version as the previous certificate will soon be
invalidated.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://anydesk.com/en/public-statement");
  script_set_attribute(attribute:"see_also", value:"https://anydesk.com/en/changelog/mac-os");
  script_set_attribute(attribute:"solution", value:
"Upgrade to AnyDesk version 8.0.0 or later.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:anydesk:anydesk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("anydesk_mac_installed.nbin");
  script_require_keys("installed_sw/AnyDesk");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'AnyDesk');

var constraints = [
  { 'fixed_version' : '8.0.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_NOTE
);