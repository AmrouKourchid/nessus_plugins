#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90544);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/23");

  script_xref(name:"ZDI", value:"ZDI-16-241");
  script_xref(name:"ZDI", value:"ZDI-16-242");
  script_xref(name:"IAVA", value:"0001-A-0518");

  script_name(english:"Apple QuickTime Unsupported on Windows");
  script_summary(english:"Checks for QuickTime on Windows.");


  script_set_attribute(attribute:"synopsis", value:
"Apple QuickTime is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Apple no longer supports any version of QuickTime on Windows.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note that the last version of QuickTime released for Windows had known
vulnerabilities related to processing atom indexes. A remote attacker
can exploit these, by convincing a user to view a malicious website
or open a crafted file, to cause heap corruption within QuickTime,
resulting in the execution of arbitrary code in the context of the
user or process running QuickTime.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205771");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-242/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-241/");
  script_set_attribute(attribute:"see_also", value:"https://www.us-cert.gov/ncas/alerts/TA16-105A");
  script_set_attribute(attribute:"solution", value:
"Uninstall Apple QuickTime.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/15");
  script_set_attribute(attribute:"seol_date", value:"2016/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 Tenable Network Security, Inc.");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("installed_sw/QuickTime for Windows");

  exit(0);
}

include('ucf.inc');

var app = 'QuickTime for Windows';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { min_branch : '0', seol : 20160414}
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
