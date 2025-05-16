#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58134);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/09");

  script_xref(name:"IAVA", value:"0001-A-0559");

  script_name(english:"Microsoft Silverlight SEoL");

  script_set_attribute(attribute:"synopsis", value:"An unsupported version of Microsoft Silverlight is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of the Microsoft Silverlight on the remote host is no longer maintained by
its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is
likely to contain security vulnerabilities.");
  # https://learn.microsoft.com/en-us/lifecycle/products/?terms=silverlight
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5c496a5");
  # https://learn.microsoft.com/en-us/lifecycle/announcements/silverlight-end-of-support
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb480fbe");
  script_set_attribute(attribute:"solution", value:
"Microsoft Silverlight has been discontinued. Please refer to the vendor for support.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/27");
  script_set_attribute(attribute:"seol_date", value:"2021/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2024 Tenable Network Security, Inc.");

  script_dependencies("silverlight_detect.nasl", "macosx_silverlight_installed.nasl");
  script_require_keys("installed_sw/Microsoft Silverlight");

  exit(0);
}

include('ucf.inc');

var app = 'Microsoft Silverlight';

var app_info = vcf::combined_get_app_info(app:app);

var constraints = [{ max_branch : '0', seol : 20211012}];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
