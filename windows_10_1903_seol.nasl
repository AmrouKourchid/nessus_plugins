#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192772);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_name(english:"Microsoft Windows 10 1903 SEoL");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Microsoft Windows is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Microsoft Windows 10 1903 is no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  # https://learn.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04d608ba");
  # https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ad4d307");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Windows that is currently supported.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/02");
  script_set_attribute(attribute:"seol_date", value:"2020/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_1903");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_windows_installed.nbin");

  exit(0);
}

include('ucf.inc');

var os = ucf::get_os_cpe(vendor:'microsoft', product:'windows_10_1903', type:'local');

var constraints = [
  { seol : 20201208 }
];

ucf::os::check_and_report(os_info:os.info, constraints:constraints, severity:SECURITY_NOTE);
