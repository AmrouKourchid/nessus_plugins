#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213750);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/10");

  script_name(english:"Microsoft Windows 11 21H2 SEoL");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Microsoft Windows is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Microsoft Windows 11 21H2 is no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  # https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c52c16a3");  
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Windows that is currently supported.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/10");
  script_set_attribute(attribute:"seol_date", value:"2024/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_11_21h2");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_windows_installed.nbin");

  exit(0);
}

include('ucf.inc');

var os = ucf::get_os_cpe(vendor:'microsoft', product:'windows_11_21h2', type:'local');

var constraints = [
  { seol : 20241008 }
];

ucf::os::check_and_report(os_info:os.info, constraints:constraints, severity:SECURITY_NOTE);
