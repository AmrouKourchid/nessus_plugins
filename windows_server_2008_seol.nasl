#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192782);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/10");

  script_name(english:"Microsoft Windows Server 2008 SEoL");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Microsoft Windows is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Microsoft Windows Server 2008 is no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  # https://support.microsoft.com/en-us/help/4456235/end-of-support-for-windows-server-2008-and-windows-server-2008-r2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?883c9d9f");
  # https://learn.microsoft.com/en-us/windows-server/get-started/extended-security-updates-overview
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39fb789a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Windows that is currently supported.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/02");
  script_set_attribute(attribute:"seol_date", value:"2020/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2008");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_windows_installed.nbin");

  exit(0);
}

include('ucf.inc');

var os = ucf::get_os_cpe(vendor:'microsoft', product:'windows_server_2008', type:'local');

var constraints = [
  { eseol : 20230110, seol : 20200114 }
];

ucf::os::check_and_report(os_info:os.info, constraints:constraints, severity:SECURITY_HOLE);
