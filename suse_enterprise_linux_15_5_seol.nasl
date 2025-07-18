#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214937);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/26");

  script_name(english:"SUSE Linux Enterprise SEoL (15.5.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of SUSE Linux Enterprise is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, SUSE Linux Enterprise is 15.5.x. It is, therefore, no longer maintained by its vendor or
provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/lifecycle/#product-suse-linux-enterprise-server");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of SUSE Linux Enterprise that is currently supported.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/04");
  script_set_attribute(attribute:"seol_date", value:"2024/12/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:linux_enterprise");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:linux_enterprise_desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux_enterprise_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "ssh_get_info2.nasl");

  exit(0);
}

include('ucf.inc');

var os = ucf::get_os_cpe(vendor:'suse', product:'linux_enterprise*', type:'combined');

var constraints = [
  { max_branch : '15.5', min_branch : '15.5', eseol : 20271231, seol : 20241231 }
];

ucf::os::check_and_report(os_info:os.info, constraints:constraints, severity:SECURITY_NOTE);
