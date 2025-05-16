#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201528);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/26");

  script_name(english:"openSUSE SEoL (42.3.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of openSUSE is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, openSUSE is 42.3.x. It is, therefore, no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://en.opensuse.org/Lifetime");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of openSUSE that is currently supported.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/03");
  script_set_attribute(attribute:"seol_date", value:"2019/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:opensuse:opensuse");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "ssh_get_info2.nasl");

  exit(0);
}

include('ucf.inc');

var os = ucf::get_os_cpe(vendor:'opensuse', product:'opensuse', type:'combined');

var constraints = [
  { max_branch : '42.3', min_branch : '42.3', seol : 20190701 }
];

ucf::os::check_and_report(os_info:os.info, constraints:constraints, severity:SECURITY_NOTE);
