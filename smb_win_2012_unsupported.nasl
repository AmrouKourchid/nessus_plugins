#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Deprecated on 2024 Mar 14. Replaced by Windows SEoL plugins.

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(182964);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/22");

  script_xref(name:"IAVA", value:"0001-A-0651");

  script_name(english:"Microsoft Windows Server 2012 Unsupported Version Detection (deprecated)");
  script_set_attribute(attribute:"synopsis", value:"
This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been replaced by Windows Security-End-of-Life plugins.");
  
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_exclude_keys("SMB/not_windows");
  script_require_ports("SMB/WindowsVersion");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use the equivalent Windows SEoL plugin instead.');
