#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Deprecated on 2024 Mar 14. Replaced by Windows SEoL plugins.

include("compat.inc");

if (description)
{
  script_id(84729);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_xref(name:"EDB-ID", value:"41929");

  script_xref(name:"IAVA", value:"0001-A-0024");

  script_name(english:"Microsoft Windows Server 2003 Unsupported Installation Detection (deprecated)");
  script_summary(english:"Checks the OS / SMB fingerprint.");

  script_set_attribute(attribute:"synopsis", value:"
This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been replaced by Windows Security-End-of-Life plugins.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_2003_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2024 Tenable Network Security, Inc.");

  exit(0);
}


exit(0, 'This plugin has been deprecated. Use the equivalent Windows SEoL plugin instead.');
