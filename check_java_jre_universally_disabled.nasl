#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(65739);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/02");

  script_name(english:"Java JRE Universally Enabled");

  script_set_attribute(attribute:"synopsis", value:
"Java JRE has not been universally disabled on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Java JRE has not been universally disabled on the remote host via the Java control panel.
Note that while Java can be individually disabled for each browser,
universally disabling Java prevents it from running for all users and browsers.
Functionality to disable Java universally in Windows may not be available in all versions of Java.");
  script_set_attribute(attribute:"see_also", value:"https://www.java.com/en/download/help/disable_browser.xml");
  script_set_attribute(attribute:"solution", value:
"Disable Java universally unless it is needed.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");

  script_dependencies("oracle_java_jre_enabled.nasl");
  script_require_keys("SMB/Java/JRE/universally_enabled");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

if (get_kb_item("SMB/Java/JRE/universally_enabled"))
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  security_note(port);
  exit(0);
}
exit(0, "Java has been universally disabled.");
