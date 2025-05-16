##
#
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024/08/06. Deprecated by cact_detect.nasl.
##

include("compat.inc");


if (description)
{
  script_id(46221);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/24");

  script_name(english:"Cacti Detection (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. Use cacti_detect.nasl (plugin ID 173896) instead.");
  script_set_attribute(attribute:"see_also", value:"https://www.cacti.net/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cacti:cacti");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use cacti_detect.nasl (plugin ID 173896) instead.');
