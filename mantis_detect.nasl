##
#
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024/05/22. Deprecated by mantisbt_detect.nbin.
##

include("compat.inc");

if (description)
{
  script_id(11652);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_name(english:"MantisBT Detection (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated. Use mantisbt_detect.nbin instead.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. Use mantisbt_detect.nbin instead.");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use mantisbt_detect.nbin instead.');