#%NASL_MIN_LEVEL 70300
##
#
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024/03/19. Deprecated
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84018);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_xref(name:"IAVA", value:"0001-A-0546");

  script_name(english:"ManageEngine Applications Manager Unsupported Version Detection (deprecated)");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. For plugins which identify unsupported instances of this product, 
search the plugin feed for ManageEngine Applications Manager SEoL.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/applications_manager/eol.html");
  script_set_attribute(attribute:"solution", value:
"N/A");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:manageengine:applications_manager");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2024 Tenable Network Security, Inc.");

  script_dependencies("manageengine_applications_manager_detect.nasl");
  script_require_keys("installed_sw/ManageEngine Applications Manager");
  script_require_ports("Services/www", 9090);

exit(0);
}
exit(0, 'This plugin has been deprecated. For plugins which identify unsupported instances of this product, search the plugin feed for ManageEngine Applications Managers SEoL.');