#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(500012);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/18");

  script_name(english:"Rockwell Automation Controller Asset Information");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a Rockwell Controller device.");
  script_set_attribute(attribute:"description", value:
  "It is possible to obtain attributes of the remote Rockwell Controller device.
  
  This plugin only works with Tenable.ot.
  Please visit https://www.tenable.com/products/tenable-ot for more information.");
  script_set_attribute(attribute:"see_also", value:"https://www.rockwellautomation.com/en-us/products/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}
