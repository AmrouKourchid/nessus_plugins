#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(503199);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_name(english:"Device Presence Anomaly Detected (Medium)");

  script_set_attribute(attribute:"synopsis", value:
"A device presence anomaly has been detected.");
  script_set_attribute(attribute:"description", value:
"It is important to know what assets exist in your network. New assets can
indicate unexpected network connections, third-party connectivity, or
potential threats to the network.

This plugin only works with Tenable.ot.
Please visit https://www.tenable.com/products/tenable-ot for more information.");
  script_set_attribute(attribute:"solution", value:
"Make sure that the asset is expected to be at this IP and is familiar to you
or to other asset owners. If you are not familiar with the asset, contact the
relevant network admin to check if new devices have been connected. In case
this asset is not familiar to you or to other network admins, consider
isolating the asset for further investigation");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot Violation");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}
