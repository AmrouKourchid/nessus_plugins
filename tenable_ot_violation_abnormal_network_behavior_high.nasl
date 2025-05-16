#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(503196);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_name(english:"Abnormal Network Behavior Detected (High)");

  script_set_attribute(attribute:"synopsis", value:
"An abnormal network behavior has been detected.");
  script_set_attribute(attribute:"description", value:
"Abnormal network behavior by unexpected assets can indicate reconnaissance of
the network by a potential attacker.

This plugin only works with Tenable.ot.
Please visit https://www.tenable.com/products/tenable-ot for more information.");
  script_set_attribute(attribute:"solution", value:
"Check the source asset to determine whether it is expected to be generating
this network traffic. If not, contact the source asset owner to check if any
scans were initiated. If the network traffic isn't accounted for, consider
isolating the source asset to decrease network exposure while you investigate
further.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot Violation");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}
