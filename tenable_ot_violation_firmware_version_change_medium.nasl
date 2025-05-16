#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(503163);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/16");

  script_name(english:"Firmware Version Change Detected (Medium)");

  script_set_attribute(attribute:"synopsis", value:
"A firmware version change has been detected on the remote OT asset.");
  script_set_attribute(attribute:"description", value:
"Changes in the controller firmware represent a major change in the
behavior of the device and usually cause a temporary interruption of
operations. An attacker could use firmware changes to add malicious
code to the controller, causing it to perform harmful operations
which are hard to detect.

This plugin only works with Tenable.ot.
Please visit https://www.tenable.com/products/tenable-ot for more information.");
  script_set_attribute(attribute:"solution", value:
"1) Check whether the firmware change was made as part of scheduled work and whether the source of the operation is approved for making such changes.

2) If this was not part of a planned operation, check the source asset of the event to determine if it has been compromised.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot Violation");
  
  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  
  exit(0);
}
