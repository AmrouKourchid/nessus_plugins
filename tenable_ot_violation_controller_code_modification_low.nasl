#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(503166);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_name(english:"Controller Code Modification Detected (Low)");

  script_set_attribute(attribute:"synopsis", value:
"A controller code modification has been detected on the remote OT asset.");
script_set_attribute(attribute:"description", value:
"The system detected a change in the controller code that was made via the 
network. An attacker may use code changes to disrupt normal operations, to 
cause production losses, or to create a security threat.

This plugin only works with Tenable.ot.
Please visit https://www.tenable.com/products/tenable-ot for more information.");
  script_set_attribute(attribute:"solution", value:
"1) Check whether the change was made as part of scheduled work and whether the source of the operation is approved for making such changes.

2) In the code revision tab, check if the code has changed. If it has changed, validate with an OT engineer that it matches the planned scope.

3) If this was not part of a planned operation, check the source asset of the event to determine if it has been compromised.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot Violation");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}
