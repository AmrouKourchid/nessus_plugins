#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(503189);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_name(english:"Device Status Modification Detected (Critical)");

  script_set_attribute(attribute:"synopsis", value:
"A device status modification has been detected on the remote OT asset.");
  script_set_attribute(attribute:"description", value:
"Changes in the controller state can stop operations altogether or start an
operation that should not have been started. These operations can be used by an
attacker to disrupt normal operation, cause production losses, or create safety
concerns.

This plugin only works with Tenable.ot.
Please visit https://www.tenable.com/products/tenable-ot for more information.");
  script_set_attribute(attribute:"solution", value:
"1) Check whether the status change was made as part of scheduled maintenance
work and that the source of the operation is approved to perform it.

2) Verify with an OT engineer that the new state is the desired state.

3) If this was not part of a planned operation, check the source asset of the
event to determine if it was compromised.");
  script_set_attribute(attribute:"risk_factor", value:"Critical");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot Violation");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}
