#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(503192);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_name(english:"Device Mode Transition Detected (High)");

  script_set_attribute(attribute:"synopsis", value:
"A device mode transition has been detected on the OT asset.");
  script_set_attribute(attribute:"description", value:
"The state of the controller code changed, regardless of the state expected by
the process. When not part of scheduled maintenance, forcing can be used to
introduce hard-to-detect, long-lasting changes that are harmful to operations.

This plugin only works with Tenable.ot.
Please visit https://www.tenable.com/products/tenable-ot for more information.");
  script_set_attribute(attribute:"solution", value:
"1) Check whether the transition was made as part of scheduled maintenance work
and verify that the source of the operation is approved to perform this
operation.

2) Verify with an OT engineer that the forced value matches the desired value.

3) If this was not part of a planned operation, check the source asset of the
event to determine if it has been compromised.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot Violation");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}
