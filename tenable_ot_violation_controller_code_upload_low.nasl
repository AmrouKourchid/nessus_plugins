#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(503170);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_name(english:"Controller Code Upload Detected (Low)");

  script_set_attribute(attribute:"synopsis", value:
"A controller code upload has been detected on the OT asset.");
  script_set_attribute(attribute:"description", value:
"An upload of the controller code has been detected over the network. When not 
part of regular operations, a code upload can be used to gather information 
about the controller behavior as part of reconnaissance activity.

This plugin only works with Tenable.ot.
Please visit https://www.tenable.com/products/tenable-ot for more information.");
  script_set_attribute(attribute:"solution", value:
"1) Check whether the upload was done as part of scheduled maintenance work and whether the source of the operation is approved for making such changes.

2) If this was not part of a planned operation, check the source asset of the event to determine if it has been compromised.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot Violation");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}