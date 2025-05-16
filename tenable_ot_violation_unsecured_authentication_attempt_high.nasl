#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(503216);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_name(english:"Unsecured Authentication Attempt Detected (High)");

  script_set_attribute(attribute:"synopsis", value:
"An unsecured authentication attempt has been detected.");
  script_set_attribute(attribute:"description", value:
"A server allow for authentication using credentials in an unencrypted manner
over unencrypted channel. Such credentials might be revealed to an attacker
intercepting this traffic and used to gain access to data on the server.

This plugin only works with Tenable.ot.
Please visit https://www.tenable.com/products/tenable-ot for more information.");
  script_set_attribute(attribute:"solution", value:
"1) Check if this communication was approved.

2) Consider migrating to more secure alternatives such as Secure Shell (SSH).

3) Reduce use of unencrypted protocols as much as possible.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot Violation");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}
