#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(503213);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_name(english:"Threat Exposure Indicators Detected (Critical)");

  script_set_attribute(attribute:"synopsis", value:
"A threat exposure indicator has been detected.");
  script_set_attribute(attribute:"description", value:
"Intrusion detection events may indicate that the network has been compromised
and is exposed to malicious entities. It is important to be aware of any such
traffic that may indicate reconnaissance activity, attacks on the network, or
propagation of a threat to/from other subnets of the network.

This plugin only works with Tenable.ot.
Please visit https://www.tenable.com/products/tenable-ot for more information.");
  script_set_attribute(attribute:"solution", value:
"Make sure that the source and destination assets are familiar to you. In
addition, depending on the suspicious traffic, you may consider updating
anti-virus definitions, firewall rules, or other security patches. You can
open the Rule Details panel to view additional details about this particular
rule.");
  script_set_attribute(attribute:"risk_factor", value:"Critical");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot Violation");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}
