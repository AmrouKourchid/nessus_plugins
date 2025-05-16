#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Deprecated on 2024 Mar 14. Replaced by Windows SEoL plugins.

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(157063);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_name(english:"Microsoft Windows 10 Version 2004 Unsupported Version Detection (deprecated)");

  script_set_attribute(attribute:"synopsis", value:"
This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been replaced by Windows Security-End-of-Life plugins.");
  
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use the equivalent Windows SEoL plugin instead.');
