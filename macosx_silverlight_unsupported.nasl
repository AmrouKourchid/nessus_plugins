##
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024/05/08. Deprecated by silverlight_unsupported.nasl.
##

include("compat.inc");

if (description)
{
  script_id(58092);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/03");

  script_xref(name:"IAVA", value:"0001-A-0559");

  script_name(english:"Microsoft Silverlight Unsupported Version Detection (Mac OS X) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been depricated in favor of the combined SEoL plugin, Microsoft Silverlight SEoL (plugin ID 58134).");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2024 Tenable Network Security, Inc.");

  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Silverlight/Installed");

  exit(0);
}
exit(0, 'This plugin has been deprecated. Use silverlight_unsupported.nasl (plugin ID 58134) instead.');
