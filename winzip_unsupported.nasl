##
#
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2025/04/16. Deprecated by plugin feed for Winzip SEoL.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78675);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_xref(name:"IAVA", value:"0001-A-0623");

  script_name(english:"WinZip Unsupported Version Detection (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. for plugins which identify unsupported instances of this product, 
search the plugin feed for Winzip SEoL.");
  script_set_attribute(attribute:"see_also", value:"http://www.winzip.com");
  script_set_attribute(attribute:"see_also", value:"http://kb.winzip.com/kb/entry/132/");
  script_set_attribute(attribute:"solution", value:
"N/A");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winzip:winzip");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}
exit(0, 'This plugin has been deprecated. For plugins which identify unsupported instances of this product, search the plugin feed for WinZip SEoL.');