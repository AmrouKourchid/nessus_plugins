#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148832);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/29");

  script_name(english:"Nessus Agent Unsupported Version Detection (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. For plugins which identify unsupported instances of this product, 
search the plugin feed for Nessus Agent SEoL.");
  # https://www.tenable.com/downloads
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acfa0664");
  # https://tenable.my.salesforce.com/sfc/p/#300000000pZp/a/3a000000gPnK/Gu5PvUfKyV_gL0LdpNGgSdJ0PLKk15KPFcucY_BGlek
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1e381f2");
  script_set_attribute(attribute:"solution", value:
"N/A");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus_agent");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 Tenable Network Security, Inc.");

  script_require_keys("installed_sw/Tenable Nessus Agent");

  exit(0);
}

exit(0, 'This plugin has been deprecated. For plugins which identify unsupported instances of this product, search the plugin feed for Nessus Agent SEoL.');