#
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151128);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/29");

  script_name(english:"VMware Carbon Black App Control Unsupported Version Detection (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. For plugins which identify unsupported instances of this product, 
search the plugin feed for VMware Carbon Black App Control SEoL.");
  # https://community.carbonblack.com/t5/Documentation-Downloads/Carbon-Black-Product-Release-Lifecycle-Status/ta-p/39757
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17b7aaa6");
  # https://community.carbonblack.com/t5/Documentation-Downloads/Carbon-Black-Product-Support-Lifecycle-Policy/ta-p/35502
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94aff410");
  script_set_attribute(attribute:"solution", value:
"N/A");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported software.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:carbon_black_app_control");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:carbonblack:protection");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("installed_sw/VMware Carbon Black App Control");

  exit(0);
}
exit(0, 'This plugin has been deprecated. For plugins which identify unsupported instances of this product, search the plugin feed for VMware Carbon Black App Control SEoL.');