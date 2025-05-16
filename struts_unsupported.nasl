#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117461);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/29");
  script_xref(name:"IAVA", value:"0001-A-0515");

  script_name(english:"Apache Struts Unsupported Version Detection (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. To identify unsupported instances of this product, search the plugin feed for Apache
Struts SEoL.");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/struts1eol-announcement.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/struts23-eol-announcement");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"the product is no longer supported by vendor");
  
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

exit(0, 'This plugin has been deprecated.');
