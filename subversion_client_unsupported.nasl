#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78506);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/29");

  script_xref(name:"IAVA", value:"0001-A-0516");

  script_name(english:"Apache Subversion Client Unsupported Version Detection (deprecated)");
  script_summary(english:"Checks for an unsupported version of Apache Subversion Client.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. For plugins which identify unsupported instances of this product, 
search the plugin feed for Subversion Client SEoL.");
  script_set_attribute(attribute:"see_also", value:"https://subversion.apache.org/download/");
  script_set_attribute(attribute:"solution", value:
"N/A");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

  script_dependencies("subversion_installed.nasl");
  
  exit(0);
}
exit(0, 'This plugin has been deprecated. For plugins which identify unsupported instances of this product, search the plugin feed for Subversion Client SEoL.');