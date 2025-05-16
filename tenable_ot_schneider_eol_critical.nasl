#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');

if (description)
{
  script_id(503145);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/16");

  script_name(english:"Schneider Electric Discontinued Devices Detection");

  script_set_attribute(attribute:"synopsis", value:
"Detection of Schneider devices that are discontinued and no longer supported.");
  script_set_attribute(attribute:"description", value:
"The current plugin identifies Schneider devices that are currently discontinued. 
Schneider Lifecycle Statuses:
 - Active: Most current offering within a product category. 
 - End of Life: Discontinued date announced - actively execute migrations and last time buys. 
Product generally orderable until the discontinued date. 
 - Discontinued: Product no longer manufactured or procured. Repair/exchange services may be available.");
  script_set_attribute(attribute:"see_also", value:"https://www.se.com/in/en/product-substitution/");
  script_set_attribute(attribute:"solution", value:
"Migrate to a product that is actively supported.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ot_api_integration.nasl");
  script_require_keys("Tenable.ot/Schneider");

  exit(0);
}

#
# EoL checks here
#

include('tenable_ot_eol_funcs.inc');

get_kb_item_or_exit('Tenable.ot/Schneider');

var asset = tenable_ot::assets::get(vendor:'Schneider');

var eol_info = {
  "171CCC96030": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2024/02/15",
    "Reference": "https://www.se.com/us/en/product/171CCC96030/",
    "ReplacementProduct": "171CBU98090",
    "LastModifiedDate": "N/A"
  },
  "171CCC98020": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2023/05/31",
    "Reference": "https://www.se.com/us/en/product/171CCC98020/",
    "ReplacementProduct": "171CBU98090",
    "LastModifiedDate": "N/A"
  },
  "171CCC98030": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2023/05/31",
    "Reference": "https://www.se.com/us/en/product/171CCC98030/",
    "ReplacementProduct": "171CBU98090",
    "LastModifiedDate": "N/A"
  },
  "174CEV30010": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2021/02/03",
    "Reference": "https://www.se.com/us/en/product/174CEV30010/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV61WD11N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2025/01/13",
    "Reference": "https://www.se.com/us/en/product/ATV61WD11N4/",
    "ReplacementProduct": "ATV650D11N4",
    "LastModifiedDate": "N/A"
  },
  "ATV61WD15N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2025/01/13",
    "Reference": "https://www.se.com/us/en/product/ATV61WD15N4/",
    "ReplacementProduct": "ATV650D15N4",
    "LastModifiedDate": "N/A"
  },
  "ATV61WD30N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2025/04/01",
    "Reference": "https://www.se.com/us/en/product/ATV61WD30N4/",
    "ReplacementProduct": "ATV650D30N4",
    "LastModifiedDate": "N/A"
  },
  "ATV61WU15N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2025/04/01",
    "Reference": "https://www.se.com/us/en/product/ATV61WU15N4/",
    "ReplacementProduct": "ATV650U15N4",
    "LastModifiedDate": "N/A"
  },
  "ATV61WU22N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2025/04/01",
    "Reference": "https://www.se.com/us/en/product/ATV61WU22N4/",
    "ReplacementProduct": "ATV650U22N4",
    "LastModifiedDate": "N/A"
  },
  "ATV61WU30N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2025/04/01",
    "Reference": "https://www.se.com/us/en/product/ATV61WU30N4/",
    "ReplacementProduct": "ATV650U30N4",
    "LastModifiedDate": "N/A"
  },
  "ATV61WU40N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2025/04/01",
    "Reference": "https://www.se.com/us/en/product/ATV61WU40N4/",
    "ReplacementProduct": "ATV650U40N4",
    "LastModifiedDate": "N/A"
  },
  "ATV61WU55N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2025/04/01",
    "Reference": "https://www.se.com/us/en/product/ATV61WU55N4/",
    "ReplacementProduct": "ATV650U55N4",
    "LastModifiedDate": "N/A"
  },
  "ATV61WU75N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2025/04/01",
    "Reference": "https://www.se.com/us/en/product/ATV61WU75N4/",
    "ReplacementProduct": "ATV650U75N4",
    "LastModifiedDate": "N/A"
  },
  "BMXDRA0805": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2023/08/18",
    "Reference": "https://www.se.com/us/en/product/BMXDRA0805/",
    "ReplacementProduct": "BMXDRA0815",
    "LastModifiedDate": "N/A"
  },
  "BMXP342030": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2018/12/31",
    "Reference": "https://www.se.com/us/en/product/BMXP342030/",
    "ReplacementProduct": "BMXP3420302",
    "LastModifiedDate": "N/A"
  },
  "EGX100MG": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2023/06/23",
    "Reference": "https://www.se.com/us/en/product/EGX100MG/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "EGX150": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2024/06/12",
    "Reference": "https://www.se.com/us/en/product/EGX150/",
    "ReplacementProduct": "PAS600",
    "LastModifiedDate": "N/A"
  },
  "EGX300": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2023/06/13",
    "Reference": "https://www.se.com/us/en/product/EGX300/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TEST-DISCONTINUED": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2050/12/31",
    "Reference": "https://www.se.com/us/en/product/TEST-DISCONTINUED/",
    "ReplacementProduct": "TEST-NEWMODEL",
    "LastModifiedDate": "2015/03/18"
  },
  "TSXP572634M": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2023/12/31",
    "Reference": "https://www.se.com/us/en/product/TSXP572634M/",
    "ReplacementProduct": "BMEP582020",
    "LastModifiedDate": "N/A"
  },
  "TSXP57303M": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2023/03/14",
    "Reference": "https://www.se.com/us/en/product/TSXP57303M/",
    "ReplacementProduct": "BMEP583020",
    "LastModifiedDate": "N/A"
  },
  "TSXP573634M": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2023/12/31",
    "Reference": "https://www.se.com/us/en/product/TSXP573634M/",
    "ReplacementProduct": "BMEP583020",
    "LastModifiedDate": "N/A"
  },
  "b3624": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2022/10/30",
    "Reference": "https://www.se.com/us/en/product/b3624/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "b3804": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2024/12/31",
    "Reference": "https://www.se.com/us/en/product/b3804/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "b3810": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2024/12/31",
    "Reference": "https://www.se.com/us/en/product/b3810/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "b3814": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2024/12/31",
    "Reference": "https://www.se.com/us/en/product/b3814/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "b3867": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2024/12/31",
    "Reference": "https://www.se.com/us/en/product/b3867/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "b3887": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2024/12/31",
    "Reference": "https://www.se.com/us/en/product/b3887/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "b3920": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Discontinued",
    "DiscontinuedDate": "2024/12/31",
    "Reference": "https://www.se.com/us/en/product/b3920/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  }
};

tenable_ot::eol::compare_and_report(asset:asset, eol_info:eol_info, severity:SECURITY_HOLE);
