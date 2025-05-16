#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');

if (description)
{
  script_id(503147);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/16");

  script_name(english:"Schneider Electric End-of-Life Devices Detection");

  script_set_attribute(attribute:"synopsis", value:
"Detection of Schneider devices that are still supported but have a discontinued date announced.");
  script_set_attribute(attribute:"description", value:
"The current plugin identifies Schneider devices that are end-of-life, i.e., still supported but have a discontinued date announced. 
Schneider Lifecycle Statuses:
 - Active: Most current offering within a product category. 
 - End of Life: Discontinued date announced - actively execute migrations and last time buys. 
Product generally orderable until the discontinued date. 
 - Discontinued: Product no longer manufactured or procured. Repair/exchange services may be available.");
  script_set_attribute(attribute:"see_also", value:"https://www.se.com/in/en/product-substitution/");
  script_set_attribute(attribute:"solution", value:
"Plan and initiate the transition to an actively supported product before the discontinuation date.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

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
  "140CPU31110": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.se.com/us/en/product/140CPU31110/",
    "ReplacementProduct": "BMEP581020",
    "LastModifiedDate": "N/A"
  },
  "140CPU43412A": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.se.com/us/en/product/140CPU43412A/",
    "ReplacementProduct": "BMEP582040",
    "LastModifiedDate": "N/A"
  },
  "140CPU65150": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.se.com/us/en/product/140CPU65150/",
    "ReplacementProduct": "BMEP582040",
    "LastModifiedDate": "N/A"
  },
  "140CPU65160": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.se.com/us/en/product/140CPU65160/",
    "ReplacementProduct": "BMEP582040",
    "LastModifiedDate": "N/A"
  },
  "140CPU65260": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.se.com/us/en/product/140CPU65260/",
    "ReplacementProduct": "BMEP584040",
    "LastModifiedDate": "N/A"
  },
  "140CPU67160": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.se.com/us/en/product/140CPU67160/",
    "ReplacementProduct": "BMEH584040",
    "LastModifiedDate": "N/A"
  },
  "140CPU67261": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.se.com/us/en/product/140CPU67261/",
    "ReplacementProduct": "BMEH584040",
    "LastModifiedDate": "N/A"
  },
  "140NOE77101": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.se.com/us/en/product/140NOE77101/",
    "ReplacementProduct": "BMENOC0301",
    "LastModifiedDate": "N/A"
  },
  "ATV61WD22N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.se.com/us/en/product/ATV61WD22N4/",
    "ReplacementProduct": "ATV650D22N4",
    "LastModifiedDate": "N/A"
  },
  "ATV61WD45N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.se.com/us/en/product/ATV61WD45N4/",
    "ReplacementProduct": "ATV650D45N4",
    "LastModifiedDate": "N/A"
  },
  "BMXNOC0402": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.se.com/us/en/product/BMXNOC0402/",
    "ReplacementProduct": "BMENOC0301",
    "LastModifiedDate": "N/A"
  },
  "TEST-EOL": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2050/12/31",
    "Reference": "https://www.se.com/us/en/product/TEST-EOL/",
    "ReplacementProduct": "",
    "LastModifiedDate": "2015/03/18"
  },
  "TSX3721101": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2027/12/31",
    "Reference": "https://www.se.com/us/en/product/TSX3721101/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TSX3722001": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2027/12/31",
    "Reference": "https://www.se.com/us/en/product/TSX3722001/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TSXP57103M": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.se.com/us/en/product/TSXP57103M/",
    "ReplacementProduct": "BMXP342020",
    "LastModifiedDate": "N/A"
  },
  "TSXP57203M": {
    "Vendor": "Schneider",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.se.com/us/en/product/TSXP57203M/",
    "ReplacementProduct": "BMEP582020",
    "LastModifiedDate": "N/A"
  }
};

tenable_ot::eol::compare_and_report(asset:asset, eol_info:eol_info, severity:SECURITY_WARNING);
