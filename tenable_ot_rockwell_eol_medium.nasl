#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(502810);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_name(english:"Rockwell Automation End-of-Life Devices Detection");

  script_set_attribute(attribute:"synopsis", value:
"Detection of Rockwell devices that are still supported but have a discontinued date announced.");
  script_set_attribute(attribute:"description", value:
"The current plugin identifies Rockwell devices that are end-of-life, i.e., still supported but have a discontinued date announced. 
Rockwell Lifecycle Statuses:
 - Active: Most current offering within a product category. 
 - Active Mature: Product is fully supported, but a newer product or family exists. Gain value by migrating. 
 - End of Life: Discontinued date announced - actively execute migrations and last time buys. 
Product generally orderable until the discontinued date. 
 - Discontinued: Product no longer manufactured or procured. Repair/exchange services may be available.");
  # https://www.rockwellautomation.com/en-us/support/product/product-compatibility-migration/product-lifecycle-status.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6be68ee");
  script_set_attribute(attribute:"solution", value:
"Plan and initiate the transition to an actively supported product before the discontinuation date.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ot_api_integration.nasl");
  script_require_keys("Tenable.ot/Rockwell");

  exit(0);
}

#
# EoL checks here
#

include('tenable_ot_eol_funcs.inc');

get_kb_item_or_exit('Tenable.ot/Rockwell');

var asset = tenable_ot::assets::get(vendor:'Rockwell');

var eol_info = {
  "1734-ACNR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2027/03/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1734-ACNR.html",
    "ReplacementProduct": "1734-AENTR",
    "LastModifiedDate": "2025/04/26"
  },
  "1738-AENTR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1738-AENTR.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "1738-IE2CM12": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1738-IE2CM12.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "1738-OE2CM12": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1738-OE2CM12.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "1756-L81E-NSE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L81E-NSE.html",
    "ReplacementProduct": "1756-L81E-NSEXT",
    "LastModifiedDate": "2025/04/15"
  },
  "1756-L81EK": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L81EK.html",
    "ReplacementProduct": "1756-L81EXT",
    "LastModifiedDate": "2025/04/14"
  },
  "1756-L81EP": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L81EP.html",
    "ReplacementProduct": "1756-L81EPXT",
    "LastModifiedDate": "2025/04/15"
  },
  "1756-L82E-NSE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L82E-NSE.html",
    "ReplacementProduct": "1756-L82E-NSEXT",
    "LastModifiedDate": "2025/03/17"
  },
  "1756-L82EK": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L82EK.html",
    "ReplacementProduct": "1756-L82EXT",
    "LastModifiedDate": "2025/03/17"
  },
  "1756-L83E-NSE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L83E-NSE.html",
    "ReplacementProduct": "1756-L83E-NSEXT",
    "LastModifiedDate": "2025/03/17"
  },
  "1756-L83EK": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L83EK.html",
    "ReplacementProduct": "1756-L83EXT",
    "LastModifiedDate": "2025/03/17"
  },
  "1756-L83EP": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L83EP.html",
    "ReplacementProduct": "1756-L83EPXT",
    "LastModifiedDate": "2025/03/17"
  },
  "1756-L84E-NSE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L84E-NSE.html",
    "ReplacementProduct": "1756-L84E-NSEXT",
    "LastModifiedDate": "2025/04/14"
  },
  "1756-L84EK": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L84EK.html",
    "ReplacementProduct": "1756-L84EXT",
    "LastModifiedDate": "2025/04/14"
  },
  "1756-L85E-NSE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L85E-NSE.html",
    "ReplacementProduct": "1756-L85E-NSEXT",
    "LastModifiedDate": "2025/03/17"
  },
  "1756-L85EK": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L85EK.html",
    "ReplacementProduct": "1756-L85EXT",
    "LastModifiedDate": "2025/03/17"
  },
  "1756-L85EP": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-L85EP.html",
    "ReplacementProduct": "1756-L85EPXT",
    "LastModifiedDate": "2025/03/17"
  },
  "1756-PLS": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-PLS.html",
    "ReplacementProduct": "NOT APPLICABLE",
    "LastModifiedDate": "2025/04/14"
  },
  "1756-RIO": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1756-RIO.html",
    "ReplacementProduct": "NOT APPLICABLE",
    "LastModifiedDate": "2025/03/17"
  },
  "1788-CN2DN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1788-CN2DN.html",
    "ReplacementProduct": "1788-EN2DNR",
    "LastModifiedDate": "2025/04/26"
  },
  "1794-ACN15": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/10/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1794-ACN15.html",
    "ReplacementProduct": "1794-AENT, 1794-AENTR",
    "LastModifiedDate": "2025/04/26"
  },
  "1794-ACNR15": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/10/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1794-ACNR15.html",
    "ReplacementProduct": "1794-AENT, 1794-AENTR",
    "LastModifiedDate": "2025/04/26"
  },
  "1794-AENT": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2028/09/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.1794-AENT.html",
    "ReplacementProduct": "1794-AENTR",
    "LastModifiedDate": "2025/04/14"
  },
  "20-IP54DR-600": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20-IP54DR-600.html",
    "ReplacementProduct": "PART(S) FOR DISCONTINUED DRIVE",
    "LastModifiedDate": "2025/04/26"
  },
  "20-IP54DR-800": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20-IP54DR-800.html",
    "ReplacementProduct": "Part(s) for discontinued drive",
    "LastModifiedDate": "2025/04/26"
  },
  "20-IP54RF-600": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20-IP54RF-600.html",
    "ReplacementProduct": "Part(s) for discontinued drive",
    "LastModifiedDate": "2025/04/26"
  },
  "20-IP54RF-800": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20-IP54RF-800.html",
    "ReplacementProduct": "Part(s) for discontinued drive",
    "LastModifiedDate": "2025/04/22"
  },
  "20-IP54RFT-800": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20-IP54RFT-800.html",
    "ReplacementProduct": "Part(s) for discontinued drive",
    "LastModifiedDate": "2025/04/26"
  },
  "2094-BC01-M01-M": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.2094-BC01-M01-M.html",
    "ReplacementProduct": "2198-D020-ERS3 & K5700 Pwr Sup",
    "LastModifiedDate": "2025/04/26"
  },
  "2094-BC02-M02-M": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.2094-BC02-M02-M.html",
    "ReplacementProduct": "2198-D032-ERS3 & K5700 Pwr Sup",
    "LastModifiedDate": "2025/04/26"
  },
  "2094-BC07-M05-M": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.2094-BC07-M05-M.html",
    "ReplacementProduct": "2198-S086-ERS3 & K5700 Pwr Sup",
    "LastModifiedDate": "2025/04/26"
  },
  "2094-BM01-M": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.2094-BM01-M.html",
    "ReplacementProduct": "2198-D012-ERS3",
    "LastModifiedDate": "2025/04/26"
  },
  "2094-BM05-M": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.2094-BM05-M.html",
    "ReplacementProduct": "2198-S086-ERS3",
    "LastModifiedDate": "2025/03/11"
  },
  "2094-BMP5-M": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.2094-BMP5-M.html",
    "ReplacementProduct": "2198-D012-ERS3",
    "LastModifiedDate": "2025/04/26"
  },
  "20DD180A3ENNAEGNE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DD180A3ENNAEGNE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DD248A0EYNAEASE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DD248A0EYNAEASE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DD248A3ENNANBSE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DD248A3ENNANBSE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DD248A3EYNANANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DD248A3EYNANANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DE077A0EYNANCNK": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE077A0EYNANCNK.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DE099A0ENNANANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE099A0ENNANANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DE099A0EYNANASE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE099A0EYNANASE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DE099A0NYNANANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE099A0NYNANANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DE099A3EYNACANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE099A3EYNACANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DE125A0ENNADANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE125A0ENNADANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DE125A0EYNANANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE125A0EYNANANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DE125A0NYNANANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE125A0NYNANANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DE144A0ENNANANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE144A0ENNANANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DE144A0EYNANBEE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE144A0EYNANBEE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DE144A0NNNANASE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE144A0NNNANASE.html",
    "ReplacementProduct": "",
    "LastModifiedDate": ""
  },
  "20DE144A0NYNACASE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE144A0NYNACASE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DE144A0NYNANASE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DE144A0NYNANASE.html",
    "ReplacementProduct": "",
    "LastModifiedDate": ""
  },
  "20DF052A0EYNANANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DF052A0EYNANANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DF119A0EYNANANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DF119A0EYNANANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DH105A3ENNANANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DH105A3ENNANANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DH170A3NNNACGNE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DH170A3NNNACGNE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DH205A0ENNANCNK": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DH205A0ENNANCNK.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DH260A0ENNANANK": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DH260A0ENNANANK.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DH260A3NNNACGNE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DH260A3NNNACGNE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DJ096A3EYNAEASE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DJ096A3EYNAEASE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DJ125A3ENNAEASE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DJ125A3ENNAEASE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DJ180A0ENNACASE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DJ180A0ENNACASE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DJ248A0NNNACASE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DJ248A0NNNACASE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DP105A0ENNACGNE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DP105A0ENNACGNE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DP260A0NNNANANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DP260A0NNNANANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR096A0EYNANGNE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR096A0EYNANGNE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR096A3ENNACASE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR096A3ENNACASE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR125A0NNNACBSE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR125A0NNNACBSE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR125A0NNNANASE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR125A0NNNANASE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR125A0NYNAEBEE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR125A0NYNAEBEE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR156A0EYNANGNE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR156A0EYNANGNE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR156A0NNNAEANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR156A0NNNAEANE.html",
    "ReplacementProduct": "",
    "LastModifiedDate": ""
  },
  "20DR156A0NYNACANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR156A0NYNACANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR156A0NYNACBNE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR156A0NYNACBNE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR156A3ENNACGNE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR156A3ENNACGNE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR180A0NNNANASE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR180A0NNNANASE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR180A3ENNACGNE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR180A3ENNACGNE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR248A0NNNANGNE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR248A0NNNANGNE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DR248A0NYNAEBEE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DR248A0NYNAEBEE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DW098A0ENNANBNK": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DW098A0ENNANBNK.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DW098A3ENNANANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DW098A3ENNANANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20DW142A0NNNANANE": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20DW142A0NNNANANE.html",
    "ReplacementProduct": "PowerFlex 750 family",
    "LastModifiedDate": ""
  },
  "20P21AD010RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD010RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD014RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD014RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD019RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD019RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P21AD027RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD027RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AD035RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD035RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AD045RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD045RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AD052RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD052RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD073RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD073RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD086RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD086RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AD100RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD100RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD129RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD129RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AD167RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD167RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AD1K1RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD1K1RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P21AD1K3RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD1K3RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD1K4RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD1K4RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AD207RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD207RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P21AD250RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD250RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD330RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD330RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD412RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD412RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD495RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD495RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P21AD4P1RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD4P1RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD667RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD667RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD6P0RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD6P0RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD830RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD830RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AD996RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AD996RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AE067RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AE067RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AE101RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AE101RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AE135RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AE135RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AE1K0RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AE1K0RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AE1K2RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AE1K2RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AE1K3RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AE1K3RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AE1K6RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AE1K6RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AE270RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AE270RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AE405RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AE405RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AE540RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AE540RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AE675RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AE675RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AE810RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AE810RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AF1K0RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AF1K0RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AF1K1RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AF1K1RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AF1K2RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AF1K2RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P21AF1K4RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AF1K4RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/02/19"
  },
  "20P21AF1K5RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AF1K5RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AF452RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AF452RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AF565RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AF565RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P21AF678RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AF678RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/15"
  },
  "20P21AF791RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AF791RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/02/18"
  },
  "20P21AF904RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P21AF904RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AB012RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB012RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AB020RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB020RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AB029RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB029RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AB038RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB038RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AB055RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB055RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AB073RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB073RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AB093RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB093RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AB110RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB110RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AB146RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB146RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AB180RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB180RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AB1K0RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB1K0RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AB218RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB218RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AB265RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB265RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AB360RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB360RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AB434RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB434RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AB521RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB521RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AB700RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB700RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P41AB7P0RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB7P0RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AB875RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB875RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AB9P0RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AB9P0RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AD010RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD010RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AD014RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD014RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AD019RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD019RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD027RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD027RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD035RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD035RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD045RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD045RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AD052RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD052RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD073RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD073RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD086RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD086RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD100RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD100RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD129RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD129RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD167RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD167RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD1K1RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD1K1RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD1K3RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD1K3RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AD1K4RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD1K4RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AD207RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD207RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD250RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD250RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AD330RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD330RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD412RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD412RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD495RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD495RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD4P1RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD4P1RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD667RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD667RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/22"
  },
  "20P41AD6P0RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD6P0RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AD830RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD830RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AD996RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AD996RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P41AE067RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AE067RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "20P41AE101RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AE101RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/02/22"
  },
  "20P41AE135RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AE135RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AE1K0RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AE1K0RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AE1K2RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AE1K2RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AE1K3RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AE1K3RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AE1K6RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AE1K6RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P41AE270RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AE270RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AE405RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AE405RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AE540RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AE540RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P41AE675RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AE675RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AE810RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AE810RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P41AF1K0RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AF1K0RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AF1K1RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AF1K1RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/02/18"
  },
  "20P41AF1K2RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AF1K2RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P41AF1K4RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AF1K4RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P41AF1K5RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AF1K5RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P41AF452RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AF452RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AF565RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AF565RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/03/17"
  },
  "20P41AF678RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AF678RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P41AF791RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AF791RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20P41AF904RA0NNN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20P41AF904RA0NNN.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/14"
  },
  "20SD1K0NEM": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/10/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20SD1K0NEM.html",
    "ReplacementProduct": "PowerFlex 755TM NRS Drives",
    "LastModifiedDate": "2025/04/26"
  },
  "20SD1K0NEN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/10/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20SD1K0NEN.html",
    "ReplacementProduct": "PowerFlex 755TM NRS Drives",
    "LastModifiedDate": "2025/04/26"
  },
  "20SD600NEN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/10/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20SD600NEN.html",
    "ReplacementProduct": "PowerFlex 755TM NRS Drives",
    "LastModifiedDate": "2025/04/15"
  },
  "20SF1K0NEM": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/10/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20SF1K0NEM.html",
    "ReplacementProduct": "PowerFlex 755TM NRS Drives",
    "LastModifiedDate": "2025/04/26"
  },
  "20SF1K0NEN": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/10/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20SF1K0NEN.html",
    "ReplacementProduct": "PowerFlex 755TM NRS Drives",
    "LastModifiedDate": "2025/04/26"
  },
  "20SF1K0NES": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/10/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.20SF1K0NES.html",
    "ReplacementProduct": "PowerFlex 755TM NRS Drives",
    "LastModifiedDate": "2025/04/15"
  },
  "22P-D010N103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D010N103.html",
    "ReplacementProduct": "22C-D010N103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D012N103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D012N103.html",
    "ReplacementProduct": "22C-D012N103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D017N103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D017N103.html",
    "ReplacementProduct": "22C-D017N103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D022N103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D022N103.html",
    "ReplacementProduct": "22C-D022C103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D030N103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D030N103.html",
    "ReplacementProduct": "22C-D030N103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D038A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D038A103.html",
    "ReplacementProduct": "22C-D038A103",
    "LastModifiedDate": "2025/03/17"
  },
  "22P-D045A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D045A103.html",
    "ReplacementProduct": "22C-D045A103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D060A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D060A103.html",
    "ReplacementProduct": "22C-D060A103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D072A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D072A103.html",
    "ReplacementProduct": "22C-D072A103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D088A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D088A103.html",
    "ReplacementProduct": "22C-D088A103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D105A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D105A103.html",
    "ReplacementProduct": "22C-D105A103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D142A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D142A103.html",
    "ReplacementProduct": "22C-D142A103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D170A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D170A103.html",
    "ReplacementProduct": "22C-D170A103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D208A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D208A103.html",
    "ReplacementProduct": "22C-D208A103",
    "LastModifiedDate": "2025/03/17"
  },
  "22P-D260A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D260A103.html",
    "ReplacementProduct": "22C-D260A103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D310A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D310A103.html",
    "ReplacementProduct": "22C-D310A103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D370A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D370A103.html",
    "ReplacementProduct": "22C-D370A103",
    "LastModifiedDate": "2025/04/26"
  },
  "22P-D460A103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D460A103.html",
    "ReplacementProduct": "22C-D460A103",
    "LastModifiedDate": "2025/03/17"
  },
  "22P-D6P0N103": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/06/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.22P-D6P0N103.html",
    "ReplacementProduct": "22C-D6P0N103",
    "LastModifiedDate": "2025/04/26"
  },
  "23PFCB017": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PFCB017.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "23PFCB060": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PFCB060.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "23PFCB120": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PFCB120.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "23PFCB245": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PFCB245.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "23PFCB365": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PFCB365.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "23PFCB570": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PFCB570.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/02/18"
  },
  "23PFCD017": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PFCD017.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "23PFCD060": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PFCD060.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "23PFCD120": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PFCD120.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "23PFCD245": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PFCD245.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "23PFCD365": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PFCD365.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "23PFCD570": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PFCD570.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/26"
  },
  "23PMD4": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PMD4.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/04/15"
  },
  "23PMD7": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PMD7.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/02/18"
  },
  "23PMF4": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PMF4.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/02/18"
  },
  "23PMF7": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.23PMF7.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12B-NB-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12B-NB-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12B-NB-R-3-SM": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12B-NB-R-3-SM.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12B-NC-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12B-NC-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12B-NC-R-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12B-NC-R-3.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12D-NA-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12D-NA-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "280D-F12D-NA-R-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12D-NA-R-3.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12D-NB-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12D-NB-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12D-NB-R-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12D-NB-R-3.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "280D-F12D-NC-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12D-NC-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12D-NC-R-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12D-NC-R-3.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12S-NB-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12S-NB-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/17"
  },
  "280D-F12S-NB-R-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12S-NB-R-3.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12S-NC-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12S-NC-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/17"
  },
  "280D-F12S-NC-R-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12S-NC-R-3.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12Z-NA-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12Z-NA-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12Z-NB-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12Z-NB-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "280D-F12Z-NB-R-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12Z-NB-R-3.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "280D-F12Z-NB-R-3-SM": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12Z-NB-R-3-SM.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12Z-NB-R-SM": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12Z-NB-R-SM.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12Z-NC-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12Z-NC-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "280D-F12Z-NC-R-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12Z-NC-R-3.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F12Z-NC-R-3-SM": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F12Z-NC-R-3-SM.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F23D-ND-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F23D-ND-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F23D-ND-R-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F23D-ND-R-3.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280D-F23Z-ND-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F23Z-ND-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "280D-F23Z-ND-R-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280D-F23Z-ND-R-3.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "280E-F12Z-10A-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10A-CR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280E-F12Z-10A-CR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10A-CR-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "280E-F12Z-10A-CRW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10A-CRW.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280E-F12Z-10A-RR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10A-RR-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "280E-F12Z-10A-RRW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10A-RRW.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "280E-F12Z-10A-RRW-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10A-RRW-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "280E-F12Z-10B-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10B-CR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280E-F12Z-10B-CR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10B-CR-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "280E-F12Z-10B-DR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10B-DR-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "280E-F12Z-10B-DRW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10B-DRW.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "280E-F12Z-10B-DRW-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10B-DRW-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/10"
  },
  "280E-F12Z-10B-RR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10B-RR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "280E-F12Z-10B-RRW-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10B-RRW-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280E-F12Z-10C-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10C-CR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280E-F12Z-10C-CR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10C-CR-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280E-F12Z-10C-DR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10C-DR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/10"
  },
  "280E-F12Z-10C-DRW-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10C-DRW-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/10"
  },
  "280E-F12Z-10C-GRW-3-P1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10C-GRW-3-P1.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "280E-F12Z-10C-RR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10C-RR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280E-F12Z-10C-RRW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10C-RRW.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280E-F12Z-10C-RRW-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F12Z-10C-RRW-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "280E-F23Z-25D-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F23Z-25D-CR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280E-F23Z-25D-CRW-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F23Z-25D-CRW-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280E-F23Z-25D-DR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F23Z-25D-DR-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "280E-F23Z-25D-DRW-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F23Z-25D-DRW-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "280E-F23Z-25D-RR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F23Z-25D-RR-3.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280E-F23Z-25D-RRW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280E-F23Z-25D-RRW.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/10"
  },
  "280G-F12D-10B-RRG-CBG": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280G-F12D-10B-RRG-CBG.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280G-F12D-10C-RRG-CBG": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280G-F12D-10C-RRG-CBG.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280G-F12S-10B-RRG-CBG": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280G-F12S-10B-RRG-CBG.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "280G-F12S-10C-RRG-CBG": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280G-F12S-10C-RRG-CBG.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "280G-F23S-25D-RRG-CBG": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.280G-F23S-25D-RRG-CBG.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281D-F12B-NA-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12B-NA-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F12B-NB-R-3FR-SM": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12B-NB-R-3FR-SM.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F12B-NC-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12B-NC-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F12D-NB-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12D-NB-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F12D-NB-R-3FR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12D-NB-R-3FR.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F12D-NC-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12D-NC-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F12D-NC-R-3FR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12D-NC-R-3FR.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F12S-NC-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12S-NC-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "281D-F12Z-NA-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12Z-NA-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "281D-F12Z-NB-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12Z-NB-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F12Z-NB-R-3FR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12Z-NB-R-3FR.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F12Z-NB-R-3FR-SM": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12Z-NB-R-3FR-SM.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F12Z-NC-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12Z-NC-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F12Z-NC-R-3FR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12Z-NC-R-3FR.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/19"
  },
  "281D-F12Z-NC-R-SM": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F12Z-NC-R-SM.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F23B-ND-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F23B-ND-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F23B-ND-R-3FR-SM": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F23B-ND-R-3FR-SM.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F23D-ND-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F23D-ND-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281D-F23Z-ND-R": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281D-F23Z-ND-R.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "281E-F12Z-10A-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10A-CR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "281E-F12Z-10A-CR-3FR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10A-CR-3FR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "281E-F12Z-10A-DRW-3FR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10A-DRW-3FR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281E-F12Z-10A-RR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10A-RR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "281E-F12Z-10A-RR-3FR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10A-RR-3FR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "281E-F12Z-10B-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10B-CR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281E-F12Z-10B-CR-3FR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10B-CR-3FR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281E-F12Z-10B-DR-3FR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10B-DR-3FR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281E-F12Z-10B-DRW-3FR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10B-DRW-3FR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "281E-F12Z-10B-RRW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10B-RRW.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281E-F12Z-10C-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10C-CR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281E-F12Z-10C-CRW-3FR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10C-CRW-3FR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281E-F12Z-10C-DRW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10C-DRW.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "281E-F12Z-10C-DRW-3FR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10C-DRW-3FR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281E-F12Z-10C-RR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F12Z-10C-RR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281E-F23Z-25D-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F23Z-25D-CR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281E-F23Z-25D-RR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F23Z-25D-RR.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281E-F23Z-25D-RRW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281E-F23Z-25D-RRW.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281G-F12D-10B-RRG-CBG": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281G-F12D-10B-RRG-CBG.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/14"
  },
  "281G-F12D-10C-RRG-CBG": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281G-F12D-10C-RRG-CBG.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281G-F12S-10B-RRG-CBG": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281G-F12S-10B-RRG-CBG.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281G-F12S-10C-RRG-CBG": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281G-F12S-10C-RRG-CBG.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281G-F23D-25D-RRG-CBG": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281G-F23D-25D-RRG-CBG.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "281G-F23S-25D-RRG-CBG": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.281G-F23S-25D-RRG-CBG.html",
    "ReplacementProduct": "ArmorStart LT/Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284D-FVD2P3B-N-R-DB-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284D-FVD2P3B-N-R-DB-SB.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "284D-FVD2P3Z-N-R-3-DB-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284D-FVD2P3Z-N-R-3-DB-OC.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/03/30"
  },
  "284D-FVD2P3Z-N-R-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284D-FVD2P3Z-N-R-OC.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/03/30"
  },
  "284D-FVD4P0B-N-R-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284D-FVD4P0B-N-R-EMI.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/17"
  },
  "284D-FVD4P0D-N-R-3-CB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284D-FVD4P0D-N-R-3-CB.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/03/30"
  },
  "284D-FVD4P0D-N-R-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284D-FVD4P0D-N-R-EMI.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/17"
  },
  "284D-FVD6P0B-N-R-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284D-FVD6P0B-N-R-EMI.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/15"
  },
  "284D-FVD6P0Z-N-R-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284D-FVD6P0Z-N-R-3.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/18"
  },
  "284D-FVD6P0Z-N-R-3-SM": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284D-FVD6P0Z-N-R-3-SM.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/03/30"
  },
  "284D-FVD7P6B-N-R-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284D-FVD7P6B-N-R-EMI.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/04/14"
  },
  "284D-FVD7P6Z-N-R-3-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284D-FVD7P6Z-N-R-3-SB-EMI.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/02/21"
  },
  "284D-FVD7P6Z-N-R-3-SB-SM": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2026/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284D-FVD7P6Z-N-R-3-SB-SM.html",
    "ReplacementProduct": "NA - Spare part",
    "LastModifiedDate": "2025/03/30"
  },
  "284E-FVD1P4Z-10-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-CR.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD1P4Z-10-CR-3-DB-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-CR-3-DB-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/14"
  },
  "284E-FVD1P4Z-10-CR-DB-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-CR-DB-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD1P4Z-10-CR-DB1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-CR-DB1.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD1P4Z-10-CRW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-CRW.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD1P4Z-10-CRW-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-CRW-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD1P4Z-10-RR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-RR-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD1P4Z-10-RR-3-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-RR-3-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD1P4Z-10-RR-DB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-RR-DB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD1P4Z-10-RRN-3-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-RRN-3-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD1P4Z-10-RRN-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-RRN-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD1P4Z-10-RRW-DB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-RRW-DB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/30"
  },
  "284E-FVD1P4Z-10-RRW-DBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD1P4Z-10-RRW-DBW.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD2P3Z-10-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CR.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-CR-3-DB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CR-3-DB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-CR-3-DB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CR-3-DB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD2P3Z-10-CR-3-DB-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CR-3-DB-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-CR-3-DB-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CR-3-DB-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-CR-3-DB1-SBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CR-3-DB1-SBW.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD2P3Z-10-CR-3-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CR-3-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-CR-3-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CR-3-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD2P3Z-10-CR-DB-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CR-DB-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-CR-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CR-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/14"
  },
  "284E-FVD2P3Z-10-CR-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CR-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD2P3Z-10-CRW-3-DB-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CRW-3-DB-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD2P3Z-10-CRW-3-DB1-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CRW-3-DB1-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD2P3Z-10-CRW-3-DB1-SB-EMI-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CRW-3-DB1-SB-EMI-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-CRW-3-DBW-SBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CRW-3-DBW-SBW.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD2P3Z-10-CRW-3-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CRW-3-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-CRW-DB-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-CRW-DB-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD2P3Z-10-DR-3-DB1-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-DR-3-DB1-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/30"
  },
  "284E-FVD2P3Z-10-DR-3-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-DR-3-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-DR-DB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-DR-DB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD2P3Z-10-DR-DB1-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-DR-DB1-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD2P3Z-10-DRW-3-DBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-DRW-3-DBW.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-RR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-RR.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-RR-3-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-RR-3-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-RR-3-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-RR-3-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-RR-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-RR-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-RR-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-RR-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-RRN-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-RRN-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD2P3Z-10-RRW-3-DB1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-RRW-3-DB1.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD2P3Z-10-RRW-3-DB1-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-RRW-3-DB1-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD2P3Z-10-RRW-DB-SBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-RRW-DB-SBW.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD2P3Z-10-RRW-DB1-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-RRW-DB1-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/30"
  },
  "284E-FVD2P3Z-10-RRW-SBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD2P3Z-10-RRW-SBW.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "284E-FVD4P0Z-10-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CR.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/14"
  },
  "284E-FVD4P0Z-10-CR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CR-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD4P0Z-10-CR-3-DB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CR-3-DB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD4P0Z-10-CR-3-DB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CR-3-DB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD4P0Z-10-CR-3-DB-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CR-3-DB-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD4P0Z-10-CR-3-DB-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CR-3-DB-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD4P0Z-10-CR-3-DB-SB-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CR-3-DB-SB-OC.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/30"
  },
  "284E-FVD4P0Z-10-CR-3-DB1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CR-3-DB1.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD4P0Z-10-CR-3-EMI-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CR-3-EMI-OC.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD4P0Z-10-CR-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CR-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD4P0Z-10-CR-SBW-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CR-SBW-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/30"
  },
  "284E-FVD4P0Z-10-CRN-3-DB1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CRN-3-DB1.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD4P0Z-10-CRN-3-DB1-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CRN-3-DB1-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/17"
  },
  "284E-FVD4P0Z-10-CRN-DB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CRN-DB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD4P0Z-10-CRN-DB1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CRN-DB1.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD4P0Z-10-CRN-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CRN-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/17"
  },
  "284E-FVD4P0Z-10-CRW-3-DB-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CRW-3-DB-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD4P0Z-10-CRW-3-DB-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CRW-3-DB-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD4P0Z-10-CRW-3-DB1-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CRW-3-DB1-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD4P0Z-10-CRW-3-DB1-SB-EMI-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CRW-3-DB1-SB-EMI-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD4P0Z-10-CRW-3-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CRW-3-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/17"
  },
  "284E-FVD4P0Z-10-CRW-3-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CRW-3-SB.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD4P0Z-10-CRW-DB-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-CRW-DB-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD4P0Z-10-DR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-DR-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD4P0Z-10-DR-3-DB1-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-DR-3-DB1-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/30"
  },
  "284E-FVD4P0Z-10-DR-DB1-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-DR-DB1-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD4P0Z-10-DRN-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-DRN-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD4P0Z-10-DRN-3-DB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-DRN-3-DB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD4P0Z-10-DRN-3-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-DRN-3-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/17"
  },
  "284E-FVD4P0Z-10-DRW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-DRW.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD4P0Z-10-DRW-DB1-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-DRW-DB1-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD4P0Z-10-RR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RR-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD4P0Z-10-RR-3-SB-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RR-3-SB-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "284E-FVD4P0Z-10-RR-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RR-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD4P0Z-10-RR-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RR-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD4P0Z-10-RRN-3-DB-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RRN-3-DB-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD4P0Z-10-RRN-DB-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RRN-DB-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD4P0Z-10-RRN-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RRN-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD4P0Z-10-RRW-3-DB1-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RRW-3-DB1-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD4P0Z-10-RRW-3-DB1-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RRW-3-DB1-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "284E-FVD4P0Z-10-RRW-3-DB1-SBW-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RRW-3-DB1-SBW-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/17"
  },
  "284E-FVD4P0Z-10-RRW-3-SB-EMI-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RRW-3-SB-EMI-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD4P0Z-10-RRW-DB1-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RRW-DB1-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD4P0Z-10-RRW-SBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD4P0Z-10-RRW-SBW.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD6P0Z-25-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-CR.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD6P0Z-25-CR-3-DB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-CR-3-DB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD6P0Z-25-CR-3-DB-SB-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-CR-3-DB-SB-OC.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/30"
  },
  "284E-FVD6P0Z-25-CR-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-CR-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD6P0Z-25-CRN-3-DB1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-CRN-3-DB1.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD6P0Z-25-CRN-DB1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-CRN-DB1.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD6P0Z-25-CRW-3-DB-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-CRW-3-DB-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD6P0Z-25-DR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-DR-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD6P0Z-25-DR-DB1-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-DR-DB1-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD6P0Z-25-DR-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-DR-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD6P0Z-25-DRN-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-DRN-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD6P0Z-25-DRW-3-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-DRW-3-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/17"
  },
  "284E-FVD6P0Z-25-RR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-RR.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD6P0Z-25-RR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-RR-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD6P0Z-25-RR-3-DB-SB-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-RR-3-DB-SB-OC.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/30"
  },
  "284E-FVD6P0Z-25-RR-3-SB-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-RR-3-SB-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD6P0Z-25-RRN-3-DB-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-RRN-3-DB-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD6P0Z-25-RRN-DB-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-RRN-DB-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD6P0Z-25-RRN-DB1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-RRN-DB1.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD6P0Z-25-RRW-3-DB1-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-RRW-3-DB1-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD6P0Z-25-RRW-3-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-RRW-3-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD6P0Z-25-RRW-3-SB-EMI-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-RRW-3-SB-EMI-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD6P0Z-25-RRW-DB-SBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD6P0Z-25-RRW-DB-SBW.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-CR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CR.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-CR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CR-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-CR-3-DB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CR-3-DB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-CR-3-DB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CR-3-DB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD7P6Z-25-CR-3-DB-SB-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CR-3-DB-SB-OC.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/30"
  },
  "284E-FVD7P6Z-25-CR-3-DB1-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CR-3-DB1-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-CR-DB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CR-DB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD7P6Z-25-CR-DB-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CR-DB-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-CR-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CR-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-CRN-3-DB1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CRN-3-DB1.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-CRN-DB1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CRN-DB1.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD7P6Z-25-CRW-3-DB-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CRW-3-DB-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/19"
  },
  "284E-FVD7P6Z-25-CRW-DB1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-CRW-DB1.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-DRN-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-DRN-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-DRN-3-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-DRN-3-OC.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-DRW-DB-SBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-DRW-DB-SBW.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-DRW-DB1": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-DRW-DB1.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-RR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RR.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-RR-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RR-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-RR-3-DB1-SB-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RR-3-DB1-SB-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-RR-3-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RR-3-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/14"
  },
  "284E-FVD7P6Z-25-RR-3-SB-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RR-3-SB-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/10"
  },
  "284E-FVD7P6Z-25-RR-3-SBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RR-3-SBW.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-RR-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RR-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-RR-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RR-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-RR-SB-OC": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RR-SB-OC.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-RRN-3-DB-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RRN-3-DB-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-RRN-3-DB-SBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RRN-3-DB-SBW.html",
    "ReplacementProduct": "Armor PowerFlex 35E",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-RRN-DB-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RRN-DB-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-RRN-DB1-SBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RRN-DB1-SBW.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-RRW-3": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RRW-3.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284E-FVD7P6Z-25-RRW-3-SB": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RRW-3-SB.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-RRW-DB-SBW": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RRW-DB-SBW.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284E-FVD7P6Z-25-RRW-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/12/01",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284E-FVD7P6Z-25-RRW-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/15"
  },
  "284G-FVD1P4D-10-RRG-CBG-DB1-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284G-FVD1P4D-10-RRG-CBG-DB1-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284G-FVD1P4S-10-RRG-CBG-DB1-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284G-FVD1P4S-10-RRG-CBG-DB1-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284G-FVD2P3D-10-RRG-CBG-DB1-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284G-FVD2P3D-10-RRG-CBG-DB1-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284G-FVD2P3S-10-RRG-CBG-DB1-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284G-FVD2P3S-10-RRG-CBG-DB1-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284G-FVD4P0D-10-RRG-CBG-DB1-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284G-FVD4P0D-10-RRG-CBG-DB1-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284G-FVD4P0S-10-RRG-CBG-DB1-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284G-FVD4P0S-10-RRG-CBG-DB1-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "284G-FVD6P0D-25-RRG-CBG-DB1-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284G-FVD6P0D-25-RRG-CBG-DB1-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/03/11"
  },
  "284G-FVD6P0S-25-RRG-CBG-DB1-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284G-FVD6P0S-25-RRG-CBG-DB1-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284G-FVD7P6D-25-RRG-CBG-DB1-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284G-FVD7P6D-25-RRG-CBG-DB1-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "284G-FVD7P6S-25-RRG-CBG-DB1-EMI": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.284G-FVD7P6S-25-RRG-CBG-DB1-EMI.html",
    "ReplacementProduct": "Armor PowerFlex",
    "LastModifiedDate": "2025/04/26"
  },
  "800HC-JR2KE7HR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/03/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.800HC-JR2KE7HR.html",
    "ReplacementProduct": "SeeMigrationDoc",
    "LastModifiedDate": "2025/04/26"
  },
  "800T-J17KT7BR": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2025/04/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.800T-J17KT7BR.html",
    "ReplacementProduct": "800T-J17KT7 + (2) 800T-XAR",
    "LastModifiedDate": "2025/04/26"
  },
  "LECTRA-PF7015-IP66": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2023/11/30",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.LECTRA-PF7015-IP66.html",
    "ReplacementProduct": "",
    "LastModifiedDate": ""
  },
  "TEST-EOL": {
    "Vendor": "Rockwell",
    "LifecycleStatus": "End of Life",
    "DiscontinuedDate": "2050/12/31",
    "Reference": "https://www.rockwellautomation.com/en-us/products/details.TEST-EOL.html",
    "ReplacementProduct": "",
    "LastModifiedDate": "2014/12/31"
  }
};

tenable_ot::eol::compare_and_report(asset:asset, eol_info:eol_info, severity:SECURITY_WARNING);
