#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(503146);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/16");

  script_name(english:"Schneider Electric Active Devices Detection");

  script_set_attribute(attribute:"synopsis", value:
"Detection of active Schneider devices.");
  script_set_attribute(attribute:"description", value:
"The current plugin identifies Schneider devices that are still under active support. 
Schneider Lifecycle Statuses:
 - Active: Most current offering within a product category. 
 - End of Life: Discontinued date announced - actively execute migrations and last time buys. 
Product generally orderable until the discontinued date. 
 - Discontinued: Product no longer manufactured or procured. Repair/exchange services may be available.");
  script_set_attribute(attribute:"see_also", value:"https://www.se.com/in/en/product-substitution/");
  script_set_attribute(attribute:"solution", value:"");

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
  "171CBU98091": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/171CBU98091/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATS480C21Y": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATS480C21Y/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV212HU22N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV212HU22N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV212HU40N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV212HU40N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV212HU55N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV212HU55N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV212HU75N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV212HU75N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV630D15N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV630D15N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV630D22N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV630D22N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV630D75N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV630D75N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV930U07N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV930U07N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV930U15N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV930U15N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV930U55N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV930U55N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV950D11N4E": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV950D11N4E/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV950D22N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV950D22N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV950D45N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV950D45N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV950U22N4E": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV950U22N4E/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV950U30N4E": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV950U30N4E/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV950U55N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV950U55N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "ATV950U75N4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/ATV950U75N4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMEH582040": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMEH582040/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMEH584040": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMEH584040/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMENOC0301": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMENOC0301/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMEP581020": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMEP581020/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMEP582020": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMEP582020/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMEP582040": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMEP582040/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMEP583020": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMEP583020/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMEP583040": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMEP583040/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMEP584020": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMEP584020/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMEP586040": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMEP586040/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXAMI0410": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXAMI0410/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXAMI0800": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXAMI0800/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXAMI0810": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXAMI0810/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXAMM0600": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXAMM0600/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXAMO0210": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXAMO0210/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXAMO0410": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXAMO0410/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXAMO0802": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXAMO0802/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXART0414": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXART0414/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXART0814": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXART0814/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXDAI1604": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXDAI1604/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXDAO1605": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXDAO1605/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXDDI1602": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXDDI1602/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXDDI3202K": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXDDI3202K/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXDDI6402K": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXDDI6402K/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXDDM16022": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXDDM16022/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXDDM16025": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXDDM16025/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXDDO1602": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXDDO1602/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXDDO3202K": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXDDO3202K/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXDRA1605": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXDRA1605/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXNOC0401": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXNOC0401/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXNOE0100": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXNOE0100/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXNOE0110": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXNOE0110/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXP341000": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXP341000/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXP342000": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXP342000/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXP342020": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXP342020/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "BMXP3420302": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/BMXP3420302/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "EGX100": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/EGX100/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "EGX100SD": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/EGX100SD/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "HMIGTO2310": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/HMIGTO2310/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "HMIGTO4310": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/HMIGTO4310/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "LTMR08EBD": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/LTMR08EBD/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "LTMR08EFM": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/LTMR08EFM/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "LTMR100EFM": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/LTMR100EFM/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "STBACO0120": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/STBACO0120/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "SXWASPXXX10001": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/SXWASPXXX10001/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "SXWASPXXX10002": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/SXWASPXXX10002/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TEST-ACTIVE": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TEST-ACTIVE/",
    "ReplacementProduct": "",
    "LastModifiedDate": "2015/03/18"
  },
  "TM172PDG42R": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM172PDG42R/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM221CE16R": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM221CE16R/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM221CE16T": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM221CE16T/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM221CE24R": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM221CE24R/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM221CE40R": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM221CE40R/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM241CE24R": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM241CE24R/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM241CE40R": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM241CE40R/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM241CEC24R": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM241CEC24R/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM251MESC": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM251MESC/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM251MESE": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM251MESE/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM262M25MESS8T": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM262M25MESS8T/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM262M35MESS8T": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM262M35MESS8T/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM3AI4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM3AI4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM3AQ4": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM3AQ4/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM3DI16K": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM3DI16K/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM3DQ16TK": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM3DQ16TK/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM5SAI4H": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM5SAI4H/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "TM5SPS3": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/TM5SPS3/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  },
  "XPSMCMCP0802": {
    "Vendor": "Schneider",
    "LifecycleStatus": "Active",
    "DiscontinuedDate": "",
    "Reference": "https://www.se.com/us/en/product/XPSMCMCP0802/",
    "ReplacementProduct": "",
    "LastModifiedDate": "N/A"
  }
};

tenable_ot::eol::compare_and_report(asset:asset, eol_info:eol_info, severity:SECURITY_NOTE);
