#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, inc.
##

include('compat.inc');

if (description)
{
  script_id(181598);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id(
    "CVE-2017-13077",
    "CVE-2017-13078",
    "CVE-2017-13079",
    "CVE-2017-13080",
    "CVE-2017-13081"
  );
  script_xref(name:"HP", value:"HPSBPI03574");

  script_name(english:"HP LaserJet Printers Multiple Vulnerabilities (HPSBPI03574)");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote HP LaserJet printer is potentially affected by the following
vulnerabilities:
  - Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Pairwise Transient Key (PTK) 
    Temporal Key (TK) during the four-way handshake, allowing an attacker within radio range to replay, 
    decrypt, or spoof frames. (CVE-2017-13077)

  - Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Group Temporal Key (GTK) during the 
    four-way handshake, allowing an attacker within radio range to replay frames from access points to 
    clients. (CVE-2017-13078)

  - Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11w allows reinstallation of the Integrity 
    Group Temporal Key (IGTK) during the group key handshake, allowing an attacker within radio range to 
    spoof frames from access points to clients. (CVE-2017-13081)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.hp.com/us-en/document/c05876244");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the HP LaserJet firmware referenced in the
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13077");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_laserjet_detect.nasl");
  script_require_keys("www/hp_laserjet");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');

var port = get_http_port(default:80, dont_break:TRUE, embedded:TRUE);
                                                                               # Examples:
var product   = get_kb_item_or_exit('www/hp_laserjet/'+port+'/pname');         # HP LaserJet Enterprise M506
var model     = get_kb_item_or_exit('www/hp_laserjet/'+port+'/modelnumber');   # F2A68A
var firmware  = get_kb_item_or_exit('www/hp_laserjet/'+port+'/fw_rev');        # 2308937_578489
var url       = get_kb_item_or_exit('www/hp_laserjet/'+port+'/url');
var fs_full   = get_kb_item('www/hp_laserjet/'+port+'/fw_bundle_ver');         # 3.9.8 or 4.1.2

var full_product = "HP LaserJet " + product + " Model " + model;

var parts = split(firmware, sep:"_", keep:FALSE);
var firmware_major = parts[0]; 
# Some models have different fixed fw versions depending on the futuresmart version
var fs_ver = split(fs_full, sep:".", keep:FALSE);
var fs = fs_ver[0];

var serial = get_kb_item('www/hp_laserjet/'+port+'/serial');
if (empty_or_null(serial)) serial = "unknown";

var vuln = FALSE;
var fix;

if (isnull(fs_full)) audit(AUDIT_UNKNOWN_APP_VER, "FutureSmart");

if (fs == 3)
{ 
  if (model == "F2A68A" ||
      model == "F2A69A" ||
      model == "F2A66A" ||
      model == "F2A70A" ||
      model == "F2A71A" ||
      model == "F2A67A" ||    
      model == "CF081A" ||    
      model == "CF082A" ||
      model == "CF083A" ||
      model == "B5L23A" ||
      model == "B5L24A" ||
      model == "B5L25A" || 
      model == "B5L38A" || 
      model == "B5L26A" || 
      model == "B5L39A" ||
      model == "C2S11A" ||
      model == "C2S11V" ||
      model == "C2S11V" || 
      model == "C2S12V" || 
      model == "L1H45A" ||
      model == "G1W46A" ||
      model == "G1W46V" ||
      model == "G1W47A" ||
      model == "G1W47V" ||
      model == "L3U44A" ||
      model == "L3U44A" ||
      model == "CE989A" ||
      model == "CE990A" ||
      model == "CE991A" ||
      model == "CE992A" ||
      model == "CE993A" ||
      model == "CE994A" ||
      model == "CE995A" ||        
      model == "CE996A" ||
      model == "E6B67A" ||
      model == "E6B68A" ||
      model == "E6B69A" ||
      model == "E6B70A" ||
      model == "E6B71A" ||
      model == "E6B72A" ||
      model == "E6B73A" ||
      model == "CZ255A" ||
      model == "CZ256A" ||
      model == "CZ257A" ||
      model == "CZ258A" ||
      model == "H0DC9A" ||
      model == "L8Z07A" ||
      model == "CF235A" ||
      model == "CF236A" ||
      model == "CF238A" ||
      model == "D3L08A" ||
      model == "D3L09A" ||
      model == "D3L10A" ||
      model == "CZ244A" ||
      model == "CZ245A" ||
      model == "A2W77A" ||
      model == "A2W78A" ||
      model == "A2W79A" ||
      model == "D7P73A" ||
      model == "CF116A" ||
      model == "CF117A" ||
      model == "CF118A" ||
      model == "L3U59A" ||
      model == "L3U60A" ||
      model == "F2A76A" ||
      model == "F2A77A" ||
      model == "F2A81A" ||
      model == "F2A78V" ||
      model == "F2A79A" ||
      model == "F2A80A" ||
      model == "CD644A" ||
      model == "CD645A" ||
      model == "CD646A" ||
      model == "L3U46A" ||
      model == "L3U45A" ||
      model == "B5L46A" ||
      model == "B5L47A" ||
      model == "B5L48A" ||
      model == "B5L54A" ||
      model == "B5L49A" ||
      model == "B5L50A" ||
      model == "B5L04A" ||
      model == "B5L05A" ||
      model == "B5L06A" ||
      model == "B5L07A" ||
      model == "L3U40A" ||
      model == "L3U41A" ||
      model == "G1W39A" ||
      model == "G1W39V" ||
      model == "G1W40A" ||
      model == "G1W40V" ||
      model == "G1W41A" ||
      model == "G1W41V" ||
      model == "L3U42A" ||
      model == "L3U43A" ||
      model == "B3G85A" ||
      model == "J7X28A" ||
      model == "B3G84A" ||
      model == "P7Z47A" ||
      model == "B3G86A" ||
      model == "L3U61A" ||
      model == "L3U62A" ||
      model == "P7Z48A" ||
      model == "CZ248A" ||
      model == "CZ249A" ||
      model == "CZ250A" ||
      model == "CA251A" ||
      model == "L3U47A" ||
      model == "L3U48A" ||
      model == "CF066A" ||
      model == "CF067A" ||
      model == "CF068A" ||
      model == "CF069A" ||
      model == "L3U63A" ||
      model == "L3U64A" ||
      model == "CC522A" ||
      model == "CC523A" ||
      model == "CC524A" ||
      model == "L3U49A" ||
      model == "L3U50A" ||
      model == "J7Z08A" ||
      model == "J7Z14A" ||
      model == "Z5G77A" ||
      model == "J7Z03A" ||
      model == "J7Z07A" ||
      model == "J7Z05A" ||
      model == "J7Z13A" ||
      model == "Z5G79A" ||
      model == "CF367A" ||
      model == "D7P68A" ||
      model == "L3U65A" ||
      model == "A2W76A" ||
      model == "A2W75A" ||
      model == "D7P70A" ||
      model == "D7P71A" ||
      model == "D7P68A" ||
      model == "L3U51A" ||
      model == "L3U52A" ||
      model == "L3U65A" ||
      model == "L2717A" ||
      model == "J8030A" ||
      model == "J8031A" ||
      model == "F9A29A" ||
      model == "F9A29B" ||
      model == "T5D66A" ||
      model == "F9A30A" ||
      model == "F9A30B" ||
      model == "T5D67A" ||
      model == "1JL02A" ||
      model == "F9A28A" ||
      model == "F9A28B" ||
      model == "CQ891A" ||
      model == "CQ891B" ||
      model == "CQ891C" ||
      model == "CQ890A" ||
      model == "CQ890B" ||
      model == "CQ890C" ||
      model == "CQ893A" ||
      model == "CQ893B" ||
      model == "CQ893C")
    {
      fix = "2308937";
      vuln = TRUE;
    }
}  

else if (fs == 4)
{
  if (model == "E6B73A" ||
      model == "J7Z06A" ||
      model == "CZ244A" ||
      model == "CZ245A" ||
      model == "A2W77A" ||
      model == "A2W78A" ||
      model == "A2W79A" ||
      model == "D7P73A" ||
      model == "CF116A" ||
      model == "CF117A" ||
      model == "CF118A" ||
      model == "L3U59A" ||
      model == "L3U60A" ||
      model == "F2A76A" ||
      model == "F2A77A" ||
      model == "F2A81A" ||
      model == "F2A78V" ||
      model == "F2A79A" ||
      model == "F2A80A" ||
      model == "CD644A" ||
      model == "CD645A" ||
      model == "CD646A" ||
      model == "L3U46A" ||
      model == "L3U45A" ||
      model == "B5L46A" ||
      model == "B5L47A" ||
      model == "B5L48A" ||
      model == "B5L54A" ||
      model == "B5L49A" ||
      model == "B5L50A" ||
      model == "B5L04A" ||
      model == "B5L05A" ||
      model == "B5L06A" ||
      model == "B5L07A" ||
      model == "L3U40A" ||
      model == "L3U41A" ||
      model == "G1W39A" ||
      model == "G1W39V" ||
      model == "G1W40A" ||
      model == "G1W40V" ||
      model == "G1W41A" ||
      model == "G1W41V" ||
      model == "L3U42A" ||
      model == "L3U43A" ||
      model == "B3G85A" ||
      model == "J7X28A" ||
      model == "B3G84A" ||
      model == "P7Z47A" ||
      model == "B3G86A" ||
      model == "L3U61A" ||
      model == "L3U62A" ||
      model == "P7Z48A" ||
      model == "J8J64A" ||
      model == "J8J63A" ||
      model == "J8J65A" ||
      model == "J8J70A" ||
      model == "J8J71A" ||
      model == "J8J72A" ||
      model == "J8J76A" ||
      model == "J8J78A" ||
      model == "J8J66A" ||
      model == "J8J67A" ||
      model == "J8J73A" ||
      model == "J8J74A" ||
      model == "J8J79A" ||
      model == "J8J80A" ||
      model == "CZ248A" ||
      model == "CZ249A" ||
      model == "CZ250A" ||
      model == "CA251A" ||
      model == "L3U47A" ||
      model == "L3U48A" ||
      model == "J8A10A" ||
      model == "J8A11A" ||
      model == "J8A12A" ||
      model == "J8A13A" ||
      model == "J8A17A" ||
      model == "J8A16A" ||
      model == "L3U67A" ||
      model == "L3U70A" ||
      model == "L3U66A" ||
      model == "L3U69A" ||
      model == "CF066A" ||
      model == "CF067A" ||
      model == "CF068A" ||
      model == "CF069A" ||
      model == "L3U63A" ||
      model == "L3U64A" ||
      model == "CC522A" ||
      model == "CC523A" ||
      model == "CC524A" ||
      model == "L3U49A" ||
      model == "L3U50A" ||
      model == "J7Z10A" ||
      model == "J7Z09A" ||
      model == "J7Z11A" ||
      model == "J7Z12A" ||
      model == "J7Z05A" ||
      model == "J7Z08A" ||
      model == "J7A13A" ||
      model == "J7Z14A" ||
      model == "Z5G79A" ||
      model == "CF367A" ||
      model == "D7P68A" ||
      model == "L3U65A" ||
      model == "A2W76A" ||
      model == "A2W75A" ||
      model == "D7P70A" ||
      model == "D7P71A" ||
      model == "D7P68A" ||
      model == "L3U51A" ||
      model == "L3U52A" ||
      model == "L3U65A" ||
      model == "X3A69A" ||
      model == "X3A68A" ||
      model == "Z8Z19A" ||
      model == "Z8Z18A" ||
      model == "X3A72A" ||
      model == "X3A71A" ||
      model == "Z8Z21A" ||
      model == "Z8Z20A" ||
      model == "X3A79A" ||
      model == "Z8Z23A" ||
      model == "Z8Z22A" ||
      model == "X3A75A" ||
      model == "X3A74A" ||
      model == "X3A59A" ||
      model == "X3A60A" ||
      model == "Z8Z06A" ||
      model == "Z8Z07A" ||
      model == "X3A62A" ||
      model == "X3A63" ||
      model == "Z8Z09A" ||
      model == "Z8Z08A" ||
      model == "X3A65" ||
      model == "X3A66A" ||
      model == "Z8Z11A" ||
      model == "Z8Z10A" ||
      model == "X3A87A" ||
      model == "X3A86A" ||
      model == "Z8Z12A" ||
      model == "Z8Z13A" ||
      model == "X3A90A" ||
      model == "X3A89A" ||
      model == "Z8Z14A" ||
      model == "Z8Z15A" ||
      model == "X3A92A" ||
      model == "X3A93A" ||
      model == "Z8Z16A" ||
      model == "Z8Z17A" ||
      model == "X3A78A" ||
      model == "X3A77A" ||
      model == "Z8Z00A" ||
      model == "Z8Z01A" ||
      model == "X3A81A" ||
      model == "X3A80A" ||
      model == "Z8Z02A" ||
      model == "Z8Z03A" ||
      model == "X3A84A" ||
      model == "X3A83A" ||
      model == "Z8Z05A" ||
      model == "Z8Z04A" ||
      model == "L2762A")
    {
      fix = "2405135";
      vuln = TRUE;
    }
}

if (!vuln) audit(AUDIT_DEVICE_NOT_VULN, full_product);

# Check firmware revision
#  Only look at the first part of the firmware revision (e.g. 2307497 of 2307497_543950).
#  The last part of the firmware revision changes for each model

if (ver_compare(ver:firmware_major, fix:fix) == -1)
{
  report =
    '\n  Product           : ' + product +
    '\n  Model             : ' + model +
    '\n  Serial number     : ' + serial +
    '\n  Source URL        : ' + url +
    '\n  Installed version : ' + firmware +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING);
}
else audit(AUDIT_DEVICE_NOT_VULN, full_product, firmware);
