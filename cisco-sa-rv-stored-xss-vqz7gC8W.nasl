#TRUSTED 5c86231bdbec56633a78571a05922abfb2da0b35ad6cd151fc7b3d3cbf4717cd12413a58555f0322c7ff8d2e0cd2e0477e0b4b88153e1014f53e54b4c3112de5a546ab32fcdf7ab054ec56a0f825363afd0e270f4bfd32bfdea707b6f8925d84007539de5aa5a89c0264b4bb6bdf4caed717fd19e75cedcd835685427cde17d3732226f3bdcbc3a5ae371ace683824153dd2500f044300968967b9b2f0a9f5d6b2c5839fbc89466a448e60c91a73f23e1db3808a29a5a5baeb914cb5baf466956ce67e97a6a41aee77dfa9e7d921bc2fe2fc467ec7b2e9f6f2a077a2a26e0410c2798a1a3903e56a77b0d0cc31dba0a8075a7c4632124f2ff9bb54a307fe8e27fe29565e9666322fb5e6c7f23b0268818aba92248a7caf7f6d793d67a861e3a744e0a54001bf41b28e20a370ea30780ef42af23fa7d43f34b5f01271c17f2c810016a04b69956612d99e8ddf616f3a46f08ff93e618b2ba7e0ddacd432d217d74937f2818a033e420271fd649429394ec548224bc4356cb963aa0a3b0c5d288634056a619db5eabcc6e09e0b49341fc282075a139c916e7242ac1866fd1358afa61ebe451649c7248fc86a4950b702e515d4ce116f06877c586a10d08714a4296ecc26f0325d800b263d6c85e067a3f64bf51ce18714dc105de5ca94dede1a9f1627f61254170ffef8deca8e6f3f87ad39308c3dc4e683eafe5a614b2e52af48
#TRUST-RSA-SHA256 083779dee144a0102d68e518baf390fcb1bc44bb8ea9037ddb36d88ce87e40de76a6f260e9d252762d39461b7f652ac5ead1cb777a75ce636b3dd9060ab17386f7c5d03687da811274769de83843b416a4d5532a5243763fa0473a3df9d584cf92dc0fb021329d4d7b8c362197cc415e94a5e7c440164f075ce8732c4a6d9c3c1754152bef50dfef78e6ddcc15fb0d823ad80fd23aaf1c628493b461e75c99fbc06d583cb78a8d00bab502037a2f21b6290bc331ed5a63ab0ea635205c78b623f4ccfa8f6c32075a16c2e2d02d32e135c694af883466ec4074779b66d69481931675083f3727033cb4c10edf59f625c4f872cffe8a8bf78e9e962028faeb0f30d5eb3591fb71c3b8006fca981898bf88e6c18d1ceb86643738919629d3d8f2cc62f72f17ca7c85fdf2053256a8bae95b5263485ac1d8a6edab5d54b98ff05525cd80ae65eefedd1828f5e1b61cfdcb8772752c1eb9c83eab41277867a073e9547fa92e082fbfc8de75f7e7c3fd48d67706ddc5e6f7675459327d74672e053750d26d5910d2c2b80016d383d5c6727f0ce8df6e93734cf018ee7ecaed473cbfa14c2a182ea818e0b5fe7ac2b20a290958198b6745f782a86a5b60fb85de6ab8b5439393db3d64492eda3e4d8c79f3848fdd7cbe2ccafe2c520a8e7f5f773b55c9ee443c0cbe16bc061e05eb06b015edd1ecf85905128124371bad8fc57408e658
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173978);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id(
    "CVE-2023-20137",
    "CVE-2023-20138",
    "CVE-2023-20139",
    "CVE-2023-20140",
    "CVE-2023-20141",
    "CVE-2023-20142",
    "CVE-2023-20143",
    "CVE-2023-20144",
    "CVE-2023-20145",
    "CVE-2023-20146",
    "CVE-2023-20147",
    "CVE-2023-20148",
    "CVE-2023-20149",
    "CVE-2023-20150",
    "CVE-2023-20151"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe21294");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75298");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75302");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75304");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75324");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75338");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75341");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75346");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75348");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75352");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75355");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75367");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75369");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75375");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75377");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-stored-xss-vqz7gC8W");

  script_name(english:"Cisco Small Business RV016, RV042, RV042G,  RV082 , RV320, and RV325 Routers XSS Vulnerabilities (cisco-sa-rv-stored-xss-vqz7gC8W)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV016, RV042, RV042G,  RV082 , RV320, and RV325 Routers
Cross-Site Scripting Vulnerabilities is affected by multiple vulnerabilities:

  - Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV016, RV042, RV042G, 
    RV082, RV320, and RV325 Routers could allow an unauthenticated, remote attacker to conduct cross-site scripting 
    (XSS) attacks against a user of the interface. These vulnerabilities are due to insufficient input validation by 
    the web-based management interface. An attacker could exploit these vulnerabilities by sending crafted HTTP 
    requests to an affected device and then persuading a user to visit specific web pages that include malicious 
    payloads. A successful exploit could allow the attacker to execute arbitrary script code in the context of the 
    affected interface or access sensitive, browser-based information. Cisco has not released software updates that 
    address these vulnerabilities.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-stored-xss-vqz7gC8W
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54397251");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe21294");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75298");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75304");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75324");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75338");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75341");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75346");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75348");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75352");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75355");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75367");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75369");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75375");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75377");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe21294, CSCwe75298, CSCwe75302, CSCwe75304,
CSCwe75324, CSCwe75338, CSCwe75341, CSCwe75346, CSCwe75348, CSCwe75352, CSCwe75355, CSCwe75367, CSCwe75369, CSCwe75375,
CSCwe75377");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20151");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv320_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv325_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv016_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv042_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv042g_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv082_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv320");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv325");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv016");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv042");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv042G");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv082");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (toupper(product_info['model']) !~ "^RV(32[05]|042G?|016|082)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'flags'         , {'xss':TRUE},
  'bug_id'        , 'CSCwe21294, CSCwe75298, CSCwe75302, CSCwe75304, CSCwe75324, CSCwe75338, CSCwe75341, CSCwe75346, CSCwe75348, CSCwe75352, CSCwe75355, CSCwe75367, CSCwe75369, CSCwe75375, CSCwe75377',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::security_report_cisco_v2(reporting:reporting);
