#TRUSTED 5107b2007a163c61c8452f3869a74e62e60044959e4e89babdc762c2fd2e5968f9e63ce7bb46bb57ee5e36deb17e53dc5916d1d14e9b5552c8e014d4bcd6ed8ab5830ad8793aca07ba839e40dac415bf8f4485b2401de384861d710eb81349458f7249db2877b666fe2ab4e68db89a8f3c8e1ee9767010d73aa198858987e528121869eb11940bb75282bcbba1dba571e72af55e5fe9ca61a0df42554d5d55b4f63765d1c17b6760d71b699404e72c01863de6b431b844ffddfc954a602b648713b184c304ba6291f5d262d0408cef0e2c31dd2f11eff67fa5a56149551a8c44a0bf138fa35a66362cd08950742e4398f7f89785d1916f950ee989ab72405f937faf2493361fe1ea73843d9cb20ca63ced85dfede534715b9aacd730519388512e4492447ebfd7e1eac7686b1f424a8d71fc01e0c819290502dcc81ba33fd55e6831460bf08a8f82364b19800ab5d8660119c51a5e0f26992e4ac45b79021a08e2ed024d891d6731288289305612ebc2063f3d9cc2f5f14baca7dbe8656f3b14f054ef268f857621d71e060b6f00da246974a5a4146aabc8452e216780dc7c5a507f885ad9777bf9cf7706af0c01175cd33c2168229184f27e9eacb0027d727eb546ac067d55bac7e994a77d354fd2669b3d4b1a7155b847210a8e011a4008e832a5811f4d1392eb636142c446cabe6c5951c0a1083ccab56c904d96659d3415
#TRUST-RSA-SHA256 69e5663ddaa63ca0a14b59b3ece11370a715af747dde2e60445b8e77017a5eb9f9bac3bcbd56315027445889308fcc60675d6306f856a72f34161ada4d7d6290e2f6ee7f2df50886238f57fb6ce3585d0e0a5c2390319eaf266744e69b81cf46ffa2ce5fdcef76b5950057c62eb0e6363ca79653d376793cfb36f34105ad8a1e810a24a31cc40ad591a3acc5f13bd3fd9a2c46036af8ffd9ff2ed38fafc190a083fb7e85513a953167163b9405714e6aec667e637204ce6881a061e9932837e161b5e42ff53950bd1a5c2c64a69176e1f16b036d6bc5abdab0cb56cb32e92d4a3cf6a4e3edaca0c30c88ba4caab20600e0f79ff2bd9d752098cc1b2858354f0b20daff869a92c9178518f576951231000d63adf860c37bc17cb26faf021bf849022ac29304ba9168edf843336dcf63bc679f0cdd3969c4d5a096cb6004cb89d660efebe2167cb22ecb73fbac638ba14a15b1b66ce30cde93cca4f5e6c7313697fb4b1dec6f0f2faae38c30af52d66c13929ae548dd091729d8b9be6db8382ea7cc582d76e8fdfa45021d6b69927664a8586a945eb69be66f059b402471e3ab5bb63f6137fa3d428e63e6f9d575b431de547911ea07b6e0d6636f8c234aaa147186e50e880223b4b2b04eb5572645c5f1425ca7764c7b19658000b3ca55fc793259024c50b585ddcc18925ebc4296f27ae71cc516a747a9cd2e0224e148699c92
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141467);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/15");

  script_cve_id("CVE-2020-3268", "CVE-2020-3269");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28203");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28218");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28223");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28229");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28233");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28237");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-routers-injection-tWC7krKQ");
  script_xref(name:"IAVA", value:"2020-A-0274");

  script_name(english:"Cisco Small Business RV Series Routers Management Interface Vulnerabilities (cisco-sa-rv-routers-injection-tWC7krKQ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
vulnerabilities that affect the web-based management interface. Please see the included Cisco BIDs and Cisco
Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-routers-injection-tWC7krKQ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48a716f1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28203");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28218");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28223");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28229");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28233");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28237");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt28203, CSCvt28218, CSCvt28223, CSCvt28229, CSCvt28233 and CSCvt28237");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3269");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (product_info['model'] =~ "^RV110W") 
{
  bid = 'CSCvt28218, CSCvt28233';
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.2.2.6' }
  ];
  fix = '1.2.2.8';
}
else if (product_info['model'] =~ "^RV130(W)?")
{
  bid = 'CSCvt28203, CSCvt28229';
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.0.3.55' }
  ];
}
else if (product_info['model'] =~ "^RV215W")
{
  bid = 'CSCvt28223, CSCvt28237';
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.3.1.6' }
  ];
  fix = '1.3.1.7';
}
else
{
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');
}

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , bid,
  'disable_caveat', TRUE,
  'fix'      , fix
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
