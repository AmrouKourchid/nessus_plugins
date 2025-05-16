#TRUSTED b1ac325a2893b6fe9f0c086af32746586546132d3f8a85d18b02c09eacc3c3d48fdfdde14c60e646b5f48e8a4cdc39584cc958a09d1d9b8d5e53eca2b58c0dd56ccd662ea76db447c46563613686ba65dd197d682b6e348f0a7b2b611fe986486d50ab2849a9adfc30f9198d6d26b8b1f2e5e6a7069e73242cd89494c491eac48153c43861adb55fa1b26a6e9fcfd540e6f370e9d8692d0c3b70e8718e23ca1746fa999afdd282e3da829cec0e26cade617cc43220bd838f5703448eb9d6115be83c62b32731986fa4bcaa31ef774773fc115a8750afea8bb475004b992f266a2b90af65fd41a6c7738f836cf22c125021cfccb6e0ed6ba776a311e499d83b1e28d6e027122c314e83fb4cc1eeb3ceb939a3d5df94adc7316c9b631631d40eca64a51eefd86ffec674d880e2c8601a49a449ea2697b20a550c91a52773331bc7ff9069a11f5bc14c61fb283c1fa856665b1ac6dbff74b7ec975f793b78f11a244ffeb4c577ec82a05f1187efa4e27b21766be986a145cd4f885d71925286a3f628a2ecb1a201b42cc4232fa2a49a9c34a9a537b7547b94f4e76422ed559f3e8657913df72c7a7faf4e5db6eb082b2948652c26ccd4095a3e33105fc4ca00a24e2bc51042c0d98ea0d34a28b57693576e6ae581d09c994cbdb36de8dffe5528b663e1e178c43aadb5bb72b0f810d2ead0d4733852e5a4222c48e7c2d267f5fe10
#TRUST-RSA-SHA256 a52c102b6faece862c80a7e7764c815df47e9091e8b81b2b594d6f3ea05b62adb63602633a8162a15fdff3f33ebdbfd203ee8bedac8bbdce67842698af2a624d227e4f85fc61b68b67c4b0b7fdd23dd396caab63badddc3e9fba2679677514a4f4a294bf8ee5fbbccf71d7ccbd1f67c3d8e83ef386292c059dd692d66a0dfa05324865598d55c15268770fceca0ddabc53f75f9da7e0b2e806d84df55afa6449d6509ad3bacae944f0152e2fa6fd7ffe8bb5f1eae5a8352f5808fc36ef21ecc8e648e42504c2f2015fd57ced4fb98cd6469ec3cdd9a3a5ea52ad6eabde883ddec506ee7665a6b074100f663d20eaff28592ea22ee3bc1fed6cfd36c1cc2d9c1e3e60d3ab968bc8435eb0a638b4fe3d4049214ba88a53fae8193d6d8e2d0c0f133dca2e804eb426734b775ca087dc2104b6ea229917b95f58905871e81f4618aba0c25270ed3cca0257d845cdd846f647fc4a5204d9e459b55a08f9d2a9f4457f1b7031472549f1960687da067b3321e980078fdaca978159b0d5f80f2e6c3445b1c13eb2b5cd02a1830beaeb0b44e2720fcb467478b45e24eea831c841f20ab9544eb25c388bc80829371ff7e3efcf8d890d5485b0c05c997a402553db7717406855f17574cdf07737ab2ab3b1c66dd1ba4b01e6789526c5e889c6f576e139c481cd04c33b8f88891e5194f32fb3af73b4b9773d7c1fde367faca8cd4cb02e21
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138019);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/05");

  script_cve_id(
    "CVE-2020-3274",
    "CVE-2020-3275",
    "CVE-2020-3276",
    "CVE-2020-3277",
    "CVE-2020-3278",
    "CVE-2020-3279"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26490");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26504");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26669");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26676");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26683");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26714");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29372");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29376");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29405");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29407");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29409");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29415");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-routers-Rj5JRfF8");
  script_xref(name:"IAVA", value:"2020-A-0274");

  script_name(english:"Cisco Small Business RV Series Routers Command Injection Vulnerabilities (cisco-sa-rv-routers-Rj5JRfF8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
vulnerabilities. Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-routers-Rj5JRfF8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?feb06e74");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26490");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26504");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26669");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26676");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26683");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26714");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29372");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29376");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29405");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29407");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29409");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29415");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt26490, CSCvt26504, CSCvt26669, CSCvt26676, CSCvt26683, CSCvt26714, CSCvt29372, CSCvt29376, CSCvt29405, CSCvt29407, CSCvt29409, CSCvt29415");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3279");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

version = get_kb_item_or_exit('Cisco/Small_Business_Router/Version');
device = get_kb_item_or_exit('Cisco/Small_Business_Router/Model');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (
  product_info.model !~ '^RV0(16|42G?|82)($|[^0-9])' && # RV016, RV042 / RV042G, RV082, 
  product_info.model !~ '^RV32[05]($|[^0-9])') # RV320 / RV325
  audit(AUDIT_HOST_NOT, "an affected Cisco Small Business RV Series Router");

# RV016, RV042 / RV042G, RV082 affected version <= 4.2.3.10
models = make_list('RV016', 'RV042', 'RV042G', 'RV082');
vuln_ranges = [
  { 'min_ver' : '0', 'max_ver' : '4.2.3.10', 'fix_ver' : '4.2.3.14' }
];

# RV320, RV325 have different affected version <= 1.5.1.05
if (product_info.model =~ '^RV(32[05])($|[^0-9])')
{
  # clarify the affected models for cleaner reporting
  models = make_list('RV320', 'RV325');
  vuln_ranges = [
    { 'min_ver' : '0', 'max_ver' : '1.5.1.05', 'fix_ver' : '1.5.1.11' }
  ];
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt26490, CSCvt26504, CSCvt26669, CSCvt26676, CSCvt26683, CSCvt26714, CSCvt29372, CSCvt29376
CSCvt29405, CSCvt29407, CSCvt29409, CSCvt29415',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:models
);
