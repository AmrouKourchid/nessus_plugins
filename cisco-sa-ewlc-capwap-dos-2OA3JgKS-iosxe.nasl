#TRUSTED 0601fdfdf55165131f6e0482a484042a56f3dd012e66b97366ab9a2ea4fbecca1205197dda7a079c7451277a602bc2a86065168b2e5c2895872bfcd713ea2a3ca3e74dcb1fdb583fdf548045bb71a4188310d631c10c548dd27127a24d0bfab7f9a20693786c53c36bb983b17c55593d309e2210b868837c01ceae3b5d8deb897541c2046eabd043f306b5d5703573d65634cca9ecd284fa4e99242fb31bc641fc4e578f0c3f93b5abc75b1c9512ee722c728f82b206cc001d13c596ee125b390d5dc9a7fa21d09f8158aa184813d0ab15a614688c72a78466251a4e4de04ed84dd1363c42402089e1c1442b6c74534691ab6e788cfa0f98660cadb6b50347b0d61198361bf84ccbd2904d6f06662c5d5eb882b8ceffc058fb1d6ec022e741c92089487400c280b0848e4c3a5b2dd9d2e6e29d60a4ac5aabe1f2a1ba33f64aa83db93468ec56959ae71b38f51476cc6e738e30ac65eb99d70fe141445fa87a184969a1aa1fac11a151eb7011515b8ff384982947613edd6c9f4951ece29878e99e35905bc4a3f705c0c36ccd38a4ea610969d9094faccbb2f6285ce7688695e04c9f7e1e1917f69277a5e09c0ab9ed010ad7aafa223166c3df915cf6f46610e01f86503170b9934218c3d6978833bef8b66d56a0d8682e83f5ebfe6e875d1bb0ed2f0a517defea07ecdfca8a7f256dbee4ffa3b6e5483293c754d3515e135d2c
#TRUST-RSA-SHA256 abba5f3ecfa5e1b9767ce76aa29da6dc2f024d3d176d262e5fdc87f2b872922845bb52e1e41a34777ccf7c9ed5e3a7468fa633d1149dea7694c4650ab47f3333e826cd897cede393657d01632788e1c01b44eccff553d54230d3fed76bae03837ea06c508ac28b25ea99e8e35c4832b3467bc4afc6b3a2a70fec50c219322edc842333528dd9883a61e66d020a65fecb706243b54f828d8912ce8b10a1e82a70e9fa8cc35dc5c3b8d19e297b553327d3ec4d336fc1bfcf019a453d3fd135fc348c1ce06a67ed43d2e0f0bdaa7c3a7ef4feeb696d4f410cbfbbe85c292c461f5ae26dd4d4cbdcbb3b8340a00f8f8b240bd98fc717dbc30ecfa501f202937012f879498ba654772f7de2e9fba425b80fc0a1cb88add07d55cd4c0fd556f423c44a3f5ad69c24892f7c000db02666647a6415bdc8c85758a4a7617597326ef3421f79a867a9575b0931026bfd45eae715ef9134081f7b3b87b38c9f9f610ac598dd580be88cd8103779d0501c0e876fadf56157a609d39a17c7ce121fb3021c8459dd7eb60fe480774390ad285d6f0441594ba7d79afb9f3e943fb944a7de1201c736a7a25aec3a893021d59748481a4dde365664788112a0a5a3f95992f2acbe7ed4ecfde04da0c80823e68845bdfde1e6aa7328c58270ac2a24018bb2d4223ef5ea33a211acfe57304e21aa227a22228baab6a57e353ec16f7f89d8b2f6e4b671
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148101);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1373");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv41608");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-capwap-dos-2OA3JgKS");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family CAPWAP Denial of Service (cisco-sa-ewlc-capwap-dos-2OA3JgKS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-dos-2OA3JgKS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6d909d5");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv41608");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv41608");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1373");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(126);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if ((model !~ 'cat' || (model !~ '9300')) &&
    (model !~ 'cat' || (model !~ '9400')) &&
    (model !~ 'cat' || (model !~ '9500')) &&
    (model !~ 'cat' || (model !~ '9800')))
    audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.3',
  '17.3.1'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvv41608',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
