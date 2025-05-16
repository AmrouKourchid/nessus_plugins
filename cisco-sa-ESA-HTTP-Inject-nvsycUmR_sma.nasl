#TRUSTED 00a3b3f779a1747870d3080f24706cf1d6373edcc641e147a9dee3337e99700a8af52e6b733dfa02959ebf51f2515cdddeb391d146daf9477a9c91be27511b9b836ac3e0adb05eb7328ea15e903d7f052abdb714b8fda4d07c93d66850cd5146ea07c1b240a0499719f732cac11cd8c1a2462fe523e17bf9f9e024289984cb2411fe0cf23a82558a12a9f9f5f3306dde8eaaed45308e00b35fc7a8a4b8181113386184ac4dbe28ba25c9915924820fc77f9f3a96e941623c62e0619cc185f99f7efebc36ef9f2d7c7ab2b220ed1b04da4ee82aca4f209f3759ed27bb9d6f55e506eac9921227f1b98fd874667cada82dc4498d13ea96c21b0c10befb593fe82e8498dcca30574cb746da25f2a1b923861e7e167b2011b160692a32824ce265888728bb16e6ad735f8e5fbbc2ead87c56748ddd46bc3a791333dc4e5fcec7598b419091bb28d55b023bc5384d9a05bea025243b4393e96884715c0bfdcf76afff98ce6de7f6727b6cc7faff3fad7dc718fb3aea475007f8f73fb31f11e0bb780e274924de43c5e4eb7f0e3d1b301fae6fa21d6f52b56adfa880668fa256d49c9468e18b83d6398befdc5504fd8a31d3284ff6e472592645f44d0f3f8f90595e97ce3d29566e57f922e8db5eea11304ca644d8e32f4508e59bb499bda241d67021fa30577fae5a7457f3eeb2cf93ce09006b760e9c274b8b73f634d6ce1edd42e5
#TRUST-RSA-SHA256 7f37050c73d8dfafec22f7177c9e91b46fb82f6a2be484ea12f10adf3cbbff0aef8465196e9c30cf549bdf449d6b42f7768653ecbdb29fd098803b885762f9b31d55ad1ee9119d7e540f3b72c6883bdc0930bdad41f04e309e883b05306cfe6993234ffaeb028f1d7bd66db89f1a2b1416045872fff219ec909290709de4e95ff02b8387b7e444771f1a0a3ee150c5900af081e34903288b3c71ac1ea9f1a03fc47055561848dc4f29e930cb4a11f7086a794af3a0f6da39d1e549251aa28668b410eb9747651f4fcc34a272af8ddbcfb2380dd34abf48ecd28f5abdf4ffd4e67408ecacdb2467c1ef7a6271a687b6d641865e3518972f25475e57d563277e86fdfa74c1dee8aca2e0a9d34e83134c733b6326115d8ff1bf2edb9c7b0f44639a3d71faf035cb29dd648d8cea37bebb63be9f2af5b5938f1cf994cc9aa0babaaeda1c43751991c21f732667c72317c8bddc8ace6030e39816a7883ac86e79cc64e258549d8b35ce1d3b2f8b01f743754f143f989e420f57de13c2976a5d0bc22b7c55dd321a67a5f7e5245d5af5ce87a8bf7e4533fc79df378434321b2a2e44f1c34f4a09a1b8eafc62257d1c33ec5e41af1300a8455710a7159c73c39ace80a984435b8369328577422c5f9f894c346a2a9a663fb6bf62610104449bb910f4c3b0c1b14401e83d10b3bd4883f7ede278baacd46cd66c01fba3b2583d61681f45
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166904);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2022-20772");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz24026");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa84908");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ESA-HTTP-Inject-nvsycUmR");
  script_xref(name:"IAVA", value:"2022-A-0463-S");

  script_name(english:"Cisco Secure Email and Web Manager (SMA) HTTP Response Header Injection (cisco-sa-ESA-HTTP-Inject-nvsycUmR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email and Web Manager (SMA) is affected by a vulnerability due to
a failure to sanitize input values. An unauthenticated, remote attacker can exploit this, by injecting malicious HTTP
headers, in order to conduct an HTTP response splitting attack.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ESA-HTTP-Inject-nvsycUmR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc1d0d7c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz24026");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa84908");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz24026, CSCwa84908");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20772");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(113);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

var vuln_ranges = [
  { 'min_ver' : '14.2', 'fix_ver' : '14.2.0.217' }
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz24026, CSCwa84908',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
