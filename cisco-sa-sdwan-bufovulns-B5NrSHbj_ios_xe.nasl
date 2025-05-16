#TRUSTED 1841ff4f915417a6ecb4f936b49c1fced11c8f869b92d0c932d485a2d39573f646be3aac568893b61f4b12dd4de1608f9aa049077d054bd394233a9dcdd6d1e95d65871a9d3f66dfb825b48319aebe873e528dc7053e7379109f0cecd2c71955045bada0151f6a8bf9775864ffcf8315f647d5badf69169aeb813e336f7891a10d30897fc1f008b05d87f41e4ecc3395152070066c00378bbfbceab033e9abf34b3b8ef23f2a760b9107e8978711ae92fc06d03f012c85f78aad1fbfacc17ee79d9be3e4fd37775fdc16922d666372a773c90193ecd6eb6b357fa8a709221ee1ecea0d60c85255ddc9224acbfb0f821d1c4d58d007129a3e602794fb15c2eb03d42a11d6b3af5351b758947e68a005a46784163b61ddbbc56d1c32217201bc279545d8afbd9f68a1be82913a769a7c950e3fc5fbd91f47f4cdc4825ae8de115d15c0bc5659ca2a70639c96cf2143dbd621886932e8e2593a588906b65009b5a3269f437e0cf7d52c18f4419d4a997b670a642a07bba04eb3b67d65c614e26fbdb04bd9128f2b24748089482ceb6a2fae2b5d64ab921842a2dea4f9a9f4a5a079a6c030604d88eec6d4b1b1b915ecdcdd4ea83d156a6c90a4cd96a746daf86b8aa69f625b33152f02a29ffaf0adfd5d9ef8bab0a7aad05b3e83a41bb5ac31843ac45c79b12124df8806d1b689227ee1935322beb4c897fb1f9690f0a6c27ce009
#TRUST-RSA-SHA256 ad053c6d130bba3d23d89952ec2f76491d555616468a680e76567d51957f0cbd0ec647f070d1dd9d32ca17da9ffce5d193eaa0918028dad2f099407eec5681285ad0a05a77dc237cafa8e1586643d50f8cdbeeb21eb056cbcd552b7192364bc949bc903b35386083ba03bb3031d4e0b4c7f643d17f91566402b824468ca1b3f2840e1aaef6924eb2f33a96e7f99c9ee3a626183f7ce331946515298cfbd8f38824c039276b22728210d0ed2d18d9c6c9d3e654dc90988a9f2d10f20f0a8f86b6b29f950746c16353ad7792d0440796c4950134abe38fb800553d95778ea8c3f7fe47891ed2f1e803eb11bfc3e60e6faec4abef860a426955f335b19f21220d7d457a47ad0af798cd86ec4d54f0d9c3ba9c71295a7d58a94b8379a26de12675b686f2268e5f05f67883b4d43f6f7d535404082dc380b6eb4f276f86e9e147472b194d746cf80dbf23ad69a4c25f75986444b5699946fcd794c2745b13b7dfdf50b8687a983093823e092869936191eb6a7b8de765cc7feecc1d711857fced79e77f0faaca6525bffb159f8ffac39b39dbcd3dc5b200161e618808e78d266b49ae800b655afbd13e731990d8322d25323544b874214613aec0cf4be772518535e25fc3de7d8736ab77b852443f1011dc269fca69f335605580a01ef6c72afa559187a5cdaa907cfbb9ccf8b2afc0a1fd47502ff555f6779dbe1d6a228d00983c4e
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147962);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/09");

  script_cve_id("CVE-2021-1300", "CVE-2021-1301");
  script_xref(name:"IAVA", value:"2021-A-0045");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69895");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11525");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-bufovulns-B5NrSHbj");

  script_name(english:"Cisco IOS XE Buffer Overflow Vulnerabilities (cisco-sa-sdwan-bufovulns-B5NrSHbj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by multiple buffer overflow vulnerabilities
that allow an unauthenticated, remote attacker to execute attacks against an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-bufovulns-B5NrSHbj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f3f0159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69895");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11525");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi69895, CSCvt11525");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_ranges = [
  { 'min_ver' : '17.2', 'fix_ver' : '17.2.1' },
  { 'min_ver' : '17.3', 'fix_ver' : '17.3.1' },
  { 'min_ver' : '17.4', 'fix_ver' : '17.4.1' }
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi69895, CSCvt11525',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
