#TRUSTED 6de7f1fe1318aa3da9b62d2d9ee0575c86784c348a2601f9ba246d264afe7ecd5f31ade622b1b336d5053f54e1d9b40d25ec091ba917740706439bad305825ee46d099a47ad2b40406eed3dba014fe8c6f8c17d42af227888a24d0d64b1d7fe788caa0e0736da440388c29854ee56fa16454f8b9c4b10ad13fdc697fcf38f04083d44ae3281336659f8dcfa759148b8b331ba590b063535024b3fef64658e07b4f51c091ec164ac210e60e59d5a53213922b4de8ef0a931c9ed189ba1ecc4c7d699007dc8abf3f3bedb1388903cf0778017f556e568409e2fc3bfcdacdf7d6fa0980e13ad9bae51e1439498b6a0f3873162352a4744ead56dc58c21de0042c02169bc689d9e53536ad5ee51127b9d65e147b40e9d8c7bead9d0d9a8e62173318389ff4ce9739a28716953fa0efc5d5281447f728818947b41edc2cb1d6245d5d8e54207fa094824f1678f4f6ee7a34eba58ec62c81d995f0e961a092bcd5f781d52d1a3a5ce36b23b9d23dea3ee20b89637faf33a05ed2459ae97768bbc9c08c9424da3bf31f19c2c26e4ea86e80ce4a8bfacd83b2e39f5e85da85ebbea5d19fc2f250b0f2f16f874795a422a33c1e6aa3510c68b1ec2a37807931c170fbd5f112915bb39b256529bd3673b9f50ce35b04753726dc11dfe3f4f80c5f44acb2b6e689b3428fee1a489e65e6c0047d6ded3ecb35f41e55733dacd78f346b7eb843
#TRUST-RSA-SHA256 5c94c2fb81eaa077107a956a2a9a5f6c6801b8278e42ea3cbeb46ce40ed96c80e4ae2b6c5e3ca23f3d183c8c77d27e4a1491dff4b9b47f30e9bcd5a8a502ffd66862b79a5177640e377b18e08c5c44e57e88958b65a82f5dc1441569674195425e0e37d12361aafba5348494a5bf1ea556cfbfc9ba616454d4975ae5ca73716e928ea21107b98ab4f6d6b201086f155fe54cef5492f387d16c399aa05e0c9897281ee153c0b0ba6c7fead8455d8c96f0a07218e8f587799b3cddb39c0cc76e365805e705b5089c3cccfa5e3244db19ba6eae41db895c311ff39bd6f5b37f1c392c93bc1f7f6a2f7b8a2232a48df83c0436a6db5c6847c4c47a50492ea9c4adc0f64ae983cc536a530476a0782741d81cf8a62145a84ff6f175f0f0a9785651ec7869fd0111584a411b1a4b3445ab68031abac9fd8280458d73718ed2657270428777a3d63147a78de9484a0f3477668d4606f1edc619a4cc01374ee4ffaf870d853d305119d8f6ac0dd950e7d7aae462a6d0a576ca5abbe9394ef3b8e73f6f34c3949ef019a2323db3bb3df65ef8839735c882b6bb1c0fed6531227c5ade165dc54674115dceadbb368057050a642458bbdb0c3d33983841479ab7463f5c5d56282ab39872c44ea250da87c28860c3a002ef799ef1df9a3d8b119565892dac6bfdd1f6f11bce114d716d71ee499915cfbdf71bced10dff567cfa6d3de95d05b3
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145708);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/25");

  script_cve_id(
    "CVE-2021-1241",
    "CVE-2021-1273",
    "CVE-2021-1274",
    "CVE-2021-1278",
    "CVE-2021-1279"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq20708");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11522");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11523");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11530");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28409");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu31763");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-dosmulti-48jJuEUP");
  script_xref(name:"IAVA", value:"2021-A-0045");

  script_name(english:"Cisco SD-WAN DoS (cisco-sa-sdwan-dosmulti-48jJuEUP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN is affected by multiple vulnerabilities, including the following:

  - A denial of service (DoS) vulnerability exists in the VPN tunneling features of Cisco SD-WAN Software due
    to insufficient handling of malformed packets. An unauthenticated, remote attacker can exploit this, by
    sending crafted packets to an affected device, to cause the device to reboot, resulting in a DoS condition
    of the affected system. (CVE-2021-1241)

  - A denial of service (DoS) vulnerability exists in the IPSec tunnel management of Cisco SD-WAN Software due
    to the bounds checking in the forwarding plane of the IPSec tunnel management functionality. An unauthenticated,
    remote attacker can exploit this, by sending crafted IPv4 or IPv6 packets to the affected device, to cause
    a DoS condition. (CVE-2021-1273)

  - A denial of service (DoS) vulnerability exists in the UDP connection response of Cisco SD-WAN Software due
    to the presence of a null dereference in vDaemon. An unauthenticated, remote attacker can exploit this, by
    sending crafted traffic to an affected device, to cause a DoS condition. (CVE-2021-1274)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-dosmulti-48jJuEUP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05f6f0f0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq20708");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11522");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11523");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11530");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28409");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu31763");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq20708, CSCvt11522, CSCvt11523, CSCvt11530,
CSCvu28409, and CSCvu31763.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1279");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

vuln_ranges = [
  { 'min_ver':'0',    'fix_ver':'18.4.6' },
  { 'min_ver':'19.2', 'fix_ver':'20.1.2' },
  { 'min_ver':'20.3', 'fix_ver':'20.3.1' },
  { 'min_ver':'20.4', 'fix_ver':'20.4.1' }
];

# 18.4.302 and 18.4.303 appear to be between 18.4.5
# 20.1.12 is between 20.1.1 and 20.1.2
version_list=make_list(
  '18.4.302',
  '18.4.303',
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq20708, CSCvt11522, CSCvt11523, CSCvt11530, CSCvu28409, CSCvu31763',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
