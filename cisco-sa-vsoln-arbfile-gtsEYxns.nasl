#TRUSTED 7cffee034703fc1220fbfedffbf4debb97dc2b72706128eefbab250762d0f6289731da7fd2c0ab82d0ca18a97207f69ae5f7a2971fc3ab19c1cdadbec5b98f81532b689720042cedfc00ee67e7a9cb72650d71c40a8c7aaa7a9b951540c23bf7f88e0bddb30008d8a3a1df33ffa330ca509e5f83d63c83e2f475c579fd72b6f68a4e0f9803db2a022909960384b55b247e5279e806623745962c66f1ad36a77f1476342c817c2b9f210b8d7b2bc37c1c79fcd4c045322913ca26b591747e76c709dfe60644172be2df003aba99f81d069ec37c3b0875dcfe90229f13dcd293e73b66c5b149941eb376b7c313ee87ba804dc3a12d3db391dad49eced230c055ebdab3b372c4f32c47d1e63169aa9d8ea09eb16c1d5fad73427aea5edf0b1afe11e16034f8b9881d7b6c644339bbd405d020bc3e3de44f5e742a9c6c48c6ffa9fcf3233c6a80a2727e9548ff30c289f07edf70ecb6beaf42a032fa844bc5104bc37974b353efc989b066884d825f62db3689e5db278bcf4163cf9ffb5e8ad1b2750151a2926df85caaaab26181c357a6f294f13404f259822d67b01a3d51110add11177cbdbcd1da17eff5b8dd99d1fa9673bc57e4ea4f8baf72c69c086807f98787aa3145c4bd116b1927059e03c65d61d2f19999658359aa8ee677f97c2a07233b3c5a3dcd78fe76976e254b010cfeb788e16f94dc47fbccf0c4244cc39cf893
#TRUST-RSA-SHA256 a387b256b62164c24d5d71c73e8f9327ed57d136eec4ba9fad377477304bc76453ed145ec301335ece38e7216059e1df42c80e56ad981250c4e0b1d95818ee564e9c471bb469a3ae6cb087df03df17fbeed23c125b83ceccfcc775ac426d3f99c46d9f8cc353c0f7a025fa68723cc0473b5f3a88d7755e15d3c3012ab115ac69df9db5d654fede7c2b395454b3e8bab725f44907161e5c9f9a531ad61da21e423fa2e0cbb140d3a29e9104c8f722dfb488c800b3ae5bf1feb322ed5ec0ae85071ebaf65c81a1be33939608e787774ec7ef301280add320c4f1336aeaac5aca1e06febc8b8767e9bd8714290c5ee584bcc01e13d8bf483177b085e6bb894c08d58c72aa8483b840faf1ccbb65bf50d8d95e94b10bccb7bad8ea2c5a0eb70aec3170079872f6b24fcfee9208a9dceef16323dbf6188e2063e309753a2896936dbd00bc26e934ea0321264f981a6caf4fcfed8da51c25b4f247d7539ac5b9c3dd5efa58bda0d1a7224aa30e9eeefdd02020c5f1f62f460120cb5a6bb9bed4a0db4f40b30f03504cc0630d47f974081f66e65a302e826baa98d194cca00d713f8c416c2a09e3c306d64e45b6a4328f699677c2721fe87f616604f061f0ad0eac7c6564fc7fa96ff8e0efe3ebc615bfe415ec3804ae56056e96c847c99d960e1f3ae01f2c0739215a35ad11f5c6a9f4580ba64d2074ddf8297476db43657773c94ebb
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142661);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id("CVE-2020-26071");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv09807");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vsoln-arbfile-gtsEYxns");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN Software Arbitrary File Creation (cisco-sa-vsoln-arbfile-gtsEYxns)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Software is affected by an arbitrary file creation vulnerability
due to insufficient input validation for specific commands. An authenticated, local attacker can exploit this, by
including crafted arguments to the vulnerable commands, to create or overwrite files, which could result in a denial of
service condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vsoln-arbfile-gtsEYxns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba488803");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv09807");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv09807.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26071");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

vuln_ranges = [
  { 'min_ver':'20.1.0', 'fix_ver':'20.1.2' },
  { 'min_ver':'20.3.0', 'fix_ver':'20.3.1' }
];

# 20.1.12 is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv09807',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
