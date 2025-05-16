#TRUSTED 4ce1e32915f616d4e9d3d4a72bcd348e3bb9dd3f018afe4a1775e74be1f1c9f70e32e4b6cc9ab56ad3f39f724878498fc2bc3e1700181359efc56bab1cd03299a3be9a16d13aedae1c1b5ce11de6dacec93a443a35dcca0fbcab39cf03892e45d50db4215428b0b2ad537a1baf0b2d04e190b9c7b71ea273bd164337683151cc94bd596b5f3f39463428d5fb0ca22da33c9d96b1d0d83f50665b4b6655ef38ac97ad282c02c9651900d424e48ade2595947353a19771e293799c3a0aa214e8758e493c928ae8326a44724a8456ade3d96ebe5809c00fcfbdff3c3ba96c560a70e310a69a88d61b52e8823316514a8e9b805f7ffc8eedc4d3938d492b95aa93731e683f6d7e9a337a5a204f4db083db51b42f3a7302127034d52db825293631fb9ae7052d9b2a369324967738a00bde7c5f1cb303604eaad2d8f6b782ae947ba416a6e6b80d6da67204df918413409714353438b886cc5f08f76c26e1173cef717ed676713baeeb6803784f2e844ec66fa3c14f0a081fb6067b9ab4ff57b1e8b8ad92755d481d3aae775ce234c43d436a3cdcb4b2118bbedade266b289e52d1d8ac4fb3c4d4a55d241413b68fb78e695c2c270b26177457dff2f931f6b4a8528d554b207530e345b3b90a005badfaabccafa6bd885e956efe1959750cfcd30db2816ed819254ed24d6dff6554186624409e9c521d17910b879a15c75a67a2a297
#TRUST-RSA-SHA256 73810781a87899052ff12857832abe8c7fdcf73c1fd0391183eb88f678342bb7cd9e29915b39e3fb3a2c62cbf2fcd0c05538ec44ffe4d50dc3ca0ef6770ebb8332e0f52ed95eab405058c508b54a03f3af64e89f6f8c7c42f532fed9df87f5edfc6a6c1bd374866e1df1a03f3e15b1837e8c6348e1077614995870538683507804002bc2e68ab57ac74800a5f515a4941f6660828ede079082147e591ed7304ab12579f6c5ddc172b109deb5e1016c21f444dd7090dd6291ee66196b52eaf49cd00212f78590d854d16615a7ca0752740d198899050635dbf6b272417b5cdc9163e5028f70664f64f49851594a29ca83955b811b364a7ff5e5b544dd4f2794b83b587a6e77dbe6c72225b4429485fba3fe947016d2232e0056b1fc8fdadb727b4c64dbfd8e4a718b3eeef53a6f206016afb37757a7ee0934c83f5e36eff1d41eba29a7b61f6dd725613876b6240b81af64fcbffeaf66ba406c6fb5784fd1d923a6e5692b1caf8523eee88ea3943d614ed20e07de019fd76d9c5437a31a3e55bdc7d4e135ee7852bb090c573ad7fbc095c82ab008095ea569c5700eb79b87afb11f8a2dba472ab4e83fe5d3ccd71874824a285f7d29821c64187c9e862e107280870509ca71fd790b64228c68dd59333556070381653f3bc1d75c6f93c7ff730539a2a51ed2f77f9342a9fca52976f4146d4a7c6f6718377ad9b4f2beed38c239
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131326);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0158");
  script_bugtraq_id(103566);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf22394");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-ike");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS XE Software Internet Key Exchange Memory Leak (cisco-sa-20180328-ike)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Internet Key Exchange Version 2 (IKEv2) module due to incorrect processing of certain IKEv2 packets. An
unauthenticated, remote attacker can exploit this, by sending crafted IKEv2 packets to an affected device, in order to
cause a memory leak or a reload of an affected device, leading to a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c962b883");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf22394");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvf22394.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0158");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.5aS',
  '3.16.5bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.4.1',
  '16.4.2',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.2aSP',
  '3.18.1iSP',
  '3.18.3bSP',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0cE'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_udp_ike'],CISCO_WORKAROUNDS['show_ip_sock_ike']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvf22394',
  'cmds'     , make_list('show udp', 'show ip sockets')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
