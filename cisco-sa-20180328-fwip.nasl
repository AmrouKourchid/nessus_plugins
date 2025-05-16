#TRUSTED 03984debf67baeec1b8f37a76fb14f86d465c4fc3dfb597b1e0d3204fe3245c5ac8a332b9632a3108bb11c9eddced4578900fb0e974492b9072cc5fe184960746a5f371073590850f215809812e07e989dbc31e567278b70015c0c6b4ebcb2e84db8d582554ee4f3aaf9be57bcd8e5add2b1f44d2db00c54b410493d8291cc27ce9ff00d165d7e1bd058ee419c92a1edb7e429615554333dcbe2dfb3a2041e183d0e586f3566a7cf1270cf3f9d2c080a554b531a339c0d787a838cba27c11b998931e11350e62dd65d190ba5971e14ead151fd4772aead0de0b5792e91c20d746fd0cf8868d32733b5ae5bbc050b91d128cb164964beb6e37a47483c903029227d4308c0f68138f95237f43a9d81720ff5ea6d37726e5759108b482ec2a80ba95cc2dd643ff88629595b5f1c4a7faa8e7abe838e616485f936513f9c8c17b7d43251027c3384a6c6ef81c370b628bb37ee8656815a6e9554958f88f23fce72e41f3e91ab163f65d58895a243632bc949c0591fb76cc72df66728786aff2b1a8529657e0fe418599d3a8a9f005a3ccd518d0556c63982511829c040cdec27b047eff2423b5b0d632ea6ad21ca2cae8c502583b40703c23128f88bf92fb0af878da6ef398c29ffb8d844c98eb619ad8c3551e3021c434e3cb47952e23cfc362e6ae9078ddbd677a13b5431ded32e23a414e9a3b36fb501ee789145ad371e5fa146
#TRUST-RSA-SHA256 ac74dcbfd86829bb75d61b3fa3bda90f7f23340dbf2f8ab8eb32248c8b79daf3ffd40637777c83a8c694b05055d67b4f1168ffb1680446c491f5f295458514db11b324550ec538e88b00cee0067ce794c96fe41d9c655c7a673321c1b8dbf0e217443c4326b4d68444ca46ff360bf8e625e8900aee1563e289b54a833d3997f5f290d35e3524a3786e7febc4648438a7faaa6e581cb03640c169599d247016e7cd234b4f56e802ec616002b79e38a5178f9ff2b2f4099d236426d07c43a6369c1d87b73d3afcb865cdc5caa9a91fef4d0938dbbaea2f55469e85f5331f122b7f399fc87462a703e6e9de8ccff4db8744c29a6426f01a28226da832b610feed073f712132806413cc783928aab973ab17eb4993df82180ba195186c426e601eadeff6b9df08518fa2d415537bb68ae6027a46c991c642938b1eeaa98babe9c24deaa7fd94745da74d9da104b38e3d597281fc2e79899432e81967f6904e92b377117ad334be58900bbb38117d7cf32af4d6af6cc1963f315ca926c62c4f7317cf57cae0e11cffc651d3bd6db89bc9cf79913952693f2f983739587a0f4bbbab37e58adf97f6973a0c068ee8c23e4a3d19e7820e2e236f3b495ad6be438437201468cb8d785c177ed15f422817a9fb1231dc3c629ee2868f4e6d0187c87e75ecd94ae9da76ab514ba33ebfc2d91411024af691dfd9305136562b17b012a8b1fe32
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131130);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0157");
  script_bugtraq_id(103561);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf60296");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-fwip");

  script_name(english:"Cisco IOS XE Software Zone-Based Firewall IP Fragmentation DoS (cisco-sa-20180328-fwip)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the Zone-Based
Firewall due to the way fragmented packets in the firewall code. An unauthenticated, remote attacker can exploit this
by sending fragmented IP Version 4 or IP Version 6 packets through an affected device, causing the device to crash.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-fwip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcf72e32");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf60296");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvf60296");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0157");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/20");

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

version_list=make_list(
  '16.4.1',
  '16.4.2',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.6.1',
  '16.9.3s'
);

workarounds = make_list(CISCO_WORKAROUNDS['iosxe_zone_security']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvf60296',
  'cmds'     , make_list('show zone security')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
