#TRUSTED 6cb788a55fb3afce49c20758aa36b92d0a975c42d8161bdf0f51d28c2accfecbf99869d67e981457c9a49094579bd764f0252f01fe10d49c450bffb56a4fb6e86dc559c87a6666071606bcbde06254476326a8c15eea1f530213f2fb81ef60dadd68b0fe1b39344be4c6fe20bac7cbbe60f29aaceac400b16fab9d40b54ae7a29d5e98699465e3c923f5672a5d94af7760f041776fe2fd56f1d1357cbe819ee93ab8fa00e42a07021a9c984a6716df7cf06b4c187aab462e41d7dc7380c4b00abe2b6d7e1730cb20c71118a5829b17d9009485184e45097746c2a0dddc13fa149865b7e34c41fe2f0a65310e86b8ab05d1dba893316b16696b1d0e23856728f5677a3cddf048cd750e884c0cbece417b0f5462559707e79f404b901add0e356a4d753a4b87817770fc1beafcc2e686ac4f56a1016b7e23839efd705506c8d4b34ebcc622096be16ce9898887a040f32546d4a6bdddabfbea3c2e90a21f2774ad5b13414ef3e0ad82355e60654ef051b566749d29204cd6e336b87c3da77d0f93fdd8f76ebfa600866b60db031f1e7a0e2558b45454be6d9e22ccf27e1bcaecbbb21ebc44684d358a9be3673d6f4d0e9299ebb8c6337e60078babcdb4beded01a68d6ba8bb089d0974ef444d859aa7e7b81c73f13839620583ae0c510662a0731173ec3c15231074694e532e619334b39511e4c10a80e52e9ac352de9f6415759
#TRUST-RSA-SHA256 8f072b299cfaaf6009bbb679b2334ddc06fcbaa7571be3ed0e70e3f7b8191059ae24c368f50e11980510f6e3d49d405eed2a94cd5501f9032a53324494e36eb583893c3bfa5569767bc5b10a5c04b25b286667acc3f0ec0241a99d57aeed5a216d373e039950167b6d680971794cb475849a2fcd8a454e350cfbee3f3966127a7078c20674a14a3e4f32109f59ebc85841ce5b5c4117ee32d3caad8ed6c5e47b5f38139b63df7aaf48e792e35be2c097473d86c39c58a35a99e28a820f37c790f57c5f7375699fcca2ef573d6ee9cf475e10ccfec2bc70972e03d4547a2390e9dabe3e32705c84e6228b354ec375578ca3c5c615348363532040380f974f89edf938a8b2b99013bb49cc6a80f33805deb36523fca22b22b4bb6e230fa4e073c0063a290416fdd726f11c021844786f16da778a91cd68f9082b9a370215bc4d2f30e4673d6ef4733d560bcff9d5ff77be4c79a66275ecebf6666436ef9b7ace4496cd5122831ddd5323c9c634d6eed48c6396e46e736190d0a046228af43da448bf2be62982cd888fbe2b43282b7c1c415a6f3013473adf5ceaca390c3aac18d1d9d154c0b6d13e4ea9adbbf9615ac20ee51c097b2d05f88ff430e9fffe32e195a7d7c77eee687f97bfae4a279e80a317c4d2e904c93035ff1375bb2e453d47348597237811b75ad6ca9c2c4ed9036a36b669229dd821f345a98f2a79d36fafca
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132039);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2018-0160");
  script_bugtraq_id(103575);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve75818");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-snmp-dos");

  script_name(english:"Cisco IOS XE Software Simple Network Management Protocol Double-Free DoS (cisco-sa-20180328-snmp-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Simple Network Management Protocol (SNMP) subsystem  due to improper management of memory resources, referred to as
a double free. An authenticated, remote attacker can exploit this vulnerability by sending crafted SNMP packets to an
affected device in order to cause the affected device to reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-snmp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b77f9f4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve75818");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCve75818.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0160");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.4.1',
  '16.4.2',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '3.18.0aS',
  '3.18.1S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.2aSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '16.6.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['snmp']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCve75818',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
