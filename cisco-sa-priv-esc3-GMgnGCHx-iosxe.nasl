#TRUSTED a53b0a4065fc83df8b833358241c6c0f65f5333479908c4f05bb44891a4e2bc897467d19f22142c2e4e52a593e5e8959a420b087b5e2454f57d34843b3c5fae48e85a0fdf43c26dc41885479982ebc44dea09d4905b97fe18c261dec536f6fa76416231f1cee4cfc545d552103576495745fbfe73ab841bafde5fa1815fc80fd559c460f40a63f8f25fea6b9cdb015dc507341d47614217adbf17c48247a74d2b5af778d9ea99acc2e1ed05acd32a4f56ba24515aac04352df90aceb45cd9da718b1d94a432f45537b258eeeac4b4b0cc184dfdcf26b9e50cd7bbf0fb97315d7d54cbf52434cf189dbb25817294a15c3b531d8c56338a2336985855ad2f524587e0a31a049a38082135f3fa99707368dc4545c4953478b4d107f59fb98a532a052c84acd0d7b829cc265c9a82c261d01ef3768cd6dfd86be250cc4d3c315db3e893bdd7379e35dc3cb2263d2be20d5984ef497e57312dce592d6bd0c5163a6c54b5f833721493f8aba60e02687f36ef70455628759a30a9b60a803512d46fd18a83146784b93b8c9ed33639926edec95e27d2ff3c79f0e3dd9eab79533cf7a66b814ee109d5b723e32e39c5e624daf5a1467e2d501b0cfa6c7b279e09fd39736b616cef257cd3e1de8cdf74027c364c4766ca6507ad1b59a6cb9da39772ec68202e82bd798bd06868820a97eee007d27f582aeafab8f1fc9e24031d56a4f80a8
#TRUST-RSA-SHA256 2581f08954d20e4100b85856fa96cb78b0100a9054785ab6322f9bb26e9a31157b7022f5f44eca1de66ec746e605c8472ddab393286144194003a1e6c42a15e33433bd980c7acbffad1f3cdc8831cbcee219cd39c7aecb271c1a93b3862b28b914391316e6fd9529ede4ea98a07b0a24ffbadfb68862b1529a62066ae0c41ef699dbc45a60bdc15452a8083a17d5ddfa392a14262b0a088ad09be714eae4a04c9d9fdbdaff5802853071791a47b4671c8db31b2c685e866f01343cf913c04293311e3f0ed30e1d629765149aaf488622d030a4e8c657c862c98e34ce945bca32175d21731c588e7bfeee7e4d36dc61f2b037bccc7e750d7b7e87d4143c90526397050cf86a8ac0f6f00c1103a03793090727b2ce1c680dc9715eca3effd3f790e38438036dbfca4181c205b277edaed7ade3e3d549a94502346b5ff3d9e65ce062b3b485115fbf31de0ca57189ebdd6e5b1b98b215461833f19e1d750f210263be7a78f5087274f80fbc23ac7b33c31a2d078d0ef6144a684f13e363badbc34eee0cc5037df8264bfe03f352947642b23ddb2609775af588be5126bb9ad3276bccedf23cd2d02e5b96b62ff219b3d443ac963ad6d1829a15e5057a0e9d088f6f4e7680ccf316deb2c7b141852b766375e97e56cc95fdf96a3ce7c1266126795cb6e15780b8804098193c7d76f9c43a831120dc1a0300885a717997fe23ca942d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137332);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3213");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq26065");
  script_xref(name:"CISCO-SA", value:"cisco-sa-priv-esc3-GMgnGCHx");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Privilege Escalation (cisco-sa-priv-esc3-GMgnGCHx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a privilege escalation vulnerability.
A vulnerability in the ROMMON of Cisco IOS XE Software could allow an authenticated, local attacker to elevate
privileges to those of the root user of the underlying operating system.

 Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-priv-esc3-GMgnGCHx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f6ce1dd");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq26065");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq26065");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2S',
  '3.9.1aS',
  '3.9.1S',
  '3.9.0aS',
  '3.9.0S',
  '3.8.2S',
  '3.8.1S',
  '3.8.0S',
  '3.18.8SP',
  '3.18.7SP',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.10S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.1S',
  '3.10.10S',
  '3.10.0S',
  '16.9.4c',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1',
  '16.6.7a',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.9',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.2',
  '16.10.1s',
  '16.10.1e',
  '16.10.1b',
  '16.10.1a',
  '16.10.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq26065',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
