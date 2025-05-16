#TRUSTED 99f75bff21b3b32145cb11b88d270545e93f108c78781b665e94b11b1b473281fee6e402818529d228803ad4cdeca7f206aef28ec2343afed5b7a5c20b224e9b86fdb36a44186efa22165b5dc2213eac52fecefe93ae10afa24bc1bb16d51ed83f10ab94f9629ad910a3641930873643a0b4224f01cc01f259f074c88f29545aa0004097970952a0f0e09c7eba7665a0e4a733739ea414d49a57fe6d1e17b2f512339268ed85f134b67316c7b8caf2d2e0ae97e6a4410909b93fced4ba412311ea7a68b86227897ce639c91dccbd22903f5ee463f2651be5bfa9c5d3125e8c5f5b6a696da771a12e6905f455b4bde09d12214e0639419f4efbb84dd06024454f0d7b6e13b3d5c94e9232110d8429ba87c544fdf65c237a7155ecf765ea3deaf6d3219a213d87c7eb18775d564494472d6a15b60ad3e0fff48a61a43d4b6c02d7320bd0044740b670c6d078453e2a785c2d695dbba8a7238891abcb012e6f5de93e85f8eb9ab5294fa80886ce09c6c04a92fa40a8f0ef212fae8727033816443fae09f50bdcc0caef123a2ccc9e0379f4052180157ed4e2a6c2b92b7546ac925a6780e248387ef5f0cc477aa7c264c4ce40b035a565d6636879511e7f7b7bcedecb60e1e571f80c4e772e8c31af27ef527a33d500d937357eab82e686ed9b5af072e865e5bd5e5fcf60b8a5dabaa24ab2b4fb9fb4fa9ad139b2ee027804fb3487
#TRUST-RSA-SHA256 a2355194f79f48ac2f1ae450e4d9cfc5b8d2bf5a20ac6f5db91de134adea834cf7a4096fe14f4fed4ab721b2bb4e772f982d737927506f61981e3fb007dd6df5f587d65d4344728c8432de7b4768d490865534f0cd934efc54fb015b845d6739f56d45e15a69af61fe89478716dd067ebc9ffdabb03625f6faacb8110fbfc129a5033087ec2e6b8c7cdcc82a24df81f00479b576af0ece31d25d7fa353c89c9531fcabb125e3700df40fa91703e6020cccb1a16e54694d46324e96df955557ba7b49332f7e5279239f34a47883ed8a5a320d8834018bc40e5c4deb498cc39f8ebbfcfa1c7c6ff41fad05268d2d1e78da78f70736b674e52b368ab9c191d8612a565fc529c2de198c3ca5229e24a0a7affaa7e153eaf43ce52f7f00157156a76b008e7202599ff205d57fc8b0eef2ce664a559ee81a9d359f075b4e8aad2fe7715bfd128236e7e5d375dd006fbcec0f829f5af700323406b5d9b86bf486ceb9d5effc5317aa15f51273653f7c1d9787fdf5e7f603ab781896e01e14b973845b0576ac98d68fdb24bb70f2ce30b3e3b270f32301af89212160cde28438e54c8febd0c4849e006ad4d60a3ece59369fc6f9186c2fe9b4ba8ab7addceb1d3057247d3b00731e0f8b345662161f85be99d376fad5ac9c49380c0c222ceb7d0f7f8f87223a07e5de562d6159e354c98e2ad724566876a3abaf67d5dddc37a42aa35e5b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132049);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-15377");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi30136");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-pnp-memleak");

  script_name(english:"Cisco IOS XE Software Software Plug and Play Agent Memory Leak(cisco-sa-20180926-pnp-memleak)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a memory leak vulnerability in the Cisco
Network Plug and Play agent due to insufficient input validation. An unauthenticated, remote attacker can exploit this,
by sending invalid data to the Cisco Network Plug and Play agent on an affected device, to cause a memory leak on an
affected device, causing it to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-pnp-memleak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f91b535a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi30136");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvi30136.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

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
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
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
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
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
  '3.18.3SP',
  '3.18.4SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '3.10.0E',
  '3.10.1E',
  '3.10.0cE',
  '3.10.1aE',
  '3.10.1sE'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi30136'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
