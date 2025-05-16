#TRUSTED 6c4f22fb49830274cc4e4de7b28c21d821b22377edeec45f4a5ab9f3268d560e1f2297bb0e33ece533078f15f1f51da14c18da598530d8253bb6016cf32644d9c78685ca2b6180e051372e2b9043c77177b28ddfde8ee81f3c398724950c07a34a2b1a7ab37aaa4b237c81776820c1db62425289fa2c9085c655a7ad48f540af7a236fd4f5aa85c54007e3fc556d415112fe16acfd285d6ccf674c60bcf948efbcd3eac91d7f4b4e8e3b85a0ac62f783ad36c02a56df2758fe8f9e311a10c5f55fccccf9a7e7e81288d8b9f2c83f2145df5e1d958f49a44b5d1248d383cd55c36dd74e7859d019d3d921e208d6f88dd43ad753c48131e41a54cfbea530ed6d7b72bb407f65dcc80749ea1040402933523a74cc8e270c442d688d07837b337f0489b13539f048fdc2c0db14374a22bd8bf3e84c9a7276c61f551fe836456c513fa571bdd97c3d4c714172eb2e74553a85d6595423fcd4ebe78c69aa13af927b6e251153fbde15366f30ac499b5ae9dfff87ebf99727d8c383b10217c2ad2546ed5716a5258e18cc52371215a440c2d15147034730ef131e6e21088088a7a959aa409378cb029cb7ef2d45f6dd8ee573c439772934908b58f15a6a5dbce9d4be2a3bac4f4ef15d1f984697d6df52d92d8ed3b7e8f68ce3ad51c77525f3394bd1325395aba8595f99086795afb285d160ed206e9812067ed200bb39f6519edd5753
#TRUST-RSA-SHA256 287397513247165b275e3577808058655fb6697d6cbc76afa4da481ff6439793498293d7ed4c67dba139183d74a9f220f0804764c3d0ad625442c09c238a694512cb8bd317b7e946b12bc6ce277606a6891d5061307fbcd8d77c5ffbe76604334de6577ea309585444d7e4b730a042902eb6e5b04af406548f79e6291016fd0844770878e20eebc471a46fe27b7e53e41fcfb2a2e68c998d40ac0fd81253bb1c06edc18edff2d2b3f68d7e34f5abb998fb8e6622e227ec90fa6424157985e7f3a7e47226e2ff4979f58f7b735b593b17796da5c8986bf571b9c841f7b812ac82275a027c36e12c9b025b209ab973cebde5803bc7208693579b41dd8c955419737bbbbc0fcf0b80bd323cf6b3fd8c5cccca0228ae66b3aa1c9bdc7ffe855366818c2eafc31cb838ee9cfdc8d0cc2c48c8abf1fefb71a7c02245a57e72550d1fbefd0362874202511692c358b38c81917880f70b3f1c5cfc0e5ccad859e8c205a5809ad82f723eb701ca67e4523b9aa5896c1b4ad2b976373e239e609b9e879d380d06a3b427db6f4803518b7fc3c2522418b16e8fd3d85cf003e22514ff696580903f87704173397d91d50ce2211b2b19de49db9c8b41dc400b1b2f93319425b53a260852e9e2257b995002b0fd99eb63107bfd6fa1ed0ce305f507f638f7c3db2c06cee5a9f34f8f31e033cbe49f81fb2ae0cd5ebccfe2f8359ba277e340663c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131703);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0315");
  script_bugtraq_id(104410);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi25380");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180606-aaa");

  script_name(english:"Cisco IOS XE Software Authentication, Authorization, and Accounting Login Authentication RCE (cisco-sa-20180606-aaa)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a remote code execution vulnerability in
the authentication, authorization, and accounting (AAA) security services due to incorrect memory operations that the
affected software performs when the software parses a username during login authentication. An unauthenticated, remote
attacker can exploit this, by attempting to authenticate to an affected device, in order to execute arbitrary code or
cause the device to reload and stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-aaa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47fc6762");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi25380");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvi25380.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

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
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.8.1',
  '16.8.1a',
  '16.8.1b'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['aaa_authentication_login'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi25380',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
