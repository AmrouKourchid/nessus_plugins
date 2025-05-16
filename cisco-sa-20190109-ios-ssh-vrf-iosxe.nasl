#TRUSTED 9cc0d32fb84a3777d5146188e5ebc17428d5f30d12cecd1606b8b254556e54cbca6f662134af6634f675875be11c71b247cca1ecfd7db2af786f8c2854ded03005ba6d9e29723cec426f4f5f0aacc8e95995b845086a5e6f8be0fbfb5bc3a92386072a20b5fc3f275c8d7cb78f953827f39822a2577715acd82ed5330089b9f2db965d85e4dc7f67015ac1953a8c307824d6898273009d2344da53f0e33c6a717a273eaae77824d29930621035c756e919922e6b794bd47d133be2091a9a91cae2cdb10bd8d71583fe9de9a84cae6904099b701b1f9cea42bd26a33aec1dc3df8b843a14f959ef42288406ccbc94696cc598ad1d1f024ba6ee56a4ac4c972ed11ed32b591456085c599ff55ad0e1a17eaa96a0dbffcfa785a0fee04e1f2b7e32c7b4b1f9af82d5f80243f57971d76b989b2f10b89c53ba8f326f133dcdd1db058a46deff8982aa9f5ffd112c9f8926c903f063acb3ffe0d7b09c1dce0c4e299baf33d72b5589bd859318d44fd30559e16a650134baac8cd713ab68a1e29e3a9e8c46f71f81bfa4ec73fe65ae6d0e3c0c25339cb04d80e2c024113d80ed0582d7e89d96faaf711115e4ce9b30dc30722d2f0c1eba9272ccb78acac490594e2af257ab35d4a5e00dbed4bd8b483c1ac0b4ecf6ba54fded3c44bb73729dd24118711b1fa220b6ae567b315bf4a939f132f6cb1e034e20dbde67ff71e22ea46c526c
#TRUST-RSA-SHA256 6c939efe82ea575f4752b7659e8e94e8c0eb7f85a5fd2817c46adbc44db30c387289276341a30022d4340ad1ff66d7da21e199fb939510d3bd05c3ee602ede68bb29756647219c135eba81203b8d401c3cb207624d9252d33c7292f683beecfd407be3f35b434df9f3ad9a357e17736462a2fd2765ebe0776f53905a1d854b6705f86e26b23ea51d77138dc63dd40cbe960d6f94eba16ce012f9eb2b5578b2fc09d4617b7b72d3b8dd78b0c50b5b78ff868c2ff487b50944047cb956fbad8a79d2e1ebe7bdde5ee3eaaaa61e7317fb785e3be34c70b8484281570098a0fef48146ee3fd4c0bc1db55b7ce1c0dbde4d958fa83c12b4c05748ab31293c0da239d23a5e0f1d64e73ba60f37ab88f423e9e0db001c705b7e4419f4c6eceb6cf80fe79c846d18b6c20f5188ed0681386442620faa42499f1ff5c9d442eeea54d981b654b388e6940da83a512f875a34c05aeb8814fde41b814f1edcbdf1d9130d9744cf556dc60d144d8793afc66d8258b3df42cb565eddf6c61f6d866b251394d3a9c7270a09055c5cc7f0a4c828599060725c9c3189be70f525d21da7fb13fee3cf5fce391be5dda6fb3e0e7b2051f9474fd8bbe42d6c90a31ce5a5184c4dd403c0f27826ec15c07d0c4a0ff8ffab128cc89f5247c5292dd555b4ad89d505ba84dc080d371d8e0ace3d1aa7dcc513ae137b9bc0086c8bc7107caa9d00318ad971f1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131728);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0484");
  script_bugtraq_id(106560);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk37852");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190109-ios-ssh-vrf");

  script_name(english:"Cisco IOS XE Software Secure Shell Connection on VRF (cisco-sa-20190109-ios-ssh-vrf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the access control
logic of the Secure Shell (SSH) server due to a missing check in the SSH server. An authenticated, remote attacker can
exploit this, by providing valid credentials to access a device in order to open an SSH connection to an affected
device with a source address belonging to a VRF instance, despite the absence of the 'vrf-also' keyword in the
access-class configuration.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-ios-ssh-vrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efbc26fd");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk37852");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvk37852.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0484");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

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
  '3.18.3bSP',
  '16.6.3',
  '16.6.4',
  '16.6.4s',
  '16.6.4a'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk37852'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
