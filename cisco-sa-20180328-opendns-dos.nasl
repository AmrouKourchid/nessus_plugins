#TRUSTED 71511c55411b951385ee8d45bd65fa95759713f1b1fdf64307c2336cfb2c1372e1c54920ef82a79f2b121f07a21351e26e300b7d3ee0876519f5bd461aca1d2f9273c3cb39c4bc038eefce5433516698b675279001ddb2b7617805a39f99c438c8bbd6e5f87b200d7da3bb60d24148880d4b1038e929278773e1b4796b447e94b4fd9c98c7119b0d6e10b4c96dc08451160e69f1dd4aa0f4a7e44f48080ba9d2146b044446b9c996bd25c397fe262863050fc123b3529a115679514263a416cc5e72a346fb133ba8aaf266f3cb95a2594276e257b7a37c35d52f4aeb1311fbd68b23e9adb8fbc6809bee77a7851a9a205828627f139f211a928f54ae9cf403bdc86415972900d6fdcc6255c1dc127cd24e9fc035f68e49a330cb20fea56c1cf85f259ffa99612e35cdea90cd8e6844e180a270cc92e27c7c5025b2f2b5c184aff3a7040a3ca44adcff65281fde98cb9f1f5d383e323fd850f672bbc97466b8f8f25fd7e8bd93881fd15d2525b487a44e10a83f0a9f0712f18584edc54facb2f648ff4ef9da4d87c39f149fa6f4ff188cdec5cd58b0f835baa559ae9852aa44c2a99b59e6f32dc7fe33183c9216943028250fbb17bc9bd7fff9475d4a4967f6e8d19aa1d24e9ca1e73dbc8f7326d760de0334246183265fe987c7161b905b2becc7dbc21df825680e1b869a2780caf6a5c51787058d2706dad50f5658c2d4ac0b
#TRUST-RSA-SHA256 031a57d609a1f2b29686f3e84a93f0f6b3f92fbe45955b0ab7221e262d6d81fc89a98491c2164e27ae08076fff0a7ccd9965ee06109043cc94dc95e4a621e39ea62f7c45858e7f2fc373f592fd9e0e27943617d7d0d6046c32693fc58771957e8e6c5cb0a80c9088044daf7a37b13ad4fedd03feee7943414136076b267306c4b46404e63007b47687f8ede5bddef8396f75ff7ee20433381359057b4b5fe8cebafae0f06cf5baf956e56c1785a4e67c12381fed0a6d508830b86c0ad69b75ab90d1b5facb6b2b772571dfcfde7a1387ac551e7b0a89217e80e60a3969995fd1f8e42b3dfff369b03ffcbfe6f1b8d4e115e45ba8ce167ce8a46a49d8b5fcf9ecaea93d8265a30b47c1d7e5c92a01acdd68cdc105cc7ee3dbecd52e55f91a331b4ef2d80a3ff87ff8a0ad8c4425967ec86f334cd9b2dc09da16b3c0f5c54625ddbadc1e75c3c2dd06dd33a9af150e03268fc449ade469ccdbaee94c7d84e6c44cc4c3ec86f1730fa3aac400bd8a3a85c66e2ad380c1f1860b1f1a1990d4a73c31e5c89ab19b2d1e58e997d7b5fa19246247d5c8f4da6254454fc0de3a40dab959c9da1a50d35e968792372ee60c63e06c7b9032f7a99ef9c6c68fd9b201f26dd5ca9e9614978462959cce12eab3808d031429faafc0166f81e22d1fb6ef992e4ec2bb0de66a45f4e6aed35521c1b8e23bfbdabc087cee924a0e8221fc4f26df72
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131397);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0170");
  script_bugtraq_id(103560);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb86327");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-opendns-dos");

  script_name(english:"Cisco IOS XE Software with Cisco Umbrella Integration DoS (cisco-sa-20180328-opendns-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Cisco Umbrella Integration feature due to a logic error that exists when handling a malformed incoming packet,
leading to access to an internal data structure after it has been freed. An unauthenticated, remote attacker can exploit
this by sending crafted, malformed IP packets to an affected device in order to cause the device to reload and stop
responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-opendns-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc4bc5a8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb86327");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvb86327.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0170");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/29");

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
  '3.2.0JA',
  '16.3.1',
  '16.3.2',
  '16.3.1a'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['umbrella_integration'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvb86327',
  'cmds'     , make_list('show opendns config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
