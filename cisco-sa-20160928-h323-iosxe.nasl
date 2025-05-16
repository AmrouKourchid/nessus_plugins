#TRUSTED 49037d58cb2f5e2d46fc3f4f6bf584d68735970b1d23729f8dc0cead874ff322ab0b4a10dc6c06336d53946a78042bfa374eadd6ebbc351e850e8c5d08f6d2c3006d2173098c5f26e841e3c802572255233df72ddcd6ab328c7e25e87dbda6c6a1760004a3afffe36c4802f1cf4fa27c58f7b4a534c27d8618ef7fcbd94e5acbb7321d46200dbb0dd0ce549a4cf7bd2f215c3559d6166d25a0f17a2c7e33ed282015f9fa2d5799b04bb537dd8bf57179e75abd06b25021a5f9dbd34fee6a821b3d3c57589d59ffe89dca63651949d1d1228da8d363e02a18bd38c00d5393a1104045f3cd42130edef2be354678e2ee72fff7356de2ca8924403ff0566eeab4ca91e6ec2ff5c07dc3c3ee030338e52a565c067e108db2e7fa3092f4ac3525059ae26731e8355b533c566d1c8725bd75f1782cd5b836bc2c05b51abc7eb3b73180eaf534a76a84dc32d343e0baeb6b9f98b6f1c8c3cc55c7e490f26e444c27424ae1bedbcf277e4d7db5eb1957e7dd5b78f6cb828e5a2da7b87116f62db4ac40d7246f24964159892b4b65b1c5de9af3c5770b077a53b13d5c96ab2e6d2f1d2c3c6f6322a3ec7c1147c8e8f6b6532f31848eb9bc52a7ddd645a13b736cb8daebfe0c1f850faa2795166eb31229f065bc664f634d2113f8c23fff1b9a595e34d0a2bb81e3b432d11c1fc5651e7e71d492fa9b16f298673d09257acd7e5ba562cb6f
#TRUST-RSA-SHA256 22a2c1a40f79b5204d674f02c276d8b56914201bb7fd45af3817598ce90c487353c0e6ec289509164080aa502472a40fe046d959f9d442c15a77ac3ffc99bde5a8b6396f9ad9b917b1cbf42eef971cc2993a377e6ed76b2b1bcabdec00babb513892709a6a5b1ca4e17f552efc54ed84d0daec4edb5217133f17fb9521c9f324af2a64f4c1596de8f7ba4fa46e0751844406bfe160c01aa0bc6c827b1adaab1470e33fc060021dd3fd55a0ff337511e8e7f849d59c41a0052fdb2b0bbd44c5889f48acb19317774cd94bee501dce8e591a8f2b8434b7763efdaf0a10dc1e2bc4d529c1dbccc142b6862efd116b769aac2ebc22c387f921b7c74ecfd8d47eeab8a59388bc0df7b46a3bf64039eb4832cb071f40f931356ceacad10eb0e6dd4b3f895a5dd8237aefc1f73b09d70ef81593a2db1e97046f4b6df7cd24e5bd71841952147c90bd553c947b096b584ad65533c2952667fee654b9e50c52a08b0a5592b986e83263540dabd9d223958b5993468a9eb7679ae28cf64ea33b72cbf31afae68fd1c761326c26dd87a96eaebbede6c3baf2fbc9407c168ac8242249641f3c24d7f0345b43ace70335f94121900a694e05118172346c237790ee0ac4817277e3e3c24ed6816810c53034baeea4bfc6c6a81f6df4fb94c002f455061ea891efcabc0373becb48790ebd92f71bf76a6d0bf94f7c453a3d677ed83e912699f772
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130765);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2016-6384");
  script_bugtraq_id(93209);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux04257");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-h323");

  script_name(english:"Cisco IOS XE Software H.323 Message Validation DoS (cisco-sa-20160928-h323)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the H.323 subsystem due
to a failure to properly validate certain fields in an H.323 protocol suite message. An unauthenticated, remote attacker
may exploit this, by sending a malicious message, causing an affected device to attempt to access an invalid memory
region, crash, and restart. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-h323
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b960210");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-56513");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux04257");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCux04257");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6384");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

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
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.0aS',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.1xcS',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.1xbS',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.1cS',
  '3.15.2xbS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.2bS',
  '3.17.0S',
  '16.2.1',
  '3.18.3bSP'
);

workarounds = make_list(CISCO_WORKAROUNDS['h323']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCux04257',
  'cmds'     , make_list('show process cpu')
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_versions:version_list
    );
