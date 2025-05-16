#TRUSTED 9ab0ef9dac00919d0dda5b67aa12d63ca957e7ee84f5b5a8b21076d671ee935d61a1d4a306560d2695a223f2d21ad270795112e8b6c16594cb3c6b4a4b0b0af61fdc7327197783db71f70dc47911ea15529fabcae5009e6826a5e8738ef308a20ff10952f7ea7834224a97aaaa48c0a08ca86ca8ffd186056eae4e1f591b178d735dd91829ddf11e5c09a3716ea474ed545f8996beedc9ac40f8792fde6dd8297a43315eecdf9c89cf1ff2eec5fb387037b671f305ee693187cafd7447f442612774ab982d83ee82cb360847d8742d081cac85751c794f933b0bfb5c0b51431040db31766144e55ba9aae4d87f19503c81883207d054d0a66cf74d9a3241c8ab0d9b1e345b7f0137613fcf6758bfb7cf52a0864c42fe8d24f62785eaedb34b3825954124eb2a92d7e5bc874cb86ece6b0483f3cff055e56ebb3ffcfbdfc698b5ad4bbf64263347f89c727e9750a36feeac70dff779e7bd794848a29f2fcbd7af6b2a7d8e4ed0d7ca046e439093fd96708d6c483aaf5b352e278ac348a7043f843d8480a9bfbb839b08eaee0ae8ee0646883a6f1827974fe0b786420ab7b490f6fcd4c7f67685a5f1990901870ed302e6a820745d9520112dbec618d15c1a91bd3629dce5c475dbb532056a53ecc0851f1105ed3a5a08b686d0d23f75c8d45bff36dd8673137756207e35473eac28b228905e6bcc896dd0fc3d1ed7380b1d83f2
#TRUST-RSA-SHA256 7cc7c1cbd0a49e3584eef2d22d9f949e075d31ebf7bc967d468f83e210d0f6267f499ea2e99d0c704c0f69cd1a3be7986b1f1da19754f64d90ff53122835656b9e0526b1217f385b37bdfbae1ce0c186811412fd451f407f50e8844280016186949c8f69fc145311e7217d19168697e876be7b32325621f87c25bcf3cde8c941d843386d604f35e2683deb06f364ecbe64449cef4313a5ac370ea00261e40a8f74a84bce6016f431100fc6db6b18f707ca099262464ab768fd9484aa28abed486034f9dd1fc383f70a7f5bf33090015514df6b8f5944d1de911f3e23c4419fc287874d30e53d95925a39483ff6ac649d7554ecedd55d3be3d8a437c3d8a2e78b663519e6cfef6125ad4aaceb8685055dc21cf78c4ca606657866b532209e2cfb148940ff7784a3ca0bfe5cc749b6ae29cf48e39d796bf2136467f8225b3b198d8ba139b65f086038874b8c16ce6a00bf599827f34276f660b27444a15b4755f32fcfb9660c14da3cadf0f2589f29925b65acb717701da8c4aebd504bb14a9bcfdb0b2af890b76e11a3685af641f43c763a712f1c44d7f8114d20cf1b374820ff24528b4cdac5826c0d84a04cc89eff931f4496118f3ebc67eec2f977e8d0284da47748074629e9ba8fffcf1d411021856e084d7579f0dbafa4191133f29efe0650f23f708812fe57b960f9ff4f3d7ea45283efe5360031477d07cae39f85f3df
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129533);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12650", "CVE-2019-12651");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo61821");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp78858");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp95724");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-webui-cmd-injection");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection Vulnerabilities");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by multiple vulnerabilities.
Please see theincluded Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-webui-cmd-injection
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f43db2c3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo61821");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp78858");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp95724");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvo61821, CSCvp78858, CSCvp95724");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '17.2.1',
  '17.3.1',
  '17.4.1',
  '17.5.1',
  '17.6.1',
  '3.2.0JA'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'cmds' , make_list('show running-config'),
'bug_id'   , 'CSCvo61821, CSCvp78858, CSCvp95724'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
