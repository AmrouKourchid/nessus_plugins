#TRUSTED 8f92f2e4f6db07312dd2c516670b1fccd2f9facd68b0a43a9b72d32c0fea3c9d84614a2ccbf636351ff4806c5af1025079fbd496bdf53c9e587d9c8d7e8ff37ee9c0a6906171babf3b9846c7da900757f55f2434cd57488064f323a59ecfacb57ff3f772584481e72b4dbab9b0350de84b6b1aee74e80aab51489b66917c3b9cbae79183fe44c805cb52056318f6eda2a144072f16fdb503ea0f6bb02d283ea631eeda8033d26b1b56cc15ff112e4b42fb3316b3062633a5da978576faa65b175a5ec87c1431bae55cdc05f43a8c6bb80277b29a414bf77e39a211a44a772632210996e6c265820581f7e7e8bdfafe93c5ce97ab3250b3d271971d4a2e072f07a6e7ccc525669449e73406524e307440816b1ff2eac1a44f1b76f57c4d51ba8bd99b4507e3c0ae4b25a337d7b9afefed2780966841428c54bd8375784722876dfaf2c83a5c510d26d5a95edc0d947e2dba41c08698bc8519afaafe259a0dcad5d984071ef240d5b7d7b196506458768e175177610e053ad00fd6c7b21d70c759e9b9a88eda519e7323b7e9f2074971b333d5a331a90c7908ac567a16fcad41412577a6277ff1a8b022f745a0119c90d333a87a93bcf910f961c7ca1ae2c9165ecd4662106a8b2d4ed481d47c2d01deec9f7f1cd191829ab088358333b371b1c849b021cbea8c95c9ccbdf712835ae579adf9303a514f04d20d690390597359a6
#TRUST-RSA-SHA256 99dcbc87136137417e8b396e55db353b551d1915c6fd62676f872ab53c344dacba9c4f7ab1a1dcd423701dc23eff1ce777b47d2daaf5ecaf0dcc910c6d91e46692953d502bf2d22cebd5a21b58ee85aac707df957c967592860fe70d31daa7fd224e664ca7061807db994e21419a2621aa1e08fac67f587ed8537287b781a7466d44f6cf7c4dce4bf7057be04032dac52b7e1d81e286d551fa22aa505afb274afdfb0330b441db53f9373533c5752cea96f3893e1dd674f1f5cd1fdc68bec0669679e1e580a1e083040bba719c77a0d2e3a72f85ac16c0adcba5098b386c6a45b539dadcb8ec06fd7d43031c59bf251a490cbd1bb20e2724fded43678851f5eb52645914a91de95e42afe69630a115f9cd9573df9117ce14083898472e56071a0b79e8101ea9bf5155ba61193bdfab5ba973d334a534c6a03959d0870db6c6bc38a6bb20d18af45ca70f50db687de1c2a00afa0e0047535bcbe062f8520d0706dee0a990d594779c7178fb06348062f89651fb5c0dea4de3ad60502215eb267dfd5f078d5ee0a0bd2d5b66157fd06bebf81b31d51adfa52a237e521ca6c5adb582a99b4fcfbefd1a30b7e78bfac32d86663d9379975ffd204ca40404e06ced77d16b4dc40868db98c3a5289e838ca719e6d671dc4b467341aff5605f0ebdbb9c9ded4b1b484d478862ac2f38d8e5924323fa744e76e6508667c9c04ae7255bf4
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148951);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2020-3527");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr37065");
  script_xref(name:"CISCO-SA", value:"cisco-sa-JP-DOS-g5FfGm8y");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco Catalyst 9200 Series Switches Jumbo Frame DoS (cisco-sa-JP-DOS-g5FfGm8y)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service vulnerability due to
insufficient packet size validation. An unauthenticated, remote attacker can exploit this, by sending jumbo frames or
frames larger than the configured MTU size to the management interface of an affected device, to crash the device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-JP-DOS-g5FfGm8y
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e04a5a3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr37065");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr37065");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3527");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];

# Catalyst 9200 Series Switches
#   Catalyst switches don't necessarily have "cat" or "catalyst in model or device_model, but the only
#   things that come up when I attempt to search for "Cisco 9200" are Catalyst devices. Should be safe
#   to just check for 9200 series.
if ((model !~ '92[0-9][0-9]([^0-9]|$)'))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '16.9',  'fix_ver' : '16.9.5'  },
  { 'min_ver' : '16.12', 'fix_ver' : '16.12.3' }
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr37065',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
