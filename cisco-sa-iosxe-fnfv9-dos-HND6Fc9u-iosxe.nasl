#TRUSTED 978a88c0dea0d7b2755fd84af79f59e64deae9441e5e4491a179e749197633a4bb07736fdfff16b6a4482325c36595559bd80195cd46410b5bf7bbd5df1b44bb3e32094f56afca6b3e130342ff562914dd76a57729c3da3dd6b538d2bd4489ab45ddc5b85d435a5d1e91ee84ed3f8dfac6cdbaaab67a29f0c308107bfd020a4fbdd46e706bf9a407514d6def242d252c6f04675795fa13eabb71d4e370ae439cc117aeda363a989847111953d23a54c7c1ba089ad7b0db8b06ef18b99a758a48c4c2bfbadb5b7769d4ae1c2d58cfb9a97b9b033f5536bd96ec90592a22aa1a746a306e96edd0c5a9fad32cecb27a3f9df55533ddacfe8ea76a95f72935adb32c972082af483a3503377863038eabffa4d8647d20807eb5dbbe99c11aad989bb3838e378e2c29147edf19ae73c2d9f4a9999b590f883a0d140ee0c31dd163fa2130e2efe8e20001223ebc72fe589ea9ff8e2e67f4e787f12f058b663c56ecb08220bb6a15ef0c661ea81ced8318994e6a147f3206c68a86e9c47dcd37c6579604a954e87fb615a3b976ce0fa789a81acd6bbd746e4d90ea0385a74159bdf9c29ee34ee6331c7b00d20bf5c07aaea1e1caec6c1652e002ab8c1d398499f955b209c869359c45bb51d9f83a4fb5ff70386a7fe4af4435e2474e186d47a4b84bd386770e80e30361df50067908b9102df968c9510cc31b7678f0496a7f63a963bb31
#TRUST-RSA-SHA256 3fdb8135dee61a653fdae1ef7da3d0921ac628ea6dc2cd061a651d884aedf5180d082630fa1c9bb02a92811c8c302f9ec39c06dcd78e1e9446807d41ffcca1a0e8c09d78fbf990fdb8979368ef597e2771dd92738d72b9f604dd16e4751daa7335f45d14f6f13ea46b0b7904a7fb602f6421e9bc0e11cdbf49b8c5b73f2516193f448349c3c203e078333bd45560550764e7006afd4989f2d75f269a4c52fcff00484f732f59679337b3bc5e62c2dde98eae09e1fa6c5c7eec4790f7e6f7e44c0590f96ca39b49a4a65b90f60c7e9b378bdf6b74ccb4fa9c48747140852e9bd086885b7c7875491954a7503b4219a0dee056f3d5fb19d23772d9f29c0f2f2e8a59140b4fc9865307d75d39f65174cd8ce4806f85fdaf2c13ee907cc3ade2a87fa8b620d7c453f673e943983b0bdfbd0b1bbafc722a5934f56b23582db833314f6851ce443173f221b651de8f1a38ded578df05868592d152cb090f4df27323481ba439bcceab249f515b9ba32bcfe5523b46683979249829de90b0153d8788de9164ac373a7c61c6ffb8543eb713bc75d9e6704c5a4c1fdf9cc2ac56496f9e0c7de1d24d23df682cc5d214719b69bea5af33ae9f60e99aaab0e7b1cb45ff30eb376d6c23751fbb898f6a65307fccad7bdfa775be323669146e6d42cf3bd3441976555e8b154ccf702111d7be3b4398f7907e562ca7fb779d4399627230da9543
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138092);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3221");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo68398");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-fnfv9-dos-HND6Fc9u");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Flexible NetFlow Version 9 DoS (cisco-sa-iosxe-fnfv9-dos-HND6Fc9u)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-iosxe-fnfv9-dos-HND6Fc9u)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a DoS vulnerability. Please see the
included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-fnfv9-dos-HND6Fc9u
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79ae6bc9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo68398");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo68398");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3221");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/device_model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

if (device_model !~ 'cat' || (model !~ '9[35][0-9][0-9]([^0-9]|$)'))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_versions = make_list(
  '16.10.1a',
  '16.10.1b',
  '16.10.1e',
  '16.10.1s',
  '16.10.2',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['section_flow_wireless_profile'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo68398',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
