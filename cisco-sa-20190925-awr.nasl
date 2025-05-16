#TRUSTED 6111f71cdfb418960698bc49a0b4a72bd08df7725ee35cc808e8a42cccd180ade71b26784ba295f4497d68adfe3524e8f6f07fdf4803b88b1ea2ea90bc0e101e436553e56c378407338b3b41298228ebff45590e00624bd848bdbae78b1410dc4586a35e9a62813fba00104c58e96f6aef58c6c9ad9f8c0131961206af7d647f63885b99f57efda70c805333fce294b4c3468839ab1df8d2dd1f7bb00b20ac295f5c0ffbba92def0de2f2a4ff40ccfc87c9bfec433c1b546cd0b07d607b79c0b064a889aa92f66a7641aed3ecb561e9319e0cd2c5566cc8a04e7acbc887247c29b42faa8f6940c7af4f571dee48878f8e92ea15e7197bfa8bc00f344d62044a52c1942f3e7753f9751c6550bfef9be37eebb4170a1d445ede8f13ee5d86608df876ed3c71cf8ab50f4209c167b36b0a32dc8b50ce58314d442cecd8aa970818fde49e6fb1c44faa48430312168f5fa126fad2383fe7042a74fdc4ab45fadbcd4df0127415f82a09254baaf23ab69a05b2e04874f7dff1328719a3d55531518cf00d7cf128d43fcf040ce9f752de08ad87bfa8d92064e34917754dd3cca299f844bbb55f70bd95d62541e29dd330cd847d67784ebb97b6d905e1635513630aeb7fe515057c5151f5a38dae3b8e74fba7fc7eadabf26bf28dcc392e7178f703ed17f6d768126a56a01a1aae4d16afb4d1af6a65234473494d91e8c676aff38d552
#TRUST-RSA-SHA256 600bd963445624bec6b130ddb1cf7c34551b9fbcae87171d6adff19b2febc3e6f57b37aca21a12988655a8273cea3b5e77ce16f7ab046f77d3dfca63c5dca06af076c370772c8d87c3cacf8d61c4c8cdb3993e0a01be72a8123f56e9265e9d5e45c6003bea8943f0f1e6b2c18454606ad4381435ca58a6faef376ff4cb1d5de93a50d8ef28a3815432ebe511fe3340d60dc4034fd974a27d1d11d822ac8a728ce7ca46faa104336dd186a6491f129dd1404f05e5fc0642cd2efaee49eb2e2fcd7c33e3e590760c3c0856bbd47a307081025db32fd2ee568b372d49630b711c2fd8c1a29951935777db1913f61244929adb32e8ef301621175f4ec9167c7875a86872ef9383d3855293413eaef392542c4608015bb15f951e2d4c0d7ed8c1deba528a1a78be89a59b2eda0d44854a90c5193d5121dab1cb7a7ce55f379e4225410ba6b34fd92718af2f92eb174cc28a1829c398dc5a0857d6bf5c660bc31b0c059b105c15cb30a4fde7a864e78ff36eca5468a3489ffb114f839fd0503656dd63b6ca633af020aae970adfc2200c94d22a959f41b6830489a1f594575078bfbd711bc6c0a9f07aaf968ce70b3db989cc578f086c96aa3eb9121af39278cf49558051dbabc3af99337a23fd85b1b277e1a76d8a9fcfba5bb4a98cbdd3dafca9e123c6e87250f53ae47731edf588898cedc2415abdf89d4d6a412a7b4a6c00ec2c8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129536);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12660");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj14070");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-awr");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software ASIC Register Write Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability. The vulnerability
allows an authenticated, local attacker to write values to the underlying memory of an affected device. The
vulnerability is due to improper input validation and authorization of specific commands that a user can execute
within the CLI. An attacker could exploit this vulnerability by authenticating to an affected device and issuing a
specific set of commands. A successful exploit could allow the attacker to modify the configuration of the device to
cause it to be non-secure and abnormally functioning. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-awr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c9e2875");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj14070");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj14070");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(668);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  '3.2.11aSG',
  '3.2.0JA',
  '16.9.3s',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
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
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvj14070'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
