#TRUSTED 121cd4ec7744044c79e96e4df1cf09f3e6127abe619819b3a3b383032fdfc16cf54fb7d31460238bc7be3b89717fe12e115cac3ec2fef58d6a6b0e942017991195f00fc871d7a67954ef88a70fbd5ab017fe66b73e83dcf44d1ebe6abc65016984d5dc3b00fd9dfb75efd4da10ff61776861833fba9175be354277ae9606860b2d2e5dbae047d1e5beaf8f47963d6050bdb9faa7ad5aa26078ac8f4b5b3c83a11a5e2c03fd4f6290a99a5b1a02f987f5ffeebb778add61f39ea46edaeb39ddd5228692d076a5ec606393c73e704851b5ff19c97776ed73344291d4f9d5b2ab7ab6807cc7b92fdb982ae5511a24e8e41b0e3dea18bd357d7c9b56519cfb1127eccb196638ab6f5938313a6f96e35c31bfdb7ddd3806202e6167f9219379a0ea4afb72f032cbda4e75c7492bffcf88bcbccaef6fd588be750f8cc14674746e0e0d10dd170b088fd48cf1512cee37f4c487c3649092c53aefa9ef8e4d41b9c1eeacd90569e93624cf31be40ba3763af34f44abdd5d4bf5d3641ce74440692c4d50c34d426716e6649bd322fbc0ac502bc4f7bd210bb24b1aeda685c2f24ecfddf2c0a0529c84b0693312aaca32bd9b6e7b2613d054ab12b04beabfecf25bf3fde56946e9125898b7f18002266ed1f4123b9cd3ff56f23a85546e9c0f68ce329faca959a66405ac1a2750db6b0d04c9954df1326ff15a7d23d2dbcecd52ee1f72741
#TRUST-RSA-SHA256 82048d264ea5a66a66ef2a67a0f43ef1736874223df0bc80c1af65a164c54cf3479ec21e31c3d9d1b84cc68d1aab7364cbb115d5a24538604aa3a754704639eb8e06b5765cd8a71c64e55d9bc340f84c4cf9e996f25b6f96e09574bffbf4e545e16bdd98306d30a16fabd0b4d7a232f3ad38076f555a252cf761c91afca2186d0b5c2f7b37158b52a6ad881408eb6e1f7d4fd4b63a4b2d91c8082b4d548141d58b13080ca762b398ae1c9d4d11e00b985ad5e643b180d608d498eff841b0843876bfb62a19ce651692d7cc141fbaebf4d23bb3530994cfcf23c2eb62c9a35f13215643f53f41046cb8f5604ea7f021e931eb588d0ab0c96ed8c9b853982a16b6bf6b9d2b1f3bf93e29fb1ecd24c7d3393a3548d963174829567f542d9a3dd0666021160f5b81196d9010601aac92465693c721c6b2371cb9d33360cc01b68bd63d1e00398ee84a03a061ffe95820c6c37c8524ad2118071cbde77f98788e634e0da2a193439d4f557417f523ba96ea9cebe0bdcb25ea290bfbe3ed40a8d4db81dd8115f419758373079a722d6b1d7ccad7ded8adc7345ba6597ba4719460dcced30e77d35abd2811355c759eb70f729ab1157b583785d4b5be49f66ee6c267fa87af6d38eb7f2a1e0ba8e2924631c2491f7e2a2b69eb19bfff5214e994da3de92e3ecac4fdee88907e55c3b10c4e0b56bc104e5731393e7ee4a01eb7501f888f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141231);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2020-3479");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr81264");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr83128");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-bgp-evpn-dos-LNfYJxfF");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS Software MP BGP EVPN DoS (cisco-sa-ios-bgp-evpn-dos-LNfYJxfF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a denial of service (DoS) vulnerability in the Multiprotocol
Border Gateway Protocol (MP-BGP) for the Layer 2 VPN (L2VPN) Ethernet VPN (EVPN) address family. An unauthenticated,
remote attacker can exploit this, by sending BGP update messages with specific, malformed attributes to an affected
device, to cause the device to crash.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-bgp-evpn-dos-LNfYJxfF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90954329");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr81264 and CSCvr83128");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3479");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '15.1(3)SVR1',
  '15.1(3)SVR2',
  '15.1(3)SVS',
  '15.2(5)E1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(5a)E1',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(6)E2',
  '15.2(6)E2a',
  '15.2(6)E3',
  '15.2(6)E4',
  '15.2(6)EB',
  '15.2(7)E',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.2(7)E1',
  '15.2(7)E1a',
  '15.2(7)E2',
  '15.2(7a)E0b',
  '15.2(7b)E0b',
  '15.3(3)JK99',
  '15.3(3)JPJ',
  '15.4(1)SY',
  '15.4(1)SY1',
  '15.4(1)SY2',
  '15.4(1)SY3',
  '15.4(1)SY4',
  '15.5(1)SY',
  '15.5(1)SY1',
  '15.5(1)SY2',
  '15.5(1)SY3',
  '15.5(1)SY4',
  '15.5(1)SY5',
  '15.6(3)M',
  '15.6(3)M0a',
  '15.6(3)M1',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.6(3)M5',
  '15.6(3)M6',
  '15.6(3)M6a',
  '15.6(3)M6b',
  '15.6(3)M7',
  '15.6(3)M8',
  '15.6(7)SN3',
  '15.7(3)M',
  '15.7(3)M0a',
  '15.7(3)M1',
  '15.7(3)M2',
  '15.7(3)M3',
  '15.7(3)M4',
  '15.7(3)M4a',
  '15.7(3)M4b',
  '15.7(3)M5',
  '15.7(3)M6',
  '15.8(3)M',
  '15.8(3)M0a',
  '15.8(3)M0b',
  '15.8(3)M1',
  '15.8(3)M1a',
  '15.8(3)M2',
  '15.8(3)M2a',
  '15.8(3)M3',
  '15.8(3)M3a',
  '15.8(3)M3b',
  '15.8(3)M4',
  '15.9(3)M',
  '15.9(3)M0a',
  '15.9(3)M1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['BGP_EVPN'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr81264, CSCvr83128',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list);
