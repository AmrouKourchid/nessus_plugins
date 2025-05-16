#TRUSTED 56139a58e014b3bedaab303d84774a466e79420a223aaed2332e21fa796048391c5421fc8a7f10f17c4571b322fd4a11478b8a36aa09931222055dbd563c3bc47015e5129184c644055df55c9015090524e0a1e7d889f2f709da3236ee25b95a017b88001d0a81c8b8c8ba21769598827482d82b661e0128e88ee138c24529541f22ef9c08e2f9a3f613f693169acc9a425713fe921549ded1ff468dbc268c3708e62921853b1b20935e54f6e3b1dac678e44d1307671ed5cb9f999f65c800980137486191dc6a3bbb6d946642cb8d17283acba28a457f38b96c840aae226a4fb907f5f09381732c9e5d76fab0b05fa55119816ec1466f83087625e7d50059cd4fd80b70a601900ac52628edbae6adbb9e1f9f444aeebeb77d5ac8ec22c7cbeacc0b06f76edd4b44528f7f1d129e87846dfd436779a8e71fb68820d8d612650648545c3c14554d391c2d65bce429dee5c0631cb4ffb6884f37e0871e3fd8b94b5e76e1ea6952a8867a9d935ea8a8b86e31518d45046ffafc948c3da5625207bf313119a0f8e83112ab1d37ccaa94f6e5e732541554aecfdc7231b714156aba24a4134184861afac8c830fbbe50cc1ba6c7e5ec52f8206c5e5aaaaa2d40e9e34a55c4fd3bea8b63a447f342656605223c8b9cd96b5831f67df3024d626be7d577151eaaffffc342a6174b68cbc378f2364d277f7f48e62dbf8ed32b0e8cf13829
#TRUST-RSA-SHA256 48abfa41a16e54716b1ceb9c5a9985a25bae2553510eba88a3415b96d9a612fb0b28090a9379ff0ba6543756bc35b4587ab615f04bed27b20c9bc4ca76eada36966a429b5c1fdfed94f8572bf4ec981a6a051c1ada6913db1e31cf045edc80ff7ad069af065edbf18d8c4cf5120825e6cf163f1195fc140b0412f15175628bc125da1df7a151e42080ff20306aef67ef33830ff92c91e55eec515ce72201552200f43b884e7d5eee5f141541c73feb5d6e72df9f94dc92550112989d6dd40b43b5f06b526fc370bdd6a46b0df78f4a19fdaa0d2cd657eb1c16b983f2813b00eaa858e06711d1ee57263ccff6572907a8d6c2a80a6015e1a8055116a251444191449297138be8f3662df993bab7c2979810ffdf5f87a93c58c501263ee2c692eb5a79e43a09d3d8e7a1cefbea39dcedf8de2f97d543defeffdefac74cce7e34c88762156daa40b511f2f49decb91c9ce289108f47f81118c1a6069dd61d94211bc24551eaad6ffcad729de1184b506ba227ccd2d5a5454703ce76d584393454bc3e2fe8723e2f877294786cfd63afc5006f6a3bf2f9c64792a8a36998022d27943643a489e9ba29f531c827f23466ed6c452e89f527c256c799557f6b7433fbc7a1aa66523b29e1e2894fbf72bde8a8ae7e55549d6a70d5451c75c9358f945167cd971b0e6549041021994f871ea73051f9ce315a0641da25e4d37c35a51046d1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141230);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3479");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr81264");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr83128");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-bgp-evpn-dos-LNfYJxfF");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software MP BGP EVPN DoS (cisco-sa-ios-bgp-evpn-dos-LNfYJxfF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a denial of service (DoS) vulnerability in the
Multiprotocol Border Gateway Protocol (MP-BGP) for the Layer 2 VPN (L2VPN) Ethernet VPN (EVPN) address family. An
unauthenticated, remote attacker can exploit this, by sending BGP update messages with specific, malformed attributes to
an affected device, to cause the device to crash.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-bgp-evpn-dos-LNfYJxfF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90954329");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr81264 and CSCvr83128.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

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
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.3.1',
  '16.3.10',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
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
  '16.6.7',
  '16.6.7a',
  '16.6.8',
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
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.2.1t',
  '17.2.1v',
  '3.10.0E',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2E',
  '3.10.3E',
  '3.11.0E',
  '3.11.1E',
  '3.11.1aE',
  '3.11.2E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE'
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
  vuln_versions:version_list
);
