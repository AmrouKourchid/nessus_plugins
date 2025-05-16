#TRUSTED 757dc13937c9f9453babc1719566063b63b3e1cf94739b9c916cec008df6cd89958237c331c8ea3f0f8140672e4a8831f3549607ba7c9e90a64117dd5f2c21de6353725c947f4594eea093cf291ebcc34a64034b6855c40cb05ad563d7d1d6fd3aaf0a65ea8d9e1e3c2b95ffd6a28c6fa215dab50e9f68d96912ce3aa9476dba586a8f0a7a7796df114fa46b658c1cc9cc4b95389bab038889edc216df6a8d74aedc81155f6cfe2691ea203d15bda3dcd9d392bd79e41ee7ef0af51515e8f3ce892361b8c6122054cd3f50bca240f8e3f465dc8bf3bd9860f9d2d3b35f7937cecfcbf96f34741a7435ca35326d4acde710114860c74eb315409634ca6812c621afba832ca08913de0913d272a6975fe3a2796ba646d0469d080c3643e23f798864277a88925aa21912c21cc8920c22c9af844e5d67ef239c69e1c9db64065e6cd4349582be0c53cb533080eda5922c8d5dede0920155ae2cf1f2162ce0172495ccd1a6f4b46ff58597c87b4f780fcaef255e7ab9011dcfb06e474f53cc0101150ad195811633d97c042d5ecef974e7553fe61501f3f616d6cfa86613055ec1f67394654ac4d94980f6d720614b940079a9b17684d38f4b6e767bf6e2f6a4ccc6e841c1f90082dbd188999820430d1b96aeb761aa40df788b2564e9b6bbb72045ef1e89baf2e35e485c4ba7a29da401ff11369f2a00486e601b9ef8e343026da5
#TRUST-RSA-SHA256 b11104eafb59fb398900876373622c93974aa4b2a3b15899af97764f482df918574216edd051dcb21658d8bee758a63f85d0732f4d961f905a843a69eb539ecb3489ce18c808fa96b852ed0767dc3a454775056979fa009eb69d298dc84746d3ef8b78133e9093fdb2e9df7cc5f04803438f682bcaf9b3b10969cf1ab042348866e5d1df916e05effe07ef55a1f15fb5318e3c3a3d381e27e48467f483ee2bd826385d2525878c91c0b250eb3e8c32815e8e0a92a9cb339d11c9a93787ca2f59c975610d05d4cbc46b54786da70c91a4e9caf75a2a282ce2a690dd9ffc9990e5f10183ea1f07c2d23f3d1796e21f138b896660967e53c45559281bb6285c57e3ec955d6b21b26828543137f5f875ebb6c256881a821e5639683fb3e24088476e6464402fe451cd06e7f1f4f34d10700df8742bd8626600c2c12963df70c808e61efd288aa8e97eade4e9914ddbd2d30bef46abfe861159b27af1f56cde32322584be7cce8b7413742d6a91055fab711075a6e1202091a0929ef6173b4177b27d7b0f4b97afcc4f32d0bf22133126cf6802219ae96b259b4cad63d406e5e9a08a40539678cbaac6e5d270cb0f46de760ea5f9bfcc54dbaa84226a16e96912cd761d12c06f33ae8db347dba665ecb81ece6f1ce735c2ac3747a714578383ac7c15bcde1a839a7ff6c6313511b34bd4ea0f51f6db6a022520b17078221dbac97008
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141460);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3421", "CVE-2020-3480");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs71952");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt52986");
  script_xref(name:"CISCO-SA", value:"cisco-sa-zbfw-94ckG4G");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Zone Based Firewall DoS (cisco-sa-zbfw-94ckG4G)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by multiple denial of service vulnerabilities in the
zone-based firewall feature due to incomplete handling of Layer 4 packets through the device. An unauthenticated, remote
attacker can exploit these, by sending a certain sequence of traffic patterns through the device, to cause the device to
reload or stop forwarding traffic through the firewall, causing a denial of service.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-zbfw-94ckG4G
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1a34db0");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs71952 and CSCvt52986.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3480");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(754);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/15");

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
  '16.1.1',
  '16.1.2',
  '16.1.3',
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
  '16.12.1z',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.2.1',
  '16.2.2',
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
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1t',
  '17.2.1v'
);

workarounds = make_list(CISCO_WORKAROUNDS['log_dropped-packets'], CISCO_WORKAROUNDS['one-minute_high']);
reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs71952, CSCvt52986',
  'cmds'     , make_list('show running-config | section parameter-map')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
