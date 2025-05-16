#TRUSTED 68ce2ad5156f8d66b88bfaf454f3d58296e62d630689939f50f7818097c51284f6624bde2582b6aab61a0cbd1ae3a3029bd0fcc16c1b5290fc30a6008c17f4eb779603f189f0021adb0907dda2c475ce4862b9d036cde6687ca1764af3754f67ded860803a9aa18b04d342d5cf81b6efa98102bca30c2ee194c1e6f9548626bedb2670724dd86f06001e9e978e869929bc785427e75b6bc70d1bae338a6ee90a7f544527a33f90c6a3009723c195f6d95aa0822aa3868760bd1bc65e385340d6f1ea0acbcdc22635168a00219696fdb3fe7b463033489fae8856a9cd31c4eed6975a28c0fa1bf4f4ef508746be19e32d5062b990daae3080d638a49f0fe17040680a4e80b5a64a55a3347a032b5c99137a637389f0681c55467daaf2c5aa68051abe50279671f3f6281ba81ea432544405dae2bcf199e9c9fcaa20814f3032acefb5706bf2b31012da22b7a02d92944a1486762619fb32678bad275529eae35a688dbee73ec8a05f5800d8563da908e47271758a90ce923432a60a86f6c44561f450fd8705b332116b4435a710503853ad0c8321f661ed1f9a7d7a0b415534fbc495480a83f4b1991a859a036ecd17a7ed91b6d967bba52b787b1c28b66042fc3e5bfa7f33169f95e73c80a2f6a54ada23676a62107ad7843f9669f9ccda8c89486e49f2a0a8c22076c7b84325b649d939f29e5551844564dbef5fcc2e7646fb
#TRUST-RSA-SHA256 a5f740bd1f42c2df3ab09c202bc2d19bc971390951f6c0a3379d9d6bc85adc3ac4351e0e1e912154f4b82048832b0d881f797003c49020848e866ff3d35bceaad67b5dabfa89e71e62f7d42d844d75d25f634ccdf9f77753704dbb36923e5e8d63c6ae1bf805565592ee59b4866915fa143681c775c5591fbb7de19fcdac075414491d2f746b15d7494c28f40f5f20745c3791f328631e9a0760e76ae5176d5307675353d432b060d4603b8f9b6ced596ac1b696bb7628d8451a6a83d34df7477fe99c8a54186c69dc8825ef7a201d48e0bb72bb1b75243311749709928c00421a9ddbd81ac1d8b73ba9ea81e5773052600a1a19715918855ef5096d9ed04a6ee0365727c705f5f233d3510c4dfe47f312c3d327a0549d233b5d539b7b9e3f495e6c705572bbb815bd9a9327918089ffe16844c35aebd6a3eb1b16d2b054a3efa23299de261ff4f50555cad87b589ae3c6b38da98b0d67b69d1dfdaef25bba04e9ec03a838a54466ec5388b710d5c4e6b95ad29df3d961aa45e6e8fe0c9ad984de13d0f9a5647bbeaa61a74d50329c619c6819eef80d5751d52c19deec7ea36a038cdd03bfc69a931d60df423b496f7fbc66eff6f3046fc96d8861cec7419556b0445f9f38cd3d82d8dc7a4629bf9b94fff021a556e26e1fa51fc7f8d424eb0552a318c777ed9991b164ac999d21c7a015ae981e1133308885ae12708a3d6ed9
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141372);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3511");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr57760");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-isdn-q931-dos-67eUZBTf");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software ISDN Q.931 DoS (cisco-sa-iosxe-isdn-q931-dos-67eUZBTf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a DoS vulnerability in the ISDN subsystem due to
insufficient input validation when the ISDN Q.931 messages are processed. An unauthenticated, adjacent attacker
could exploit this vulnerability by sending a malicious ISDN Q.931 message to an affected device. A successful
exploit could allow the attacker to cause the process to crash, resulting in a DoS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-isdn-q931-dos-67eUZBTf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2af093d4");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr57760");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr57760");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3511");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");

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

vuln_versions = make_list(
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
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4s',
  '16.6.5',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '3.10.0S',
  '3.10.10S',
  '3.10.1S',
  '3.10.2S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.0aS',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.10S',
  '3.13.1S',
  '3.13.2S',
  '3.13.2aS',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7S',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1cS',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.0cS',
  '3.16.10S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2bS',
  '3.16.3S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6S',
  '3.16.6bS',
  '3.16.7S',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.2aSP',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.1S',
  '3.9.2S'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['isdn'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr57760',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
