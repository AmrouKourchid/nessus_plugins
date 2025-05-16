#TRUSTED 35e0617b8eba16fc006ec8923093d7884fd9f521815d2a3e1691067dc8c1044cb477aaa9d8517dd480fb9f3a5a5aa6805639910c742aeb51c1e6b1ba42e02f6ae1cbaff2ce042598eb44e5fe295f685407110875da32b20333c2d7382468ff3ac7b2b53f3bfdfe3c3a2dba2b93b8349305d2b08d7cf8ca3587718c2f54531d3943901cb1b0ab2778dcbc58a8131f055b27730d0a7af43e66b4dc249bbad9457ee8f4142156e8fbf3a8c0a897bd357a9b5d14b3f0580eba356954b4bdb80e5e2f873c3e897a19af4820750b2305bcc26613ca3730a35a78fa03c7af995155c1297479fa4b5424c7fa336ada795051f1bc6f62151b22cba836ef29ef7f102b92387def9b535161ba3d0036e230563b2fd9be4c333bb3216711302fde67d6145cba64af2f41bc5a02c0550dc91a5e117fb394a0aa17efda766dfc84bd67cf654517742909040ccf73131f762a89d14dc7c91981ff82e09aaa9cea752d3cf5e6f07981229e5a74f4f5ff01465f027d2c740a67895a4a9bbe873ab6eade7ac635550b000df7a14e6dc99746eb746a6c3fc6325b5278cb75d76e52ed7ca939e467df23ea9a3c28a8f5573b691277e877c0c4e22bc2af9afba35dc9ae134c2dd7a619e4c1bf09096368c87384a8cd3cce1780bb84db76b335798777754b6b2d7a961f7fb6e12ca8f24b0d8ea9bac96a79dfdf87a868fe3852f822eb3de85ecf1b01281a
#TRUST-RSA-SHA256 055cd95a8c42a68e766737deb2ada6d277dba0b0d5815ce2aebcb46a3166ff0eff0e7155f0be66fe3ca944e30d23af0cee5a328c193a3504b399a701aa227769b37d535c5b4cbab9966c405d290493ee646e429a521f15a6ff92706e410ece10adde8f3f432c7c1c9bc9ed962784a8439cf54096410964c4dede51777baf24c0c85f6c9aa618556ce58812be15eecdf6b694b58c83293807ea298374550ccd7d89746289bcb702e65f2b39faded3c713ed874ed71110b6aa645c5ffc3f31d953fbe4e83ea44c63f807f25168a32511b1ddd1a1ad50f69d530e20aad305a77fc54c35ac92b5669acef6c7ec073447627ec1efb988d01376e90410d1b6dd1ed3d330f8e1865ba04a6e6a03636dff613c19bea5d64c535bbfc464fe62d29279f49fc5cf8b195c15fa7f912614adc7e40a2410b9f9510f3d7c6c5d6df569abc366f830ee2d1fa775f187592b5eb207d913d94ee960d2a55414f91379c0c0ab66806b9aa3cff749e10eeaae3e3329ece5a6706921c274ef9d2f1587e59b882aba46381a6f3fc8c3439c526058845f06c8b3235fbd7ac0cbeac7f0e857a2acb97054d752803e22f3758444a56411017c6c13cca380fd40cf474c39e5c7fe8a3e7d6e9bf6d568cb7f109ceade5dc383fed2370fce8d94376ad0ad156558d3369bc62a9c800853e3276daf543ab9796a86d1276133c64df456449211d603ffa4b05df4a3
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152877);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/22");

  script_cve_id("CVE-2021-1587");
  script_xref(name:"IAVA", value:"2021-A-0398");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx66917");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-ngoam-dos-LTDb9Hv");

  script_name(english:"Cisco NX-OS Software VXLAN OAM DoS (cisco-sa-nxos-ngoam-dos-LTDb9Hv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the VXLAN Operation, Administration, and Maintenance (OAM) feature 
of Cisco NX-OS Software, known as NGOAM,  due to an improper handling of specific packets with a Transparent 
Interconnection of Lots of Links (TRILL) OAM EtherType. An unauthenticated, remote attacker can exploit this issue by 
sending crafted packets, including the TRILL OAM EtherType of 0x8902, to a device that is part of a VXLAN Ethernet VPN 
(EVPN) fabric causing the affected device to experience high CPU usage and consume excessive system resources.

Note: Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ngoam-dos-LTDb9Hv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7380f039");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74640");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx66917");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx66917");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1587");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(115);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "^[39][0-9]{3}")
  audit(AUDIT_HOST_NOT, 'affected');

var version_list = make_list(
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.2(2v)',
  '9.3(1)',
  '9.3(2)',
  '9.3(3)',
  '9.3(1z)',
  '9.3(4)',
  '9.3(5)',
  '9.3(6)',
  '9.3(5w)',
  '9.3(7)',
  '9.3(7k)',
  '9.3(7a)',
  '10.1(1)'
);

var reporting = make_array(
  'port'     , product_info['port'],
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvx66917',
  'severity' , SECURITY_WARNING,
  'cmds'     , make_list('show vpc brief', 'show feature | include ngoam')
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var  workaround_params = [WORKAROUND_CONFIG['vpc_alive_adjacency'], WORKAROUND_CONFIG['ngoam_feature'], {'require_all_generic_workarounds':TRUE}];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);