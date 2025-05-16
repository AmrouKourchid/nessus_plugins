#TRUSTED 99b81f67e8217fd66058bb2656bd7b8ac532f15104956a32c21fff2f0b5f1b9b081291f6f6105317f030f9d5e92df6ebf9765bb6548ce1dd0e90cdd82ed50791ad2650b4be7f89626f1257be3a0b8e0b93484e6018b07493a23f4882a337e9623de331b678b20b0f5da38d02942dcff4266abfc975290c3feb49d8f5a5d88d56f0f090d85586a863a100b1c1990ae162181d7eb3d3e41d97db926110f3f6de7cb8434b68bf94f568b0cf57b63ec50c9e154851ecb62e888487099557fe3c3521c934f985f64289c5d575b52f5972a663c1dcd49fb2f794ee4ca7027c1baeeae2ee85282dea85457b2fc290b3623d7ccc5c08c0bea30ba4e377f1b70272a3df0c22d6e479517957e04c346779e0edec8bdc014a0ec818f53c55851e73404ea25f7c6759ee3ffa49b3e1e0cdd7fcb76aefa4768065f7e821f36bcf6c4588aeaa25ed209d12c313d25853a38692705d420b9bd8ac44ec2e4d9f54977f841d4a814d66ba863ef6fb61080cdf3b2e4dbeeefbbef1054810ac69c9908d4a913b329eb69e5326d51e803b68f97aa14b29ca8ebec8a00a7fe535ee08d2eb105ac634e40248c6d7b3736e386e0353248e669b163af6e19be65e3bad7df28433b7347a05c6d2df66e375227cacc41b2b5c17c81b03c3f97093a9ac8297bad47ba547c586a3f73e1bc14d43ac2d63eb52d6c0936e14e9a6596f5c42d80ffc324d2d63606c3c
#TRUST-RSA-SHA256 5ede7eafea737841bcf134e6f55c45cab71b58ef9f2f86ccdf417c176e0ca0629a0b7f6d3f893bbb7cebffd54f5becf1fd46e95ff0c2d05bdd94b64c8f7c37ccffd2a8693ec68e1b1e05992cb9cd36d95606f8270dc2a19f62b446cee0ce87ee3c8ad988a0816bf79754dc456c60534cdf64d5ba889767517b801749b327be2d269dcfa2c2d7975ea8405c542e10eade845bcec6a9662815240e00c3628b8a6401f02d223aca0a9b724d1ad07a45608317e53e2e3db8804487b7a64e2443ddc4f80e78a7e17ed07261fea26e8d3dbaed4254c88ed70ad5eb8a6880e3ae45042eb6431074577d05db89627eae376a026151b99f9244a48f65c0e576196f993d773283a07619dc63b742050bf700af7f0bf14af424bbe2bdabac65d4e2092cf9fd53525ea82946b2f715e368e8496f2aa97e353909e53653f5e4cb57e92656bf40c971a316de321f9abe789a5781c05357556ac89e05ebb0d7e39655a9a7214afd44e12112b6bb272aa19659e8a0fcf7be0a67a953ecc51a9aa6d648f4793f1a1f3a3d3c5b9372a48fa5f11310c15530668d4b4511661d5be1536f3dca2cd4043aa2b4c007cd92dba48d9e0a65b06f935ab7ecfd2b5d0c96904067c1941c16f03206ba4356ebd8c8a9103670778c42a6865f9ade10493bb7bc74bfdcf02cbab445c119a07dcd03adbd0ae2c8cdce668acb7b521bb1011c76ac6d4712738618f0e5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124334);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2019-1830");
  script_bugtraq_id(108028);
  script_xref(name:"CWE", value:"CWE-20");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj07995");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-wlc-cert-dos");
  script_xref(name:"IAVA", value:"2019-A-0132");

  script_name(english:"Cisco Wireless LAN Controller Locally Significant Certificate Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco Wireless LAN Controller (WLC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller
(WLC) is affected by following vulnerability

  - A vulnerability in Locally Significant Certificate (LSC)
    management for the Cisco Wireless LAN Controller (WLC)
    could allow an authenticated, remote attacker to cause
    the device to unexpectedly restart, which causes a
    denial of service (DoS) condition. The attacker would
    need to have valid administrator credentials.The
    vulnerability is due to incorrect input validation of
    the HTTP URL used to establish a connection to the LSC
    Certificate Authority (CA). An attacker could exploit
    this vulnerability by authenticating to the targeted
    device and configuring a LSC certificate. An exploit
    could allow the attacker to cause a DoS condition due to
    an unexpected restart of the device. (CVE-2019-1830)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-wlc-cert-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ef69a18");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj07995");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvj07995");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1830");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '8.3.150.0' },
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.140.0' },
  { 'min_ver' : '8.6', 'fix_ver' : '8.8.100.0' }
];

var reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvj07995'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
