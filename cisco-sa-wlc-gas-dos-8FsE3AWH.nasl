#TRUSTED 0e99053c202222ccd1379ff515b405545cfe2e2d577600e480d8e1a97f237f871025aaa7049b9ce6481ce070f49e63ce388368892036e06a3047adaea88b338da1bd54c70cee21cedf845418861db9a7f5cc0b1327c43f8863bc4c0b60bbed1335fb9f1d1f99bb7cfdba32135024f70d47cca05c73da8384920c937e7d3d4da7ff6537133112332879657da8a0daa2c111cd49e0d679aaa17efa8e49cbcee3ab039b5e3a32e13718651fbc51a26d1673c95cfe6a964fbfb14400e80e3c8bee3320939c1324354b1f93c2a9347a4404d34409a9ec0e52e6827174041265ca2ec49078d63ce8393d5a8f186d180d2b6c4a9c2f60f52ae1686daf6086f08de68c4f9e79f89591b9460d3ffa0ef14ad7cb066b98cbbdd77cd5ea4aac6d49425c0e2e35b266aa575ee9ba4bf0b2c4013f0963fed269afef37db09a2d25dd0fbfacb6ba4f3b748e333947754c9588bccd0ea2a2dfc30ee5ce2386d73547c9a804986f9b1b74e4f9c7ee05119c605a8a8ab7c56a62b455d5eca4bf23513319f9cd23154d74da9dfa85d9a7d71525d30a85b81d693fe2da650cd3e8e153656d7d4c1f6bbb7e8d291a3b29b2c3c8ac6869d4b23314390bfe4b95032a5c29406a6eccd4014b8e97e5a310ba52cb7b4c790de16ff91342743a5af2d05f70071202ea8543d63cb846727731125cd47895ca93e08245500e436224b13d9b5f4fb79c454f9e34a
#TRUST-RSA-SHA256 6d2a4bb51bbcc381faf59ddd866e320605743b52d336336df889596a6094d3c5703eb49724d6b15e448bed3e39a427a8c713ae6b4b3cfcd8ddb462d625103f8eaaf10ebaf4daec2aa8cfd883440cad896b1b99dca6ca6e675568d8ee72231343c2e9da1dfd37249a08f440186f653d70a8864d21adacd23ddfd994e1bdd4937456eae6bc1b5245bcfedccc2990aaf5067db9e789626cc1f1140e89d89734b45ae64a5ca47b6efd492f5a16c50a0cf4a7480738c5cc9e18370c81bb91823b6a68ad09f310f8906fbbb2193eee22c7ea8a396ea22a5b83e049a5cb647c6712ee910b1f083fd9ec8a443abe99ff6030544b8bbf37a4a027e8a8ef181dbec4cd10cd6c7844020f517d6b54d2c08cc10c1322e7ae3b2e7443f1f7aad2a78758374022c61396c7897ee317cc51fd7dc858e49bf79cc2c39bc2cd1b1e33c1dfae841a40dcf8811aa450ff23df0ed88eddfc1d81094e8b79875df38e2d1eadf204d823f03b73e7e76ae9c138f99cd6648e79e2ec2fa400defb0f42de2fe8dcb934fa33ad59a886a417e75e64a4e95cd00f0014a6b113fa6862da9df7d9a20860885fb63b42f1ba1466f44c97b7eb6c36623fbe9fdaa89a782ef0fe4c7e8e0832e4010fdddd4e1c29a6e8bfdfb358d9ad7d99d988f03c6a611d22c9aaff8b899dff064c6ba277b9bc359e197d3303fda099f6fbaa093ad702b68ed964e918aa2fbdc35173
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135858);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2020-3273");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr52059");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wlc-gas-dos-8FsE3AWH");
  script_xref(name:"IAVA", value:"2019-A-0424-S");

  script_name(english:"Cisco Wireless LAN Controller 802.11 Generic Advertisement Service Denial of Service Vulnerability (cisco-sa-wlc-gas-dos-8FsE3AWH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the 802.11 Generic Advertisement Service (GAS) frame processing
function of Cisco Wireless LAN Controller (WLC) Software due to incomplete input validation of the 802.11 GAS frames that
are processed by an affected device. An unauthenticated, remote attacker can exploit this issue by sending a crafted
802.11 GAS frame over the air to an access point (AP), and that frame would then be relayed to the affected WLC. Also, an
attacker with Layer 3 connectivity to the WLC could exploit this vulnerability by sending a malicious 802.11 GAS payload in
a Control and Provisioning of Wireless Access Points (CAPWAP) packet to the device. The described attacks would cause the
device to reload resulting in a Denial of Service.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-gas-dos-8FsE3AWH
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b296684");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73978");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr52059");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr52059");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3273");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("Host/local_checks_enabled");

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '8.5.160.0'},
  {'min_ver' : '8.9', 'fix_ver' : '8.10.112.0'}
];

var reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvr52059',
'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
