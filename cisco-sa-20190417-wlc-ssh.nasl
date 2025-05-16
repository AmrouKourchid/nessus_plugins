#TRUSTED 753dcba88c569f57340ecc6bc8642fd6b43a7ec061d449c43cf3a06bf3dddaa14ce270f5152edcb9042e0bf44dbfd151a11c065ddb3d5ea5b93d0f9cd750d49d52ff7cc8dc54f85452b4fd603b13e4e1c175a85ae7b9204d80e6988655ea6a19f66ab045fb42ba63353361bbe6e7200077220d8d310ef1859ec4703b192c9605d8f983db921cfaeed9d9d9856cbf08cf8459cd8fa10d85518266b8eed4700d889bb75641bf0d55e6bcbd27ebc256f88fd31d13e285fc32324a1b3a76a33381ce284be5479800159439c5f83d72d38108ff38b230bdbbb7ad02a1b2e87e479c78ecb4e60bab9e64c9cd3d280b69b6495e8ffa90e4e6abda1ade3d662f45c6c7f2c854413e196efde0ccd6d5c001c3bc80b95a8911d8b8c57c2eaa796041ad27be2974978f4c96304f82fc726c7a2e4cc20b355ead64cbeba733714eb45699600e9d4ef0cf26655f2e6814277dc1c877c87c6232ce1ab064e2cf02226473bab47b5d9f6390c69a5ca0502d76b2366c748ac3f12bfdf3a36b134e82e03e282f074d51889075f57caeb5b8628157f1cfa7c1c1ec7c0def60f14d35195fb6d83079a6189f005f0c0b4ff4c6d0927f775030ca9e0c402ce81cf57327dc49118207c71845d591a13016f220ad70cdc54e0f97b8480f4bef7e100c0624763ae72cb551fa76956275b406f846872e85da180f4f2b45e185db58391b76af346f5bfe58dc23
#TRUST-RSA-SHA256 853ba0b141b19abc5e95288772837a810d176ecade9a7d9acab4b7aec3f6f6f104adbb11d43bb20a389fd68e394d6b832b393887b282fb1fe1207eef87113b4b37ec636eab948a7998193a04f0926637b023cfd8a48f0660b78092201fcc628340fd3eebff68f000c5461918e17665d4bef1a38978873adaa66b05d4fa2ec0a99dfaf6ffc268a83e776202f3193d224e6116d49236e240cfa0aa95e2bdcf99247b57e274b813689c48d2dbf01376ab3e7d0e134791444672d29f080014c205710d83fc2d94767f4722cd7a34912614a08f1d2251fb788a94a6040a95462eaf7d6968e81a42152b81e84abc17d7cd49da8fef7e0b2a217b15f7a8814629117a5f706ea5ab4338ba82f12d66d94523f6b7e916b147ca84de1c7f103b1307984f204b856eb2088893d6d39a8ef6b949dfa6ebeb2e912b18e3f8e9e4e0fd5e9d1ae4e348b51349fb8bef7161275374f2a96ec4d689862fe3dd642e429cd784ad651b46557503c9885cca27d1ae5115cc40f7c8f1ac33c5102329ca458f5f769f53af4f748b21da460f4947f0c861b32f36ae37a3e68750d487ff86890941f2b407ba26b1792c08904a15e38b27796cc750706dbb629a689f6bd9ede3e20881195af3fac43af3e86d63afb265f75b3856ab00b0f063f18a2fa6d6352668fa2ca977411c70706aa1fd8c69ac2b1cc8c8e2b7858638748bf744f072f01b852c8a4d4160
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124333);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2019-1805");
  script_bugtraq_id(108003);
  script_xref(name:"CWE", value:"CWE-284");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk79421");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-wlc-ssh");
  script_xref(name:"IAVA", value:"2019-A-0132");

  script_name(english:"Cisco Wireless LAN Controller Secure Shell Unauthorized Access Vulnerability");
  script_summary(english:"Checks the version of Cisco Wireless LAN Controller (WLC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller
(WLC) is affected by following vulnerability

  - A vulnerability in certain access control mechanisms for
    the Secure Shell (SSH) server implementation for Cisco
    Wireless LAN Controller (WLC) Software could allow an
    unauthenticated, adjacent attacker to access a CLI
    instance on an affected device.The vulnerability is due
    to a lack of proper input- and validation-checking
    mechanisms for inbound SSH connections on an affected
    device. An attacker could exploit this vulnerability by
    attempting to establish an SSH connection to an affected
    controller. An exploit could allow the attacker to
    access an affected device's CLI to potentially cause
    further attacks. (CVE-2019-1805)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-wlc-ssh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f076a8ed");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk79421");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk79421");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1805");
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
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.140.0' }
];

var reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvk79421'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
