#TRUSTED 690e25255d4c6bb24cef8ae4b692f64516d5df78a4e8f400f0503bf815fe5ed1a1edb9811aad8b6167572ff361688de26d56d3122101e3680853c29962e0fb350ddc2cdb6d45e469c57a45bd6cc97204f8dd600309255169e7f0e1f0b26936a938c66a2d47826ad5f9df9387458a46ae83f1deadf02d225e5dc5b24ab51f09458571edad860fdc1016df81351e9751b541e39164c0d6ed0bdeb8d13f88e5a0af25064f262b7a23440c3b55a81ba41fa1390e27f6343d166edacaea6f1c789b77c26abd2595edd51d830f4888c0bcd84d4a2cda992473e29f726d471c2bb035ca4c3fbfbe6d7bf6284c892401f11b4dfd6c1b0c15c297a0956c81b10f90b3c0e0650ac63de565f29b01bf27c8f7c6489d89c2987153b0662da6d94b79382ec3e511877200923c28191605e1a116607c36321300d94523881c852cc281449fb7fe2c592eaf1b884a32f501984a6fe827f58bb58bb101f9bdd443194222cc9bcd5ebae5f6c62886cb6191d16b379fa6b1fea0ff2a87c431082c54955e0d36a1caca31628fa2da06bb0ac9e7ec88850eedd9786a0028a10a917f1fe6a752d69d77d7043fc270f6146828de7b0201ba6d8df10e00f3fa3e5118518bc0bf955be86fb36c9e5235695ed803e4b58c80e5f7eec5b9b342bf6a7f2f094071dc6a0d3b539ab28594ff7c133cfb92b97f4cad46a8f7adf6b42811f5eb65e74bd99d967b2719
#TRUST-RSA-SHA256 3c7f4f7544855c9f341cf951ea9e0350c5063cd328d7e0809e4e6e7e60c5f284d67b7995af401d9587afbb092a72ee81a2f384557d98bc8153b67a8021a45342269d3ce155b04198e873133e328b5338290f540791b298e366d271e66763f49b6c3ba9e42133d42a70ee7eac8d29a672a50a433ed0f322dba8495a3bd55a9fb1ef1be5f6608af8e283f880cb0bb892d73f50412ea5865e87ab8a5ed9ce0382f7ad17e06e96597879888f601c8a6ea17bc9765bb239b481850a1ff5b0a0509a3fa875403c6b64eb69a66dee3c96a8bfa1ceafa6385f3768dc1f00a911fc4de0a922eb287d8218f41efe5aac3a9a3ba3592ca6ddf299ad96823534ee4c3472c99c88021dde288b528e3411f87483a9cc788053ab6d2407333d800c3ce6767ad6528df08a68150853a943aee2f04b281579d5815300ef253292468b6b8a7efc89e30be1d49a8ed8db5d3e89dcc26ee7cdf69aa3c9244290f16ab0a4285f27f2c828cd05f1a4c40d2c40b9fa245d61d51ea256a8c8e46cc8548e5e35797d8592af173f828c4dfbf58e0744071b46a4c230cf8e390324fccd1443a6b7f3868640bff4382fbee7aa85dcf11605614663d337b2dea108e5626ecc88a7d2ad18e5131c8d31a850354382b22adfc79fab2245b29a770d193c20babe7ba67fcb0cf6d26c767e4572ae2dff7817c1d24f323d889b7812748f4d733110aac19fd5541adef88b
#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(130208);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2019-15262");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp34148");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-wlc-ssh-dos");

  script_name(english:"Cisco Wireless LAN Controller Secure Shell (SSH) Denial of Service Vulnerability (cisco-sa-20191016-wlc-ssh-dos)");
  script_summary(english:"Checks version of Cisco Wireless LAN Controller");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller (WLC) is affected by a denial of service (DoS)
vulnerability in its Secure Shell (SSH) component due to insufficient process cleanup. An authenticated, remote 
attacker can exploit this issue, by repeatedly initiating SSH connections, to exhaust system resources and cause the 
system to stop responding. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-wlc-ssh-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?728814ab");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp34148");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID 
  CSCvp34148");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15262");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp34148'
);

var vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '8.5.151.0' }];

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
