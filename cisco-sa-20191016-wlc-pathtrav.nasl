#TRUSTED 57f7bf2c3b382ecc7fda3d08f91de074fc76f010819d8803bdb2f42f6787baf0a88c1fae18a9c57508d9d4c8f635eceefe8753416ed2926e7c5b5e4033dfc5d88e78ee24819d3286f07f8d05adc9e1833030e83501b49b23ea6feca10199d47a5ecf6d4cb99ffdec7d8663e5220d7214e58cc6a303bbc4abbd4e4920dc1e22d8675ef7613717bae224b696071c084cd70fc6799040560ca814171ce8eafed540fdda410abc1983c0a23d253f5a314af5e333959d7551fd6c6b04cbaa89e2172f2f6930456cd1e0eb838b8313f6029ce8debd22489f467425eb02730e02d332ede48b27c43c3d33afd3a76c21aa0eb08a3c2f42bb2e21f5e484eb3ff9d915d5997690574274a8a19dd25a4b2b665ca3c2893b52b6b482b4c939891060aacb8f30f17bd49d70e29add0ae77c9f0e47832a2a50905545724171936ed84aa36410936ce18c754a9eb65d1bd001556b283cfa8a1a8858cb02f5d6f60f5f3f0caadbbbc798a4f51467305630b5f01b525adefa5aa6b5a52b4e4f972443c7ceec7d9b1de78aef3089e4a39cc09998921c4b449f23989c6d2b17e400112a189bdf9055cf6db82f88f6e9f416ea1e2b799dec044b96573ec2cbd723d0dfcbe371a36f72583607e936c2f27525cd77faa157a10760c63b9a9881ba9cb54fba0e49267bc70a546596d7bf71a1c2cc4c191b118da5649b4bf56599bc60300499b0f452b8e3de
#TRUST-RSA-SHA256 31d3cae05696e1a11e3fd62d0d9af32c7da069169cdf95d41872444e7ba89bf893ebb01913fa5f76ccaadcbef402ef84e0fb5328f4d9ca28513c02383dbdd8ef3d3562f1da36a4d64bdb679290a264a7876256792b6bce2b2ada211e575fbc34c8eb4d621e8ddfb61967448d14a947e8e5411675417ef33e5dc229f6acd13aed4643279a0c49794f78f7dd7c3a2c6ed6091c5b77e82e3702a49911e6971b412f6aea89012eb5b4722d9b292b064b2f44a50dd1e54cdbc83a0562495d78413fd566f52eb5c0bd3e41a38b4cea8143151de332fba56476de830813e7ad5f56d6480bb04a0779d568ff3def1d64207352803f44d453dcdd939a80cbc27fce1f0a9410aa970d3865939aa8df14b17a02a2f1fb468a5bda0e48b6f22b241225298dba89690647b1b654a68337d7b635632bb843dd0f7e768f3a53b7f289e22825c5a79b6029bbb0ed00c7323538d8553ed21ea709e39d8c8b42ba1154d8246bd034c5fc97200225b75f1044e096b68e945fc796d3241fada49b059daa5512785868a48a88f5449ae38bf3b0e3822ad8c9d65dd998fb36b791dd0bf3ea7e8c1a5afac7ac7ca4c1559814cf2a0c1dc62015f388fb4dac5ae69bd428d7106d8a176f8e35df62b0cd3b23dd6d8fcc4569527bff1db80e3c73222774afc7268e46bfe8cc5496a9ec33d3cd4a126e652e59dc7a17c427601c6a7af546ebd927e2f276640ec7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130259);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2019-15266");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq59683");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-wlc-pathtrav");

  script_name(english:"Cisco Wireless LAN Controller Path Traversal Vulnerability");
  script_summary(english:"Checks version of Cisco Wireless LAN Controller");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller (WLC) is affected by a directory traversal
vulnerability due to improper sanitization of user-supplied input in command-line parameters that describe file names.
An authenticated, local attacker can exploit this to view system files that should be restricted.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-wlc-pathtrav
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2da8949");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq59683");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq59683");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15266");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");
  exit(0); 
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var vuln_ranges = [ #  8.8 will get Maintainence Version in the near future
                { 'min_ver' : '8.4', 'fix_ver' : '8.5.160.0'},
                { 'min_ver' : '8.6', 'fix_ver' : '8.10'}
              ];

var reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvq59683',
'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
