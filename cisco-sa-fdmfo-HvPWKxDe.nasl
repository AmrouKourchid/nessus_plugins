#TRUSTED 738980609558e82280507fcb873fc65d3e7c1f2294b8c0b7775ff63ffbe42070cf5f10a172ab02979c9ea607fc31f44971b65c2d782d4c009ab83b410d4b5cc3073bf79c601de7131ff676eabc9540a408895e490b2f5462735e4b4de6479318076534f34bcd0e5655fe89a217a75be6fa9760c2f08e8512d4997e5c4f54c05563a14691ad64e6d74d996304e2cf9d5c785194c7dcec68b811357c1cb4b5944c10354ab1fc7387392b72c6818766c12a6aae1114e33c0de4613aed3af80aa9912b9f2448a55505d64b5a57a7ecfdb34e41d602e6ff54e4d581692495fe77dc9b6556354aa0c58f27507ab0c1c1a802c4a49b374f9b209fc05b969f60fc322dd6cc2f1d39b3e07990fa68e5fc3cac221aa0d6d46bce69ac2d34400e0b309c764a3edb2ff6665e6b05251a1ccab0b3e4b8674bab024db37958cedfb99d377a542e6f74ab0bc0dbc282562bf8e806951b89f7fc0043f1ed4b2a9e56fe055d8ffbd9025ad20d3248bab003e3a50aea0485726f022bca8a6d036e24fed7e9ad02356631876e8bfb0a80b6d348ed6aad55db1dc7a5c08da26d35eea40b18fb741acd422c3473e2a883e8c9794bd946f7a2ba400aeddb8a4c36fbc22015c5a8b9a797cebb2d8d0f76e4d5def2106a7b6a6a915bbbb42c961117bcb9c355a3e7f3fdbf88da954ccd278c7b3c24067138780b3a2b5ed379278e991f5eb8e06dd9867d5f87
#TRUST-RSA-SHA256 ad4d35d914ae3f0945e2aa0b6bdea6aa131489442c66efd963cce289af92c8676df644ff1261361cabdf51cca12a54ae7fa975846aa09841fedec234b0d5df06e68ced446c37924f21cedbf62dd014134528cf5495781def86c4d4e0fded891575b4c2b62a48aa0c32cef2112f4153dd5f663fdc6436a299b23f13fb521134590241d91b1ab5342dea7612c0585ba6282ddb7cab201a2f67a3ada7ca75d474e9de26dd95cbc06d6ab2fc9ae4334b4d08cb1333159221e83ffc0e2ba7f0680d604dd138c739f9b929ddc0d1e80a926d3c5ca2535d5fd2dad21d4ed5e32193cce9bc567a0cafab806a3f8afd61cf76d2fce99f0a492676ef0bf7e0647d5eee6dc377a503938b3eb748c42918354d02ca5793a03341e6848d22a9d477308fc425294a87d892ebde9d881049634bc8da2d10c24a52652d8af4df4731d11a11ae989731669ab1f411616790c73cd1d8dc93af5440072b1bafab31eb3f6a5a3779d8595c9c51dcea03c24054d1878709aa0485bb032586df6a1c83068a570a584453ca0306a4a6391b786f3474562e05776f617d75ed96e2e2dee576eeb993e78ccca4c029cae15b9542337b53702cbab746b937374d33080b29024cc44143c4944927dc9358f120d49944dad26214ddff052d4d88b22a99bbb69b0f0bc655e412427e6d56fbd03116325a4f77613e4a3a6509b0cfaa96c61cadc00d04645eaf702c5f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138446);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/01");

  script_cve_id("CVE-2020-3309");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg48913");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fdmfo-HvPWKxDe");

  script_name(english:"Cisco Firepower Device Manager On-Box Software Arbitrary File Overwrite (cisco-sa-fdmfo-HvPWKxDe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Device Manager (FDM) On-Box software is affected by an
arbitrary file overwrite vulnerability due to improper input validation. An authenticated, remote attacker can exploit
this by uploading a malicious file to an affected device in order to overwrite arbitrary files on the underlying
operating system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fdmfo-HvPWKxDe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4adfe580");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg48913");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvg48913");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3309");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_device_manager_on-box");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_device_manager_webui_detect.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "installed_sw/Cisco Firepower Device Manager Web Interface");

  exit(0);
}
include('cisco_workarounds.inc');
include('ccf.inc');
include('http.inc');

get_kb_item_or_exit("Host/local_checks_enabled");
port = get_http_port(default:443, embedded:TRUE);
product_info = cisco::get_product_info(name:'Cisco Firepower Device Manager Web Interface', port:port);

# Strip part after -, not needed here
if ('-' >< product_info.version)
{
  product_info.version = split(product_info.version, sep:'-', keep:FALSE);
  product_info.version = product_info.version[0];
}

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '6.2.3'},
];


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg48900',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
