#TRUSTED a93369071d3ae8305d1e0a6ce8d723cb95150516df219ffac4e7247fc572d316fde5e72fe521511cc4acc7d3d80aa45e5e277db6b827a12d26066c881ebaf11b40b570a0f7f1134d5727945ae0bbcdcfc4f78984dfe7a7317c8bb5f2ff0df7c596573570ba11a074fe7ea21593da74e2b05bb79af266074119dc8546dea2e29c8f3e14031a866765f165fbd16c677c955ecdc79a097eca20fc5c8c646979e5831fa9d6e7205429462102878ededf87968ad5bc17c04b715395997f1d5060a18ae5bf1150f98b711ea3391bf428c733b022b53092ea532c48c568364f4ece7691b589311838e7810f4aca8d1f3df2ed01a31dccae05d5850c75a09606dd590407bc5865851de4c7ead13b48f5b3551a8721f538a387fe1cab62d42c00d091e5503711bdd594ce5b30b6ce0bf02182509de97bd57eb6e06ce5fe8ed4262ac4c99008be82a4b4fc5cdce503957849cc4b8c13389562e9c994801822ca7d1847845cb0c80ad415c48079a7bf9d4cc92dcde0e286279bb6c7288173a489ebedbdd7703b31646b7191145e290e6a553fae7cabc17ec8945398058c1f1a55e40cb5460c91ecd8b7e88cf7944f04725aa1003bd47757d3da7525397af075c7ec6f9ddb60cd683e9e0972c455057d8cdb3400a3fdd2fc662eaef623e088c2119df9093636be94785a2ef207d5c080075d5850afe02fcab3e0f058cb68a351d7267f2484a1
#TRUST-RSA-SHA256 63cd5a36d2395ecfa883b10f55e370456af103d260c6d179c3f93a4634c7ce29d2d1a4bdcea717677c64e43ce3c82455dd6693a227693aeb4aee2e91957a3024c39af52ef2ac2fe63118acc5ba0eba2cd23d8284e1521092196f394190bc29948a04c65a7dc8601078050973ca79fc6fdcacfcb75e47b09e064d8d07962f27730869593424d967eb226ed9f82886b568cb0eddcc1688c60231bc2d7f12c6aa0b8fb2f06685b7a0ab660f096058a77b19d3f50440167b8b1e5f80fd216c0dd32e4296682c7ead51aa8341c7cf702d63f3eb54147d6d1251c93affb17dedc0b336f30b1ce2659bb11f65cb636062f355651dd07d12781ccf679ccc8786cd31267f913c7b02d0baca8b43c2a32fc6db3fb7fffdd11d540294e87ea72b94713c6a52079bf796efdd9084b743b95f61216061c02ef8530903a7bc0924ca5e024a2263f163efe8dda25ba0d7038cf2c70a7ae398d5502f7fa3e03f9ec1796cbaed1210bcb00aa5f9bc396199b14f09c55d3f5d57fa03aed859d17edf9a3bc744eb08d812beb7275fbd06d1bc7690260a2d02d06b89ea25b435b232a27187c4da393bb68c1f69b6576200878cc8ad2edf36132f28be689d852479bcdf23700298b12d9383d55a1f79fa30923e400c9ef48b9ef7844142422d0289fb08a6288b21516fbe6e1855a91408d71c6b9023e059f6d9d26a4ddd0b371a20b74aed3ebd8833bbea
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181183);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/21");

  script_cve_id("CVE-2023-20269");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh23100");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh45108");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ravpn-auth-8LyfCkeC");
  script_xref(name:"IAVA", value:"2023-A-0460");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/04");

  script_name(english:"Cisco Adaptive Security Appliance Software Remote Access VPN Unauthorized Access - Unauthorized Clientless SSL VPN Session Establishment (cisco-sa-asaftd-ravpn-auth-8LyfCkeC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the remote access VPN feature of Cisco Adaptive Security Appliance (ASA) Software could allow an
authenticated, remote attacker to establish a clientless SSL VPN session with an unauthorized user.
This vulnerability is due to improper separation of authentication, authorization, and accounting (AAA) between the
remote access VPN feature and the HTTPS management and site-to-site VPN features. An attacker could exploit this
vulnerability by specifying a default connection profile/tunnel group  while establishing a clientless SSL VPN session
using valid credentials. A successful exploit could allow the attacker to establish a clientless SSL VPN session (only
when running Cisco ASA Software Release 9.16 or earlier). Notes: Establishing a client-based remote access VPN tunnel is not possible as these default connection
profiles/tunnel groups do not and cannot have an IP address pool configured. This vulnerability does not allow an
attacker to bypass authentication. To successfully establish a remote access VPN session, valid credentials are required
including a valid second factor if multi-factor authentication (MFA) is configured.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ravpn-auth-8LyfCkeC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e25914dd");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh23100");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh45108");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh23100 and CSCwh45108");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20269");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');
var model = product_info['model'];
var vuln_versions = NULL;

# flagging all ASA versions in CVRF < 9.17

# Cisco Firepower 1000, 2100, 4100, 9000 Series
if (model =~ "((FPR-?|Firepower)\s*)?(1[0-9]{3}|1K|21[0-9]{2}|2K|41[0-9]{2}|4K|9[0-9]{3}|9K)")
{
  vuln_versions = make_list(
    '9.8(1)',
    '9.8(1)5',
    '9.8(1)7',
    '9.8(2)',
    '9.8(2)8',
    '9.8(2)14',
    '9.8(2)15',
    '9.8(2)17',
    '9.8(2)20',
    '9.8(2)24',
    '9.8(2)26',
    '9.8(2)28',
    '9.8(2)33',
    '9.8(2)35',
    '9.8(2)38',
    '9.8(3)',
    '9.8(3)8',
    '9.8(3)11',
    '9.8(3)14',
    '9.8(3)16',
    '9.8(3)18',
    '9.8(3)21',
    '9.8(3)26',
    '9.8(3)29',
    '9.8(4)',
    '9.8(4)3',
    '9.8(4)7',
    '9.8(4)8',
    '9.8(4)10',
    '9.8(4)12',
    '9.8(4)15',
    '9.8(4)17',
    '9.8(4)20',
    '9.8(4)22',
    '9.8(4)25',
    '9.8(4)26',
    '9.8(4)29',
    '9.8(4)32',
    '9.8(4)34',
    '9.8(4)35',
    '9.8(4)39',
    '9.8(4)40',
    '9.8(4)41',
    '9.8(4)43',
    '9.8(4)44',
    '9.8(4)45',
    '9.8(4)46',
    '9.8(4)48',
    '9.12(1)',
    '9.12(1)2',
    '9.12(1)3',
    '9.12(2)',
    '9.12(2)1',
    '9.12(2)4',
    '9.12(2)5',
    '9.12(2)9',
    '9.12(3)',
    '9.12(3)2',
    '9.12(3)7',
    '9.12(3)9',
    '9.12(3)12',
    '9.12(4)',
    '9.12(4)2',
    '9.12(4)4',
    '9.12(4)7',
    '9.12(4)8',
    '9.12(4)10',
    '9.12(4)13',
    '9.12(4)18',
    '9.12(4)24',
    '9.12(4)26',
    '9.12(4)29',
    '9.12(4)30',
    '9.12(4)35',
    '9.12(4)37',
    '9.12(4)38',
    '9.12(4)39',
    '9.12(4)40',
    '9.12(4)41',
    '9.12(4)47',
    '9.12(4)48',
    '9.12(4)50',
    '9.12(4)52',
    '9.12(4)54',
    '9.12(4)55',
    '9.12(4)56',
    '9.12(4)58',
    '9.14(1)',
    '9.14(1)10',
    '9.14(1)15',
    '9.14(1)19',
    '9.14(1)30',
    '9.14(2)',
    '9.14(2)4',
    '9.14(2)8',
    '9.14(2)13',
    '9.14(2)15',
    '9.14(3)',
    '9.14(3)1',
    '9.14(3)9',
    '9.14(3)11',
    '9.14(3)13',
    '9.14(3)15',
    '9.14(3)18',
    '9.14(4)',
    '9.14(4)6',
    '9.14(4)7',
    '9.14(4)12',
    '9.14(4)13',
    '9.14(4)14',
    '9.14(4)15',
    '9.14(4)17',
    '9.14(4)22',
    '9.14(4)23',
    '9.15(1)',
    '9.15(1)1',
    '9.15(1)7',
    '9.15(1)10',
    '9.15(1)15',
    '9.15(1)16',
    '9.15(1)17',
    '9.15(1)21',
    '9.16(1)',
    '9.16(1)28',
    '9.16(2)',
    '9.16(2)3',
    '9.16(2)7',
    '9.16(2)11',
    '9.16(2)13',
    '9.16(2)14',
    '9.16(3)',
    '9.16(3)3',
    '9.16(3)14',
    '9.16(3)15',
    '9.16(3)19',
    '9.16(3)23',
    '9.16(4)',
    '9.16(4)9',
    '9.16(4)14',
    '9.16(4)18',
    '9.16(4)19',
    '9.16(4)27',
    '9.16(4)38'
  );
}
# Cisco ASA 5500-X Series Firewalls
else if (model =~ "(ASA)?55[0-9]{2}-X")
{
  vuln_versions = make_list(
    '9.8(1)',
    '9.8(1)5',
    '9.8(1)7',
    '9.8(2)',
    '9.8(2)8',
    '9.8(2)14',
    '9.8(2)15',
    '9.8(2)17',
    '9.8(2)20',
    '9.8(2)24',
    '9.8(2)26',
    '9.8(2)28',
    '9.8(2)33',
    '9.8(2)35',
    '9.8(2)38',
    '9.8(3)',
    '9.8(3)8',
    '9.8(3)11',
    '9.8(3)14',
    '9.8(3)16',
    '9.8(3)18',
    '9.8(3)21',
    '9.8(3)26',
    '9.8(3)29',
    '9.8(4)',
    '9.8(4)3',
    '9.8(4)7',
    '9.8(4)8',
    '9.8(4)10',
    '9.8(4)12',
    '9.8(4)15',
    '9.8(4)17',
    '9.8(4)20',
    '9.8(4)22',
    '9.8(4)25',
    '9.8(4)26',
    '9.8(4)29',
    '9.8(4)32',
    '9.8(4)33',
    '9.8(4)34',
    '9.8(4)35',
    '9.8(4)39',
    '9.8(4)40',
    '9.8(4)41',
    '9.8(4)43',
    '9.8(4)44',
    '9.8(4)45',
    '9.8(4)46',
    '9.8(4)48',
    '9.12(1)',
    '9.12(1)2',
    '9.12(1)3',
    '9.12(2)',
    '9.12(2)1',
    '9.12(2)4',
    '9.12(2)5',
    '9.12(2)9',
    '9.12(3)',
    '9.12(3)2',
    '9.12(3)7',
    '9.12(3)9',
    '9.12(3)12',
    '9.12(4)',
    '9.12(4)2',
    '9.12(4)4',
    '9.12(4)7',
    '9.12(4)10',
    '9.12(4)13',
    '9.12(4)18',
    '9.12(4)24',
    '9.12(4)26',
    '9.12(4)29',
    '9.12(4)30',
    '9.12(4)35',
    '9.12(4)37',
    '9.12(4)38',
    '9.12(4)39',
    '9.12(4)40',
    '9.12(4)41',
    '9.12(4)47',
    '9.12(4)48',
    '9.12(4)50',
    '9.12(4)52',
    '9.12(4)54',
    '9.12(4)55',
    '9.12(4)56',
    '9.12(4)58',
    '9.14(1)',
    '9.14(1)10',
    '9.14(1)15',
    '9.14(1)19',
    '9.14(1)30',
    '9.14(2)',
    '9.14(2)4',
    '9.14(2)8',
    '9.14(2)13',
    '9.14(2)15',
    '9.14(3)',
    '9.14(3)1',
    '9.14(3)9',
    '9.14(3)11',
    '9.14(3)13',
    '9.14(3)15',
    '9.14(3)18',
    '9.14(4)',
    '9.14(4)6',
    '9.14(4)7',
    '9.14(4)12',
    '9.14(4)13',
    '9.14(4)14',
    '9.14(4)15',
    '9.14(4)17',
    '9.14(4)22',
    '9.14(4)23',
    '9.15(1)',
    '9.15(1)1',
    '9.15(1)7',
    '9.15(1)10',
    '9.15(1)15',
    '9.15(1)16',
    '9.15(1)17',
    '9.15(1)21',
    '9.16(1)',
    '9.16(1)28',
    '9.16(2)',
    '9.16(2)3',
    '9.16(2)7',
    '9.16(2)11',
    '9.16(2)13',
    '9.16(2)14',
    '9.16(3)',
    '9.16(3)3',
    '9.16(3)14',
    '9.16(3)15',
    '9.16(3)19',
    '9.16(3)23',
    '9.16(4)',
    '9.16(4)9',
    '9.16(4)14',
    '9.16(4)18',
    '9.16(4)19',
    '9.16(4)27',
    '9.16(4)38'
  );
}
# Cisco 3000 Series Industrial Security Appliances (ISA)
else if (model =~ "(ISA)?3[0-9]{3}")
{
  vuln_versions = make_list(
    '9.8(1)',
    '9.8(1)5',
    '9.8(1)7',
    '9.8(2)',
    '9.8(2)8',
    '9.8(2)14',
    '9.8(2)15',
    '9.8(2)17',
    '9.8(2)20',
    '9.8(2)24',
    '9.8(2)26',
    '9.8(2)28',
    '9.8(2)33',
    '9.8(2)35',
    '9.8(2)38',
    '9.8(3)',
    '9.8(3)8',
    '9.8(3)11',
    '9.8(3)14',
    '9.8(3)16',
    '9.8(3)18',
    '9.8(3)21',
    '9.8(3)26',
    '9.8(3)29',
    '9.8(4)',
    '9.8(4)3',
    '9.8(4)7',
    '9.8(4)8',
    '9.8(4)10',
    '9.8(4)12',
    '9.8(4)15',
    '9.8(4)17',
    '9.8(4)20',
    '9.8(4)22',
    '9.8(4)25',
    '9.8(4)26',
    '9.8(4)29',
    '9.8(4)32',
    '9.8(4)33',
    '9.8(4)34',
    '9.8(4)35',
    '9.8(4)39',
    '9.8(4)40',
    '9.8(4)41',
    '9.8(4)43',
    '9.8(4)44',
    '9.8(4)45',
    '9.8(4)46',
    '9.8(4)48',
    '9.12(1)',
    '9.12(1)2',
    '9.12(1)3',
    '9.12(2)',
    '9.12(2)1',
    '9.12(2)4',
    '9.12(2)5',
    '9.12(2)9',
    '9.12(3)',
    '9.12(3)2',
    '9.12(3)7',
    '9.12(3)9',
    '9.12(3)12',
    '9.12(4)',
    '9.12(4)2',
    '9.12(4)4',
    '9.12(4)7',
    '9.12(4)10',
    '9.12(4)13',
    '9.12(4)18',
    '9.12(4)24',
    '9.12(4)26',
    '9.12(4)29',
    '9.12(4)30',
    '9.12(4)35',
    '9.12(4)37',
    '9.12(4)38',
    '9.12(4)39',
    '9.12(4)40',
    '9.12(4)41',
    '9.12(4)47',
    '9.12(4)48',
    '9.12(4)50',
    '9.12(4)52',
    '9.12(4)54',
    '9.12(4)55',
    '9.12(4)56',
    '9.12(4)58',
    '9.14(1)',
    '9.14(1)10',
    '9.14(1)15',
    '9.14(1)19',
    '9.14(1)30',
    '9.14(2)',
    '9.14(2)4',
    '9.14(2)8',
    '9.14(2)13',
    '9.14(2)15',
    '9.14(3)',
    '9.14(3)1',
    '9.14(3)9',
    '9.14(3)11',
    '9.14(3)13',
    '9.14(3)15',
    '9.14(3)18',
    '9.14(4)',
    '9.14(4)6',
    '9.14(4)7',
    '9.14(4)12',
    '9.14(4)13',
    '9.14(4)14',
    '9.14(4)15',
    '9.14(4)17',
    '9.14(4)22',
    '9.14(4)23',
    '9.15(1)',
    '9.15(1)1',
    '9.15(1)7',
    '9.15(1)10',
    '9.15(1)15',
    '9.15(1)16',
    '9.15(1)17',
    '9.15(1)21',
    '9.16(1)',
    '9.16(1)28',
    '9.16(2)',
    '9.16(2)3',
    '9.16(2)7',
    '9.16(2)11',
    '9.16(2)13',
    '9.16(2)14',
    '9.16(3)',
    '9.16(3)3',
    '9.16(3)14',
    '9.16(3)15',
    '9.16(3)19',
    '9.16(3)23',
    '9.16(4)',
    '9.16(4)9',
    '9.16(4)14',
    '9.16(4)18',
    '9.16(4)19',
    '9.16(4)27',
    '9.16(4)38'
  );
}
# Cisco Adaptive Security Virtual Appliance (ASAv)
else if (model =~ "^(ASA)?[vV]")
{
  vuln_versions = make_list(
    '9.8(1)',
    '9.8(1)5',
    '9.8(1)7',
    '9.8(2)',
    '9.8(2)8',
    '9.8(2)14',
    '9.8(2)15',
    '9.8(2)17',
    '9.8(2)20',
    '9.8(2)24',
    '9.8(2)26',
    '9.8(2)28',
    '9.8(2)33',
    '9.8(2)35',
    '9.8(2)38',
    '9.8(3)',
    '9.8(3)8',
    '9.8(3)11',
    '9.8(3)14',
    '9.8(3)16',
    '9.8(3)18',
    '9.8(3)21',
    '9.8(3)26',
    '9.8(3)29',
    '9.8(4)',
    '9.8(4)3',
    '9.8(4)7',
    '9.8(4)8',
    '9.8(4)10',
    '9.8(4)12',
    '9.8(4)15',
    '9.8(4)17',
    '9.8(4)20',
    '9.8(4)22',
    '9.8(4)25',
    '9.8(4)26',
    '9.8(4)29',
    '9.8(4)32',
    '9.8(4)34',
    '9.8(4)35',
    '9.8(4)39',
    '9.8(4)40',
    '9.8(4)41',
    '9.8(4)43',
    '9.8(4)44',
    '9.8(4)45',
    '9.8(4)46',
    '9.8(4)48',
    '9.12(1)',
    '9.12(1)2',
    '9.12(1)3',
    '9.12(2)',
    '9.12(2)1',
    '9.12(2)4',
    '9.12(2)5',
    '9.12(2)9',
    '9.12(3)',
    '9.12(3)2',
    '9.12(3)7',
    '9.12(3)9',
    '9.12(3)12',
    '9.12(4)',
    '9.12(4)2',
    '9.12(4)4',
    '9.12(4)7',
    '9.12(4)10',
    '9.12(4)13',
    '9.12(4)18',
    '9.12(4)24',
    '9.12(4)26',
    '9.12(4)29',
    '9.12(4)30',
    '9.12(4)35',
    '9.12(4)37',
    '9.12(4)38',
    '9.12(4)39',
    '9.12(4)40',
    '9.12(4)41',
    '9.12(4)47',
    '9.12(4)48',
    '9.12(4)50',
    '9.12(4)52',
    '9.12(4)54',
    '9.12(4)55',
    '9.12(4)56',
    '9.12(4)58',
    '9.14(1)',
    '9.14(1)6',
    '9.14(1)10',
    '9.14(1)15',
    '9.14(1)19',
    '9.14(1)30',
    '9.14(2)',
    '9.14(2)4',
    '9.14(2)8',
    '9.14(2)13',
    '9.14(2)15',
    '9.14(3)',
    '9.14(3)1',
    '9.14(3)9',
    '9.14(3)11',
    '9.14(3)13',
    '9.14(3)15',
    '9.14(3)18',
    '9.14(4)',
    '9.14(4)6',
    '9.14(4)7',
    '9.14(4)12',
    '9.14(4)13',
    '9.14(4)14',
    '9.14(4)15',
    '9.14(4)17',
    '9.14(4)22',
    '9.14(4)23',
    '9.15(1)',
    '9.15(1)1',
    '9.15(1)7',
    '9.15(1)10',
    '9.15(1)15',
    '9.15(1)16',
    '9.15(1)17',
    '9.15(1)21',
    '9.16(1)',
    '9.16(1)28',
    '9.16(2)',
    '9.16(2)3',
    '9.16(2)7',
    '9.16(2)11',
    '9.16(2)13',
    '9.16(2)14',
    '9.16(3)',
    '9.16(3)3',
    '9.16(3)14',
    '9.16(3)15',
    '9.16(3)19',
    '9.16(3)23',
    '9.16(4)',
    '9.16(4)9',
    '9.16(4)14',
    '9.16(4)18',
    '9.16(4)19',
    '9.16(4)27',
    '9.16(4)38'
  );
}
# skipping Cisco Secure Firewall 3100 Series: all CVRF versions are >= 9.17.x
else audit(AUDIT_HOST_NOT, 'an affected model');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);

# vuln config requirements:
# (local creds || http creds) && sslvpn enabled && ASA <= 9.16 && clientless sslvpn in DfltGrpPolicy

var cond1 = {
  'workaround_params': [
    WORKAROUND_CONFIG['local_user_with_password'],
    WORKAROUND_CONFIG['aaa_authentication_http']
  ]
};

var cond2 = {
  'workaround_params': [
    WORKAROUND_CONFIG['ssl_vpn']
  ]
};

var cond3 = {
  'workaround_params': [
    WORKAROUND_CONFIG['ssl_clientless_DfltGrpPolicy']
  ]
};

if (get_kb_item('Host/local_checks_enabled'))
{
  var res_cond1 = CISCO_WORKAROUNDS['generic_workaround'](cond1['workaround_params']);
  
  if (!res_cond1['flag'])
    audit(AUDIT_OS_CONF_NOT_VULN, product_info['name'], product_info['version']);
}

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwh23100, CSCwh45108',
  'fix'     , 'See vendor advisory',
  'cmds'    , make_list('show running-config', 'show running-config all group-policy DfltGrpPolicy')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params: make_list(cond2['workaround_params'], cond3['workaround_params']),
  vuln_versions:vuln_versions
);