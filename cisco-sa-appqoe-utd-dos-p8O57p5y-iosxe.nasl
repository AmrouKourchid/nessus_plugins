#TRUSTED 2ff1871059d616ae7ef890ad0df63f772513ea58f19ba863632db17887985d071b33789779913eb835cca7405d417a49aec054566f6073239665c0372d907469bbdf6637f1133f759c2a88ca4e4a25fe1f1c4ccebcdfbad2522649bade1a42377371c3884136489ef769517e62d620aa65b67726d556c3f9217a1afcdcd87537c6db3f7377d322d17549ef0abba7e24910be4db705c20f1eb3f22c4166790e1fb9a346d5207f4a3308a461c6d316b9d86a4905ff6cb90695f957919147cf65ca7184c51e1d96aae8d1804abac0b4c2823a8da832397460aa8a38ee940fd19508b1c8caac237f0744f0920c65872351a130023f7a3d768680abcc1b445957aac2b5f4426012bc35cec5b1fbdfcb0f7ed664828d21103ead1b66afceaa68eb59542c0e1d00dc86e68357ed2e7db8cd06ba21f4359e32799bd16682d8a21035635e738a2ff96c660fe3465111c447980bd9c52a58cb14472686e6f88ffdcba37b7a4680c113d50aa6d3bd4642f3131acc37e911c0b3708f8c74953b46cc12ecc21e94afdb2da42d60b3b67d8d27d1bb30ab35d5d9f4eebe06b75c92f45628fe858399eb3eb5b8cbe9409b2ebb8e2c812e194a1271bb39ce579e086dbc73e4537f3aaf613c1d6f726a218c0d776b1105404c2ed3d31203bd9eacf3cd4a357eb330d2d30f307ddd63cb17fbfa84686d0ffe2f9a0e59d16d7224c8ef5626d95d9343aa
#TRUST-RSA-SHA256 2e683a4d47d1451045a348382ea27cbe0b91087098302fb803c1052b3529bd82683d3364e9c8aff1381d3fd029bba4f997b60cf74978c5cafc9474f4de6d2e49c20d6310a159559a3f6d32a8fc1cf4cb726fb322eb1554914b114df8ed3e47b5f88c1eb19603c1c76ea1240cf02b7de9c56196d8e8c94ead2df6691f1b8bb684b991c7f6880162656b68e1fa1ffe8d6df81ba1adf33ed73761a92b54faae7812d0fa47fd030b036678c709dead4c59b7fe2abf77539b2f09ca59396b144ce19299ecbb53c1a48467a5e62ca22847fea454bb77f3917b4b56f92ec132a6a526705888bc6a0eb96bb336d8188780d96f815741a3fe55f4d3bee20d0f002ded0a4ace56dbd10d0bc9848ad728a3ed59eddbdc7365841a17ab29083dbdbf046d702834385d55fed86a07bfef04db2e8a5b74729aa082766f3c0be43bc11fa791275d0019322307e8c83c5adb21e8baf01ad5cf59ca968782273076b94878491f0baf7c384e16e2fc6eaf108db75141bbd5943904e5db2f7daaa8efaa71178b850d8a3d8db668aafcee15809c9ed1eee97a06bb50841d6b351a06e52196831d681f0a9549c47d7c5d923375b498c50e3571f842c980a26ace783f009d11040ee92133f4358b1a87eb3d55ecce1ffd3b317abb46e1d51fe1513a32b52304c58dbe02a886e2f88d2e80611639b4734dbb9e80dc4fbb1d7ad78606e02fdc6000148ba18a
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182200);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id("CVE-2023-20226");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd67335");
  script_xref(name:"CISCO-SA", value:"cisco-sa-appqoe-utd-dos-p8O57p5y");
  script_xref(name:"IAVA", value:"2023-A-0510-S");

  script_name(english:"Cisco IOS XE Software Application Quality of Experience Unified Threat Defense DoS (cisco-sa-appqoe-utd-dos-p8O57p5y)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in Application Quality of Experience (AppQoE) and Unified Threat Defense (UTD) on Cisco
    IOS XE Software could allow an unauthenticated, remote attacker to cause an affected device to reload
    unexpectedly, resulting in a denial of service (DoS) condition. This vulnerability is due to the
    mishandling of a crafted packet stream through the AppQoE or UTD application. An attacker could exploit
    this vulnerability by sending a crafted packet stream through an affected device. A successful exploit
    could allow the attacker to cause the device to reload, resulting in a DoS condition. (CVE-2023-20226)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-appqoe-utd-dos-p8O57p5y
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a8a74ca");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74916
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3520ae2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd67335");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd67335");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20226");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ((model !~ "IS?R" || model !~ "1100|4200|4300") &&
    ('CATALYST' >!< model || model !~ "8[0-9]+V|8200|8300|8500L") &&
    ('IR' >!< model || model !~ "8300"))
    audit(AUDIT_DEVICE_NOT_VULN, model);

var version_list=make_list(
  '17.7.1',
  '17.7.1a',
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a',
  '17.9.2',
  '17.9.2a',
  '17.10.1',
  '17.10.1a'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['utd_enabled'],
  WORKAROUND_CONFIG['appqoe_enabled'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwd67335',
  'cmds'    , make_list('show utd engine standard status', 'show sdwan appqoe status | include APPQOE')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
