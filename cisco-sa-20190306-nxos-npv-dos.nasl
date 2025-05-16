#TRUSTED 624b5613b81bdd64fe38f20458dc9b1524ae2cf297c14f1659f9fa0768bc5f42710ebeb1bc03c87fb06fc9c40c5255722376826c4c9a2f97974e31307876a026e510be7486ca3eb81db186741d74a00b89f966e58e45dbaa20b3e9f0175840716bb10f431d68298f01a185a0c5fa3b8915abf3243490cec7a9958471b6be442d9d1310f7c2eda9128e3198d422230c6a15add4a91656c5aabb02993103d65460cdb8901663cff1e9f8bf09ee882fc91dba63e0bd7231aaf1fdcf796614de57a2e8f3340514668165558debc3da7dc6d44dd5dc184e0c21988216a0724e4ab2a32e67bc9f725ac508152dcdf2cfa3076b5f7b1f0badaa04437614a77cfea1034d0b33d28da119b60210b943e1110b0f79ca321d0c082ace4d41333d0c7dc0c37770e395b4ad50a566180bb8f8662c316759ba7e8ee5e4953ea366464ed0353f02c146cb2e86dc12f94fd6892a33bcc931c5f64df12508e796c7af61d81266c025ba77babf11fbd39e3c60534ed5adfb0b06494959ac9bb323333d71a819febfc5e517596579286c5bcabc78fff59aeb80c715f33403d6311b998dee40e9a1e4856f58712ea09de50b62eb4647b026903a05f235635298561f00ea0f88796331eb0ebdb50969e0847849abbe9c86fd8f855fa58ad263819f69b2953afc7c0d58ab8584929a56c2632e0713dfec41b2f97a7a044a39c3159554ba0149d6f9814ad8
#TRUST-RSA-SHA256 549d81fd1245e69357cff77b66e0ca635e44e7bb21601b6c45451ba5dac225d8b5f1363fb3c7bd1361f81d8a89223790407b97734013965fe40905b055116a81fed8b982439570922b7d560c444d1bec7077269db1e03516aa1b86c9b17d41a6ff9099ba472856ee9c020c07185ac55e2769ffdea03d8251f8d9943e2afc07f73073fc0e7008211fc02507eb4ba5ad17d6979dd60779c2cfa46582f4d72a83818a49fdc43b8cf1b16a6e0632e0b41ad73c9e5df99960d3e7b4212ab432b05f131ad58beffdab3189a57ca7c20d739ea4b180f845323e5e561a642242d5230bd26ea417e5cc48bf4753ea8809a83c35d11bfb0d0c8d383e9a19b1b86eca7dacc21be4d97e6536a85d9a6b2d80d5f54cf372e94294b25b73bb204ea14961d4e89178da31c0e8bcc6d6eea4644b21f887d1e5c423eadd8d7695f3ca53cfe3d5efe98fd9724e188091a6902bb73ca9cfbcbfa1b07185110db7cff3911ebb53c38e218f7dc89eade77426b475b8e6277a67be24ca23f6f186cd86a8085c8f96dce0cd1ef03c22e57b5a245752960509c1bf4252d37de52a9596dcfddab781c738201413f8be4858448cbdcc82153f945bbdb48248df1222a110686ee68b4e3b6e4d99aaad1bcf4b328111d667d99ef0b7a0a2912e955f8b6ac5c535653f8a9edf297c9767d479c7513b22b41c286dc31664c07f3e3cccb6d4a45331a718f0c21d5fb7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138354);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/01");

  script_cve_id("CVE-2019-1617");
  script_bugtraq_id(107336);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk44504");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-npv-dos");

  script_name(english:"Nexus 9000 Series Switches Standalone NX-OS Mode Fibre Channel over Ethernet NPV DoS Vulnerability (cisco-sa-20190306-nxos-npv-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a denial of service (DoS) vulnerability 
exists in Fibre Channel over Ethernet N-port Virtualization due to incorrect processing of FCoE packets. 
An unauthenticated, adjacent attacker can exploit this issue, via sending a stream of FCoE frames, 
to cause the system to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-npv-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d825de1");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk44504");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk44504");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1617");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ '^((90[0-9][0-9])|(30[0-9][0-9]))')
  audit(AUDIT_HOST_NOT, 'affected');
var buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
if (empty_or_null(buf))
  audit(AUDIT_HOST_NOT, 'affected');
else if (buf !~ "N9K-(C92160YC-X|C9272Q|C9236C|C93180YC-EX|X9732C-EX|C93180LC-EX|C93180YC-FX|X9736C-FX)")
  audit(AUDIT_HOST_NOT, 'affected');
  
var version_list = make_list(
  '9.2(1)',
  '7.0(3)IX1(2a)',
  '7.0(3)IX1(2)',
  '7.0(3)I7(4)',
  '7.0(3)I7(3)',
  '7.0(3)I7(2)',
  '7.0(3)I7(1)',
  '7.0(3)I6(2)',
  '7.0(3)I6(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(1)'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['vpc_alive_adjacency'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk44504'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
