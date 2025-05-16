#TRUSTED 10feab7bcce34f8b2d21e9c558d8a2279c91b68660159058d4f44229883541a5133cffd48b2ba7455df579a1d7999f57be9b4ab524812bf0ee0554f81c73c713e01b8fad5e5158211ac284514c617290a85c78f3c3f2f1768c8eb0df0ce15172da94f1f0159d3c5ac3a3bd75218a50cdee9458d01beeb9e0ba8d961c5c7f5e6b57526187b98534c016012104433ef8e9d4de25cd1ff9525fea931a308ad73d75ad3d391a8b548835804e5a55beac6633cb95b879936f1196cde845fe4688efe4cf47dd186c8e3b8066371dffa352f282438616dd528c2b280aa5c7ec403ef53dcb47973cad9b90e5a9381a1af64d2580f686f8ff7a1bca01b34f7d020e4a5e52dea786dcad0d7d8705ddbb157ff3a6b89096db7001e51324335fc1664932b88666e8a1846ab2f100a57d7a48212f72cb3c213dfa15e916ca4a782b6fa36520594818618dcb04f90cddb91b742b1c0a468ed00b68aeff493828cc33fdab2a7f2634813d88f5b0f9c04cdf4421f2d73c2b7cc663ad089d1b1347b72556e117031c34a221fa208478c1669ebb16f75d1ce536bb6e45532154a8d6c13fc7694fe80f6feec00b5e4ac6d8e2034589a2e435443869e5eaaf057a65a00f4d0592a7117903df683cbea07ecb9909aa33894dcde2d6f14b88fcddfe3ed72eafa8abe88ab1f84592451a82527ea2ec4e94c55f00f915f409428f3519d4c2f30fd0f5110ae6
#TRUST-RSA-SHA256 4aaa75216a8c3ac961a313fec892c067cb33864f096cb361285c4f7e41ac051b5c264045d899081b206ba2c67fe1107b623b77beb5e8b053f1c006709e8dbecff054e73a170ea5dffe355ba0cb1249a39a9f42d936a94222343170bcea5eda9aab6de0161e62e5972e1c7d234fbb06e41e90bf1753e72bb870273c93d1899ff26018914987b1560471bb25e55c442cf05f91802d0fdfb99edd0555a01373112ea6a572242453842a826db9cd4601231812bd78b0dbb34c69343256f22fea53434a400f856560e54fce4d47e54f0b2e304488823b92df367e58833b930d100338ba8aaaa2c169b67d593dd7e26927a8d12e9207784f3633070a7e3c240c97a47ba516b87ca4acfb21cd32cad4985a443d04a105aa8efa1801ddd57c8a71e89db421e02af3e4aba08e5f79e09997e335f9b527ea1abe85ad37f58499d69889dd1456e5dee01b24a11d0fd0ebf6c662ad542080ccad9bdf4a4acf8d1b15a028ad95f170164791273f05c7233482120e5ea9ec3d90b3ca536e14aef68efeb9acf8220e42f919ee768004a8a976f222649483e4398d6c024cd7ca490a2f2c8a9ec39187c20ca5847af054c6e6f1c35638d307b9eb3c407c3199bd84bd99fa6c9d863e393dcaf23835cfe6b9e34ee6a0d7b2bf9afe7f28d7f0a21935df2d3df3d0566be4c4117504e8c9b8fe130aa78c46fb8ba023a805965c5fe26dc4f45f8e1e1c38
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140097);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2020-3394");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt77885");
  script_xref(name:"CISCO-SA", value:"cisco-sa-n3n9k-priv-escal-3QhXJBC");
  script_xref(name:"IAVA", value:"2020-A-0394-S");

  script_name(english:"Cisco Nexus 3000 and 9000 Series Switches Privilege Escalation (cisco-sa-n3n9k-priv-escal-3QhXJBC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the Enable Secret
feature due to a logic error in the implementation of the enable command. An authenticated, local attacker can exploit
this, by logging in to the device and issuing the enable command, in order to gain full administrative privileges
without using the enable password.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n3n9k-priv-escal-3QhXJBC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c634fbd");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt77885");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt77885");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3394");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "^[39][0-9]{3}")
  audit(AUDIT_HOST_NOT, 'an affected model');

#  not 9k in ACI mode
if (!(empty_or_null(get_kb_list('Host/aci/*'))))
    audit(AUDIT_HOST_NOT, 'an affected model due to ACI mode');

version_list=make_list(
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '9.2(2v)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.3(1)',
  '9.3(1z)',
  '9.3(2)',
  '9.3(3)'
);

workarounds = make_list(CISCO_WORKAROUNDS['feature_privilege'], CISCO_WORKAROUNDS['enable_secret']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt77885',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  require_all_workarounds:TRUE
);



