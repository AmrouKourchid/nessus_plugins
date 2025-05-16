#TRUSTED 29efbb1835b6e05ba120328df5a27e9521d5557519bc2d5fbaac9784516f89911fa64c093966b87f2adc9670c5d0c5d5ea19e37e62f64d9c47c634dd0ff15db0cdca11654823ba582f8b032a6e76df2148e9c67c7e0f735eedd4f44e43f3fc136f2d02ed7016f026af7bd1d63b76e8de295d4fd2cbc7209b3d1e781a284f13908e48208705c40e135744e4dadd1c81b1723dcccacf5717322398a227df8416774105cbe8f2b81f86b79054bdc88fd96059e89f3640536e7561a0715a9d24f8f9556c5109de3aa7a89459fd2b88ddc17cd1278729824cb2819271bc980ae697d877588d6fd4e209b3a91d8c266e8cece5ebd4f3b9950d9dacf192a493af82a133317fb5d7c80bda5e1dae3bf4faa56be079a9265136fe7e1e3eeb17aa1c4c2c92cd8001797e97a6010d149344461aaeb3d2d6ad3554cc4fdc65454b0ead374e20038a337835677cd4a0384f1d3ddd9fe44a819880e337b531b1553d69e9259c2693c3d383f8f790ad5e2b626f07be68c61919902fcc0aea0e2ec63285b1839a0a1f7fdbb085ecbbcf152e7529d40212b31c5a39fa4f4ee5fbe3aed111b953485e4afa76070a4a95a42ae59b620c5ead003a4787b22790afe11fc45ccfc69603eefe90c709a4c3dc1a537b05d21aa243eb77671ce4bbdc136d84385d9955c11693faffd956c9b28201ad69a891c7119a78cb8537771db50af0e4f5bb96082bf692
#TRUST-RSA-SHA256 0e62d29344d1619fac1cfc8a3d7071cc3be464caac326ec05aa95e8afdce250bc1c3009f33c6c4bb80c48bd7d5b53be4fcd8073b8829d1f172ae9b475ab80419c013eb67f4605ef5ed775824a656c0799b2ec8b0cd8b5c0ad64cd9f17d54df46b6d99451e39ffdc14cebc45e0d231f1203e6f30b53fdd3ddf28e91ed0321b9fc0b4636a578dbfb308430273d622153aed4f0269b480d6bbde7b536ee5bcc6e356a8c1b4472f5f0f37edcaf79de5c095a02e645bb6aa99ec0ba159211cb1655eb00db6b595e1cfc0293f12c433c460a57c9e3ac24e80765fd64a437c9880f815b171ba19f2869d6c67843363f317d5aff3ced6b70a9891782be56302ca9d9a47bdc88048e93bac885d622ac55379364731f58161496b264de168aca463ab92d89a5bcf5180624942d6ac0af78266cf7988665d9c8a5be5d622d73fb0b9a104896afa414bca6e49768980089cd528e87957d516af9655e2ad5d492146857e218735b017bcbf49ae13c2f13dea70bb95a741244a0fed7289d7a741ba5166b5ef940ea863f00c35cf13ed99e670c1c85cc62192bf0e8e826f9f89535cae6e493fc21c1949cb5e6e07d3402813a7d81992dba8cba3ec28966fa7af1f083fb19d65c266d088da5f50c3ed1da46e4523990cf54d3e4004659c6e1417ada8b4becedb805c0939c0740b5542519c510c76cb2a733bdcf277308ec2df3483fee5cd0d5b612
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130916);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/11");

  script_cve_id("CVE-2019-1774", "CVE-2019-1775");
  script_bugtraq_id(108371);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh75895");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh75909");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh75968");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh75976");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92256");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92258");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92260");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99195");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99197");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99198");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-cmdinj-1774-1775");

  script_name(english:"Cisco NX-OS Software Multiple Vulnerabilities (cisco-sa-20190515-nxos-cmdinj-1774-1775)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by two command injection vulnerabilities due
to insufficient validation of arguments passed to certain CLI commands. An authenticated, local attacker could exploit
these vulnerabilities to execute arbitrary commands on the underlying operating system with elevated privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-cmdinj-1774-1775
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?217a964d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh75895");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh75909");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh75968");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh75976");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92256");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92258");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92260");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99195");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99197");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99198");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvh75895, CSCvh75909, CSCvh75968, CSCvh75976,
CSCvi92256, CSCvi92258, CSCvi92260, CSCvi99195, CSCvi99197, and CSCvi99198.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1775");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';
if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^7[07][0-9]{2}')
    cbi = 'CSCvh75895, CSCvh75909';
  else if (product_info.model =~ '^(30|35|90)[0-9]{2}')
    cbi = 'CSCvh75968, CSCvh75976, CSCvi99197, CSCvi92258';
  else if (product_info.model =~ '^36[0-9]{2}' || product_info.model =~ '^95[0-9]{2}R')
    cbi = 'CSCvi99195, CSCvi92256';
  else if (product_info.model =~ '^(55|56|60)[0-9]{2}')
    cbi = 'CSCvi99198, CSCvi92260';
}
else if ('MDS' >< product_info.device && (product_info.model =~ '^90[0-9]{2}'))
  cbi = 'CSCvh75895, CSCvh75909';

if (cbi == '')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '6.0(2)A8(1)',
  '6.0(2)A8(2)',
  '6.0(2)A8(3)',
  '6.0(2)A8(4)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(5)',
  '6.0(2)A8(6)',
  '6.0(2)A8(7)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(8)',
  '6.0(2)A8(9)',
  '6.0(2)A8(10a)',
  '6.0(2)A8(10)',
  '6.2(2)',
  '6.2(2a)',
  '6.2(6)',
  '6.2(6b)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
  '6.2(10)',
  '6.2(12)',
  '6.2(18)',
  '6.2(16)',
  '6.2(14b)',
  '6.2(14)',
  '6.2(14a)',
  '6.2(6a)',
  '6.2(20)',
  '6.2(1)',
  '6.2(3)',
  '6.2(5)',
  '6.2(5a)',
  '6.2(5b)',
  '6.2(7)',
  '6.2(9)',
  '6.2(9a)',
  '6.2(9b)',
  '6.2(9c)',
  '6.2(11)',
  '6.2(11b)',
  '6.2(11c)',
  '6.2(11d)',
  '6.2(11e)',
  '6.2(13)',
  '6.2(13a)',
  '6.2(13b)',
  '6.2(15)',
  '6.2(17)',
  '6.2(19)',
  '6.2(21)',
  '6.2(23)',
  '6.2(20a)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I4(8)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8z)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '8.1(1)',
  '8.1(1a)'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , cbi,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
