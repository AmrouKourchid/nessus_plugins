#TRUSTED 6b513c376f2a442255689e34cd7c185213a1559d74cdafd429a2114ed5f16a2d3d73385f679dd342fcacb40d39f13451a8e272cbe7edd1af330643a3f813049fd93ae687c30d1d8abd78a10049bdf9dda5ce812ff30786c826649a47d355f576166a1d6ec0551e62a22ccf699a3f6d46443ee9cc99c7aa4de466d8aa8d920fa33e0186cb99a13ba01dc42919c624161316fbc570ada4fbeae7f9674dea5da3204b5a16c1d83ac650e0cade8a934b6e2f2c32d862716a4a54d7c2624ee1970fe0c7088284669c6d0f61571b756ed65c28b88529afb529ad1570ef20ed656e2823d176de6bd334e7c94a689343ceca29735afdbcba39a696edfe5beb733866e31ab5657a10fd178baa6a03b10417444e89b95b70871060f2949d76cda9a9550010cf4079a34b0939f4fe2d6a284859d05a10824abf5dbe10f72b209d1c5e49350b79b98199e2f0b7ea402b003df9f89f94cddb99ce5f3ce843c4a07f0d7b946615260a33ba11ba7ee7b7a7428ec407962bc447fde58a43bd0095a8d9c44b75ece467b21424bc45335d102831a8120b4f54a6d21001c00e036e24c026baf3f189d1c49c590891fffcf836b0a14c6f65670159fce6f75b130d801e8a37dd189d3ad891f4b91831fc31fa9b049f78b27ea3c7b2aa7fe4aacbec87c2ac94930322935d3a2b40985e840f711348988fac96582456c59ce9dcc6d538d400232fcca91875
#TRUST-RSA-SHA256 09ee3855498630b63a261897234512ac8bfeeb575d77fc00a8be8f12ca6ae3820656dc943c681feb8ad3ce4c078d2e571f97d5b3802e67b0c611fe4c4eeb5ba6184e6ca7530a064309bbe51b4945bc416f1392a127c520fca75f1c8969985b7f47311c1745d228910103a7f52777ee4492d210f0fa22b5df87d8da1e227fd2a9424d4519d2f8d4e3361d62f9e7ebc3e3521258e71a87d21e3073d6235c3d13426be5e676cd4e92a806d99b63b499784893aa2e4fd566d8c199e1745dcda72af35e699e6a2c34eca91fe859ce14b4ca82875333f0887fe888fa98c3c0b2da14f5020d5d2ba67d752cc1df3365381248887cf7fb08cf01b2c0c57037f46de4a0ccc70f2cf2c6d1680eb2e8f86915d31c54c157f7c9d6eab86104e3a0f3c879b957e3157e44468c40a4a4a13f5da5397475baeaa770f6d300dc8990d08d43ab56f7e02224fad832aa92eb79833f8e833fbfcadc2427918d7b2690e474f3d6abbcf67f1fa127fe7dd108c68b20f427f455c66eb02a5480ded2ffd72c529077cfc43583fa3f568d2767a7f569890fcff0ecc6fad1fca97a202029ff22afd20887f97892a49601aa5b31ca16421d6d2e84d455222e88494bf68fa1e2c37d9c3cc6b4faa385d0aad07ca348ef8bc299a439ae9d0b40778be0b68c4484edaa03929efe8511d1bdb068340992ac4f22273e4899080e0bad2bcc43f80ba173f1d37c87bf36
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138148);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3229");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp95718");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-PZgQxjfG");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI Privilege Escalation (cisco-sa-webui-PZgQxjfG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by Web UI Privilege Escalation Vulnerability.
A vulnerability in Role Based Access Control (RBAC) functionality of Cisco IOS XE Web Management Software could allow
a Read-Only authenticated, remote attacker to execute commands or configuration changes as an Admin user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-PZgQxjfG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a073145");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp95718");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp95718");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3229");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.5f',
  '16.9.5',
  '16.9.4c',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.8',
  '16.6.7a',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.9',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.10',
  '16.3.1',
  '16.2.2',
  '16.12.1y',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.3',
  '16.10.2',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp95718'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);