#TRUSTED a0d69565aa579bb5675ac5e52d6bf86b38790e23b03f817c4f28c621cb0088965349179b81328d8be66a6053b2330bacc91f48ee8e2a6fc7356b1f2ab17b09f60f09a89cb8ab43c82d0b75d919bb508b23ce5d3516b8d50c36a085bacfc9a4be9dbc3caa79ddbfd8eb146f1ef1ddc1348114b382fbab5276ed095cecfc251a8d8ff605bc343f42ed4b2d6abb90e36cf8ce03572f55330d41a96612008fd028b74c4c58741ac4250a4124294198d2e9528de33f60ba6442e36f483de768001f63ec6fb334ac6a175a7103ecb2d14e232a87ad7173fbd15b4e5d01592d36a0559079ac60ac290bd944d16a8647391de8d10bc1f9306b3054e89ae3d66fd2c6567332f84492344991b0c079df437740ac84d91e05cc66452e9aec59f36f55313534733ec6aedc6a7d875d8bf07a56ed9cb7ebbbb5356d39aa95deafe660a176338e644446109bb8c55a8bb1e71842223e6d1c43907d5c1a278d707066e6086d375fce887fd151687d92949f770423fb9a4da2df01754b8aeadd5734faf3ef9cebb7a0399a8a670fed8fd7577c7511fda447854ea2a9289bfeeeb69d2f3f538e2cb56fee17345d8fca64855c61c78e561fb127b6f2f11e9e1377c6f560f84de77d7acbc38c910bbc8559dea4f0282f5007568158af44498ca7bb696946a5874262dc887838f650352f9d52757fbec3ef915d73a406d6e6f4a825cae39e64387fa496
#TRUST-RSA-SHA256 20044b3f1a71c2d27db0174269a6c65ed6b6675aaf3549f10f8be36dc1d79f1745d243e2755ab7986cccb25f7613d99840a8a96d371ce9f5f2e6aedce24e3d4e714bd286e26abcddefd1fcc762609c891988fa4e1aad79e02766689538b86fedd5da7c13d1da72d90755e795b946308bd2e34d2a390a89a68cb14febdae1092514aabceb8a835527d49d974f5d9b82c21b31634a5a9130034e7f87f137e3584124141f446325b019f7c836af9d521d582c539eb5f562b83f367d6dddac5623fdbbe827f133244d6a8eef3bbc9be8ac37e8acc68a0be2e5cf741bd80e33ad8899f46155a265b1e111cb1e41734249090a82f2d9772b89692a05ebe7e14301eedf1104e4fa961f4602c4cd8d2a046258b8eb7229e9615ad61dfdce6f8bcd965cbaa4f301059e3dce964847677802b41da6c6d7c4a4f39320e82233cab18536e76b9b2dbf4b9fd9429e831870f6513bed08d3ad54f0ccba4ccb1c9f784844a293afc041f985bbf5f06d238f4aa61b7466e6795cdc16fb418305c2e71b8737fc0d9e66033bb8e226b9a3b8b2a029e69bf3a7012849a2f126998fb73380e1a3277ec4eef553b4a8591b2b07f91ac6c08d06c423f361215cf2a24ab66746ff39ad8859fe5caa43ab10c80612379950eec6a60f9f0ae41086e568cf727e8ee34e1255f7ac2fa97b1be9820c8dc5dc5d32399dc890db58dbaed9cea5371faf8672496cfd
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141266);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3390");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs56562");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-ewlc-snmp-dos-wNkedg9K");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Catalyst 9000 Family SNMP Trap DoS (cisco-sa-iosxe-ewlc-snmp-dos-wNkedg9K)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS XE Software is affected by a DoS vulnerability in the Simple Network
Management Protocol (SNMP) trap generation for wireless clients due to the lack of input validation of the information
used to generate an SNMP trap in relation to a wireless client connection. An unauthenticated, adjacent attacker could
exploit this vulnerability by sending an 802.1x packet with crafted parameters during the wireless authentication
setup phase of a connection and could cause the device to unexpectedly reload, causing a DoS condition. Please see the
included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ewlc-snmp-dos-wNkedg9K
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7ff3e30");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs56562");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs56562");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3390");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

if (product_info['model'] !~ "^(C)?9[13458]\d\d($|[^0-9])")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_versions = make_list(
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.1z',
  '16.12.2s',
  '16.12.2t',
  '17.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['trapflags_client_dot11'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs56562',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
