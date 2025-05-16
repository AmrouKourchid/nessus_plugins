#TRUSTED 85a80a24f7b3c536372a3ff968eb356b4db8a1390e2c2c00facab162954b861842f4328073e7fd1c5ea346002e89427e7a61c66a53e521be0d5c0fe3d677ebd3a7dfd0795f7b5ebe11537f8ef26e526165fc45e2df54ba538c890e4939ff16bc37d506aaecd92b8ce9c20531e64475b837a29ff966cbf836512b72aa9cad77bcaf3aa25b57388b95bf354268ad822aaf041375967312e081a762d91ab9a788ffca2c9c4586c471376421c348cc3060c80d8b4fde406ec3e4b5a3e0f25ef83e42c690f3974801eedffa6a544fa817e5cd514196893284746e0e635bc258816193df135adb7e7aba7b400881b00ffd2c3565fa9edbc1e7ec705db5930f1fbb8d3a165c973785c0f2ac302c5c5225efae20c20b3907710831b442c9e0599afc62b95d44132cafcf8597a07857048555d444a05381bc88a95f85248db7bffdd3367cda73fd275e378c0b90972f9c6554376cd10b9844ae65f1cfeb0fe21864ef5fc5acd92f8eb1787fd4b08eba1d656bb207d1ba70c41ee1c98b341cfeb57a065f409f83240f796458dc9d0a075947221ae543ee7cfd73fbaa06a47e7acf325c992394b7e11dbcb573fc07fce6308789940b90ab55880041ecc3eadb8e2a6ba83e96121c794e1433221b418fe2f25075a997244f805babe7f389ff7389d5e5163e5c57ff6228f1f63d43b629dff5971796a539411aa8ecaaf0c72ea4d5ff1baf14e2
#TRUST-RSA-SHA256 3ff68b87c9818f698b3a7e30d6465bccfb3d815f396fbb5f8e316fe8a64cf29dbfa3f981cb414cf5a9efdc0d562cba8bfe9d4c87fbbd4d2baa577db2004c644c044ea7335b48ae85f4a6c8e5d8477f71364299c1c9b6a4986f1e8197f07b93d893428cfd9868b0f51118f2ab9a369863e954bb4d47774a555dc35090c719663d5bfcc9f577eb3f4c72dcbfb612752bd2781cd5a7bd26e0adf7580f5b079957fc3e3bb7c31682ff23649afd10a7da26d727e44a98a305b8c2e5ebbc5d0afcf0c176788f0883e93e6a5fb1d3e7da0d7268b17930949a9a2cba1582d1f271bb32342b269b37faf5c12eaf50f3a00baf6b67637f5ea9b435ec963d49772a5b0f02ded9d58ec61d4b2cbb58d93e48d14d3c6b85b446eab3515b5f4206a9a22b55730d5b11678219a280ff24b9ff85faa319ac0f04bf48c1a3e2af0a96e59d7f3a799ce5ff533d93fda7adb52c9c43a5fc3fe60c570522ce48df79e08cefc5639a563a71c14de6df6cada9af2e481a1d5241d795dc46cc05510a4dcd33a4923115e1001c3e49111831d7590d7ec3ba9cd03b9572bf2f9d5c7fd975c1b12bfb42b3eaaa1b81fe281f3240056eee5fc8e095afa095e2d2e1fd0d3517eeb89016adc6fc96e866d739956aad3eedc749b7668443c57d2d68f862c963c36819f1da4ac44ae35bc3b659fb54e10386bfcba39dae31d3f4cede1db213082b8f76dedce25b9cf3
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153895);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-1619");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt53563");
  script_xref(name:"CISCO-SA", value:"cisco-sa-aaa-Yx47ZT8Q");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software NETCONF RESTCONF Authentication Bypass (cisco-sa-aaa-Yx47ZT8Q)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software's authentication, authorization, and accounting (AAA) 
function is affected by a authentication bypass vulnerability. Therefore, it could allow an unauthenticated, remote 
attacker to bypass NETCONF or RESTCONF authentication and do any of the following:

Install, manipulate, or delete the configuration of an affected device Cause memory corruption that results in a 
denial of service (DoS) on an affected device This vulnerability is due to an uninitialized variable. An attacker 
could exploit this vulnerability by sending a series of NETCONF or RESTCONF requests to an affected device. A 
successful exploit could allow the attacker to use NETCONF or RESTCONF to install, manipulate, or delete the 
configuration of a network device or to corrupt memory on the device, resulting a DoS.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aaa-Yx47ZT8Q
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?086551f4");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt53563");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt53563");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1619");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(824);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.6.9',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.9.7',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.10.3a',
  '16.10.3b',
  '16.10.4',
  '16.10.5',
  '16.10.6',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1d',
  '16.11.1f',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1b',
  '16.12.1b1',
  '16.12.1c',
  '16.12.1d',
  '16.12.1e',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2r',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v'
);

var workarounds = make_list(
  CISCO_WORKAROUNDS['enable_password_no_enable_secret'], 
  CISCO_WORKAROUNDS['generic_workaround']
);

var workaround_params = [
  WORKAROUND_CONFIG['aaa_authentication_login'], 
  WORKAROUND_CONFIG['netconf_or_restconf'], 
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt53563',
  'cmds'     , make_list('show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  require_all_workarounds:TRUE
);
