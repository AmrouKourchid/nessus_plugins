#TRUSTED 5ba9ae265a43bf11ba160fdd9735c8a232a1f2203380332d59d1f814b78849b520682230d2e54807fcbe935fa4ea6e32a328ea69d3a711aead854adfe3c42ffc7f3107cbc0297cad3c34d8e9cfe3799bb5f79e020875badd116bb9797acc0005e0af33974f5fe327499fa4a129998fdbf8abbf5ae4eef7aacdf0b0b909e0f302fb28a2c69db963d21a3770ca9b04f959b12ba51bcc123d2b9063eec56a6c141f482ab235e3b91e82d608a14321d4c3706bf758966382772f29dc762f4208348426d14b6cc6831bb3090e9bdb27a9a2661a01dc116aa499739f4f12a7303db807815fb799dff20a9f067562c03ab7efdb0643b6bc78c794533dae83d78a84ce9d10cdf86c1dc9bbf8ff8c21128305dd827f56b1173e5c738f7e93337ad26d191d8280a7ead024fa18090777ed8cb147881ec3a7ede3e0ed3c75a10d0614c1c0bad2e73ea614ba4921d8ee324cc59d2d791ac293eb52ede47ede209506fdec6e9be49e9339f8988dc12809001a4789e49a98e40fd23d4ae5ae134ede61fc6c3681cefa85be10ce2a0717119f89ab88d8ff60e55f62d2e417aedb02dc7f1daf625f6ac3a9bdfd8d5ba017de2b88ea556b3364f6d64769fc6cc69f1853cb8e26454a92ae9f5cc78cd2778ccde08a2a3b66f3efd05820804e33667e7478796de17d97a0dbb6962247307021031373ab50759b10d8f49d7bb3a28ee0455febbb48a455
#TRUST-RSA-SHA256 78f1f98466ae365082e25eba6fa41c1063be354135596e4b6929ff9785dc739e262e4f0e22c72ab66a34901dd98630289fa549e288ddd5a5b567b4b74dc141df98258fde80585fb7c494ea225e398f05fb964b19f8983339c50e7c92b0a62fdf59ac721aac542f20f8b47e919580807141e0d2cf7f27f2e369c5c947278ac6008d1b4cc6695a5197cdc66c66eb2a33765f0bc701968b2cd9ae4f8f7ca0452af08201b9ba0f8a9fd9ee2ed20d5d830aeea3743bd56882999b606327f8821f5550f4040bab40b3a7bee87298a9a612acbc65ebb0bb30e8c678793529d7a6d8ddc7a0b1f9f258f42695da8d344d56c5905d0a09207836e296a115007c7dd623eb8faddd131a1091e321c24aaeae61997396bac9e0646c0c531cfa13907d3f54095f318434e9567140c5b48c122d2f1a2eb73f330610cc763611fb61c74ff441a03266d8f91f17e35974f88c2109f3de99834c45bfac5111c533a89e1dd720d6881057d5066cf62596ff0aa0a309f93d6dfa27768b1c1b56080241acff374ff78df9b880754181f08374369b815d206b24f8b8e70671df194ac892e0eabb5fedfe4812c29c923de0a38e072acbd93d8d0290356885220bcfbbf7b65a4732bc867eae1c3976a1355a71a989f8394dd427a36eb9085881307c0097f821f5f67b0c313acd203e434ca948c41b364c66e307ae1a6620d57b43cf69ae696138b7525a47a7
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211956);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/29");

  script_cve_id("CVE-2024-20437");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh96411");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-csrf-ycUYxkKO");

  script_name(english:"Cisco IOS XE Software Web UI XSRF (cisco-sa-webui-csrf-ycUYxkKO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to perform a cross-site request forgery (CSRF) attack and execute
    commands on the CLI of an affected device. This vulnerability is due to insufficient CSRF protections for
    the web-based management interface of an affected device. An attacker could exploit this vulnerability by
    persuading an already authenticated user to follow a crafted link. A successful exploit could allow the
    attacker to perform arbitrary actions on the affected device with the privileges of the targeted user.
    (CVE-2024-20437)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-csrf-ycUYxkKO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5da63ec5");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75169
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0341eea");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh96411");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh96411");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20437");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.3.5b',
  '17.3.6',
  '17.3.7',
  '17.3.8',
  '17.3.8a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.5.1b',
  '17.5.1c',
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.1z',
  '17.6.1z1',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.6.4',
  '17.6.5',
  '17.6.5a',
  '17.6.6',
  '17.6.6a',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a',
  '17.9.1w',
  '17.9.1x',
  '17.9.1x1',
  '17.9.1y',
  '17.9.1y1',
  '17.9.2',
  '17.9.2a',
  '17.9.3',
  '17.9.3a',
  '17.9.4',
  '17.9.4a',
  '17.10.1',
  '17.10.1a',
  '17.10.1b',
  '17.11.1',
  '17.11.1a',
  '17.11.99SW',
  '17.12.1',
  '17.12.1a',
  '17.12.1w',
  '17.12.1x',
  '17.12.1y',
  '17.12.1z'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['internal_service'], 
  WORKAROUND_CONFIG['HTTP_Server_iosxe'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'flags'   , {'xsrf':TRUE},
  'bug_id'  , 'CSCwh96411',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
