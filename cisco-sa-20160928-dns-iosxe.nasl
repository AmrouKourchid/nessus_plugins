#TRUSTED 2014f0c15895d39cf33c1821e7257dfa8297d924d30941a2957ee019f78e240722e7442545f917c9cafa572a4c04135e48952127678f7cea6cf4137e1d4c3603bab35d8366e2136262516d63cd86ba3a987d3136ead832386653b2f34b58ade9678ab91b17445ec724c50ba92d8f08ed835a80fd8dc00a4a086ee81504ebe50733ab2924445126e2ca36f6139909d1afbf6aa5da00a10913e385f46736c9b6e468321a50db02420bfb1e63f88b67934003e827163dce09ee08fa3eebe2d8f244a7d93014a0733c007766bd48c831a9c3d7be4414a178746a107acb1fc0c6ff3c7be5bebd0e6f5c22895f88bc4a0d779918cab5bf338d354bd5add024f7975d4a0dd8dbcd6f398be549104b1087554d4550afe95294d6a4197d8e133358f5abb2cde731492d7a21daff45c7a877be4536aac210fb8e6cd01766abaa72465b8fab73136356cb4bda1477e07e0e3e11e5aa6a4f732f5db8d465d5aae5e103bcc02675885fbd9efa92ccbb67c46be3da0de22b629a346253a713f204ce46517e179d0b630628434467a279d9db6d1fadd7eec30b33530d7c1de9fe468e21e9c8dd6db572ffcd9a071d56e2a3a1b2697b34f43645c1b2da5ac496f8e73358c29f29db282a6bea3d70378b77cec68a6aebdf09d62f2697e30a59845a236b22ef7e7c459482a05e9c9f084212704875cd32ab459cd2b201e2c2a9f2ec76c8f093166154
#TRUST-RSA-SHA256 7041ac46a93357c84a7c0147dd566d4b733d174b756e81f563b814ebb6fdb8150e8d9c324943bda0e253c0833128244658b0da0e153671a5a9ecfb3b8999b0f99a16734e34b499f8e23be471df45a89bb908938c0d9f0fac1081dda7edd51579b1b0cdade572a744545e5bb0a7d556dddd9b8b05b7e7066cd13968fdd7eff6f2cde92ba34db265a9e5c59d55dc91310c94c257e53731184ef881dfdf9dd6095fe95ee1a549059e072de1a1a3280d91acaf1a7b795f136288d876975f9b7425c38c26f14365503cc099a6883d25d34b2b39819d21bc3eb1e260b14eb292f9ff02d7742a510efaa5c297f2fe6896bdf5fef491149f22204fe986c1d38b17cf062259c134c2ab49fb148d3987bb470ea58f22b0f3c23c6a07c866d6a00e42c7d9ea80030b0e29586dc108a60dfe8ca7fee669796990aceec5c31dc5fdaa553b911715ef0d060d381a388581fc7ea74966b070415bb8542f1e1505e7bfe56fa82e6b5037f74087f0c1b1d8707ab2fea4642196ad23e92d0cd45d89049e892bc08a51120b9824202cef49c44f93b3af61b9ce06c67e8548ff4c70f8ad883d5e1b179d7f83ddf0fe1da04552fc4e842186de5eb2e1666272e8272563c850c76b3b97d4098f53bd369271e265959a8eb7cb4d0337382fbe47969f7d58ab5e1a43de8156ba4d4d0df4008f36f4ad6e2dc8d039f9ceb64f92d356ce548bf231d233151b74
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108957);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2016-6380");
  script_bugtraq_id(93201);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup90532");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-dns");

  script_name(english:"Cisco IOS XE Software DNS Forwarder Denial of Service Vulnerability (cisco-sa-20160928-dns)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-dns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37daabf8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCup90532");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCup90532.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6380");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list = make_list(
  '3.1.0S',
  '3.1.1S',
  '3.1.2S',
  '3.1.4S',
  '3.1.4aS',
  '3.1.3aS',
  '3.2.1S',
  '3.2.2S',
  '3.3.0S',
  '3.3.1S',
  '3.3.2S',
  '3.4.0S',
  '3.4.1S',
  '3.4.2S',
  '3.4.3S',
  '3.4.4S',
  '3.4.5S',
  '3.4.6S',
  '3.4.0aS',
  '3.1.1SG',
  '3.1.0SG',
  '3.2.0SG',
  '3.2.1SG',
  '3.2.2SG',
  '3.2.3SG',
  '3.2.4SG',
  '3.2.5SG',
  '3.2.6SG',
  '3.2.7SG',
  '3.2.8SG',
  '3.2.9SG',
  '3.2.10SG',
  '3.5.0S',
  '3.5.1S',
  '3.5.2S',
  '3.6.0S',
  '3.6.1S',
  '3.6.2S',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.4aS',
  '3.7.2tS',
  '3.2.0XO',
  '3.3.0SG',
  '3.3.2SG',
  '3.3.1SG',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.4.0SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.1xbS',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.0aS',
  '3.6.0E',
  '3.6.1E',
  '3.6.2aE',
  '3.6.2E',
  '3.6.4E',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.3.0SQ',
  '3.3.1SQ',
  '3.4.0SQ',
  '3.4.1SQ',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.5.0SQ',
  '3.5.1SQ',
  '3.5.2SQ',
  '3.2.0JA',
  '3.8.0E',
  '3.8.1E',
  '3.8.0EX'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['ip_dns_server'];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCup90532',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
