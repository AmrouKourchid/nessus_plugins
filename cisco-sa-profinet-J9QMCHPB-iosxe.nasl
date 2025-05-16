#TRUSTED a01d4aac44d6994eb31d16e6197a47d9feb7af815f727982ff415838e6c5fea425f8223829e8d384162dd748d80245dfa3f0752d5b943041a46e540fefc292c2252a45d3a020d7f17c4b60d348e13f42aee38496971ea51958921b8202331de2bb06c47933857d06c6a57b4f2076f7e88b85dba61ae3dc7d3165c5cbd082e2965a4bc2696f989381191bfafd3f8be2b4e91dc1a94539fd31fe1bbf04bd6b5ca974e7613b767b46e96ce46ede49859124da9b521fb974b134288802ab2a6b0e17f84a6a913945c75f7ec4f6caca1402e4f6cd58d59429f88d3f9a892543fa55a68d063876370af3efbbdcfe702ebdf55b940b2732e7d2283fc3d6ca9a42b0caaa7ee1c38a4793a0247c63c67e28d6e942313907d90b2940c44f9962f84c9ffb0c39cc85b6a74cc2b16cba60507e90b65d0def8eccd7d9cf4bdaca4fed85c3350ec6734a7322a3e95aafb7a34d73d5850f38f030f1274a0080b54f4a0a464feb3f75f786e12ff26f47fdba13228af81d3c5c9605ad3d565e5c6ba8bc7020fe1623df806b49d9c95e415fd6db56dc740676e1585eaca4968730178c59b431812c41e65e4f3ed00930bbcdc48975a98f2315e6d4455c776f48b07d360315dfb51c9db5d93d0c36242b07348f25ac88071fce0fd1952a01cbf32a4018c70290bf2047867f8abae07a172d976544293f74be1701f0eba1a19cb0639222c418b0f10a4f
#TRUST-RSA-SHA256 58de045e2b44285ce84f6ecec6b50fb9203c6555926b99003ef34267a54eb323be4b91cf76716b61d7aec5b1237de7cbe77db1befe9b264f061f7293ba49998a3a4e59719e8a4cb558658a4113bdfebafb71cb0766dd7fb8596e7bdbde064d53f2d7ae8c7cc4b5016db7712e4e3f82665052cc1b29691e20774a2f01a2f7267f0292bc66d5b5ea29be9f8f3d14a6fcab347152a724775cc2bf79ea4b8e79b5cbabbfe2b97cb4f6bcc66a410385a58f95cbc9cdf97d46ecd7cc39abf493937da692489bfa026b6a022cc430d045c3fe727d8ba734c0de11ce12ad10a09267c73f322dcedaae538fb24305155b423a5d1d7655a54bebbfc5a0c0d92c30c897d0b2443dee13198fe9846af7e21d30ebbe7fe581a3b15868c4444be94232f074fbaff89b7b2fae053d006571b0938a2e59f346b204570d12fe02a13237dd48327c3f822b101ef5a96b557fc7289325becd2b8c5c530fe001e319b137677083954221e8c1a9a85c4cb08c3ecb7728d98e85a4e42c2bc6b797b4291c3bc2e2837237aa183746bdf6193ee600685adbb12c8154ca628972777df5173ed0e3ecf93c6f00d6d6df9729741b457a8aa2684b1180ce304874b44b636875bffc36bffc8602f933541075e22a081f243b3066b5df44a874d42959b736050eb9ca0eb3663664883c3fb96c6d14dc48523fb26158abcd1329f9d76284f87e0487693165f4418713
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142472);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3409");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr83393");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs48147");
  script_xref(name:"CISCO-SA", value:"cisco-sa-profinet-J9QMCHPB");

  script_name(english:"Cisco IOS XE Software PROFINET DoS (cisco-sa-profinet-J9QMCHPB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a denial of service vulnerability. An unauthenticated, 
adjacent attacker to cause an affected device to crash and reload, resulting in a denial of service (DoS) condition
on the device. Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-profinet-J9QMCHPB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cff4d72b");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr83393");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs48147");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr83393, CSCvs48147");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3409");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.10.1',
  '16.10.1e',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.9.1',
  '16.9.1d',
  '17.1.1',
  '17.1.1s',
  '17.1.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat' : "(^|\n)\s*profinet($|\r\n)"};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr83393, CSCvs48147',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
