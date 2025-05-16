#TRUSTED 96a1e8c121036ff2c066ef6069e8ef68880144c624930993102320071a8b52ff48e77eb5bd2d6d6bf9509025b41a47487966ee1f73ff7a76d68fd38115a7edd55a41df844cc23a47ece1e1b8dd7512b7920f15f214affb3e058898a7df07bc654546b19fcfbe982380c8b49fb713293b640c7f9c00abd53219e5644a307d0da695a0d52121fd1abc58f64bde39de874611b3973a9f4dd2ed88cfc9306ab9a6ac6dcb3cdbe7dece2e7e656d52bffc27632a9243514439b5f65cc9ce7496d06277708e6962aa9f5c4db96fdf7c67479a5ad08614fd057e5a24a3d6d3b697c6c9e799d0927c009c594d00e5b938f06c24cdec4531b53d673b5dab63df5746d53906f05653e120134aa6fcdb7e7566013181c46254b5067a81312b8a60401da4fce4d186d681a5adc43feecf5777a335971cacee6df26e0a8147a448e0204cf7d5609a882d067cb92ec8308c3e538be41f40177fa0bd42df702c1e766264fc95df3e00b9019aecd1bf3cf2f38fc2e80d7afd0f31dbf86621b314428c1c5111488ce6fa6fa4db8ab6bd4e7d4028d8e59741da5d83cea47f6f1f2d7c34a68f158880d97834849aa0f4eef370494cb340e6562157e84dd4e57ee35c3dce5475191f43736a3b211a6d61da590e1a5527bc43ece3cdd8d75963baa556f2318807682f9cefc060fb4d578452cf79369501d04c416393b4d00fb764beb3e9dde9cdfc11bbf5
#TRUST-RSA-SHA256 6dc8975237437064d73379fafddeb9e5a79600612f1423cca612ab1bc0eb56311cc4d0cb6a175be90fed1ef5fd02310b4c2659a9844395c0b818764d518ad85760b4081637bd3523a83181ff1061a8f50bf0f16a9704be6e1821a5803db345eda968ef6d6b3c9b2693f1eec88342e410060fc5fe252f355151ed17b44fcd0aa544cafd5afd4ce6a43733c6ce24744e747c38c548829c80dde28ee323a3344a997a3d1d07e8dbec2bf03cb73635577eb07f51a9f84ba10b3fcaaa96476ddb06a10ad8bfbb67dd30cc2afce4fff897ff2b5745d1e79bfbbb085f425d08640827feb43277a114a8d027e53832730e1d1650574e326d36e0f618e858aa92c98b3fd4b025d03b0e3b3d32a16b9ea2a26cfb7d854c081e6c2366510648c7d25cac42bbc2b1cda45a27ee8f97b3a9b7cc267f4fab14a06ba8e0a3250234934e8ba08aad2f149559ba18b3a26c11be0235ef8857a57868db1da4c35d07b97b39b17c3648b60ba2203b95138bfa4f187b93b1bc4b2010658e815ba6450de7afbbaf4728519a3b80606840daa5bd2d9326aace19834e438891bf8a8a2912dd93c09f5c3b4dab9ba8c6e730cbb5b4990ac6b4b33ec37cc5e3d4f8a05db466985f9c3ac4a67971f8c8dfe836d76f89f8e6ceb92cb775ca7b8a3467b088216929286cd1b9497453f87fd8570f298e97386063ebe38403dc45b8809be2cbaa428d431d5d97cea3
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132078);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0164");
  script_bugtraq_id(103553);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd75185");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-sisf");

  script_name(english:"Cisco IOS XE Software Switch Integrated Security Features IPv6 DoS (cisco-sa-20180328-sisf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Switch Integrated Security Features due to incorrect handling of crafted IPv6 packets. An unauthenticated, remote
attacker can exploit this, by sending crafted IPv6 packets to an affected device, to cause an interface queue wedge, a
DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-sisf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcc60cbf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd75185");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvd75185.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0164");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

model = get_kb_item_or_exit('Host/Cisco/IOS-XE/Model');
if (model !~ 'ASR1k' && model !~ 'ASR10[0-9][0-9]' &&  model !~ 'cBR' && model !~ 'CSR10[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'an affected model');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
product_info['version'] = toupper(product_info['version']);

if ('E' >< product_info['version'])
  vuln_ranges = [
    {'min_ver' : '15.2(2)',  'fix_ver' : '15.2(2)E8'},
    {'min_ver' : '15.2(4)',  'fix_ver' : '15.2(4)E6'},
    {'min_ver' : '15.2(6)',  'fix_ver' : '15.2(6)E'},
    {'min_ver' : '3.6',  'fix_ver' : '3.6.8E'},
    {'min_ver' : '3.8',  'fix_ver' : '3.8.6E'}
  ];
else if  ('SY' >< product_info['version'])
  vuln_ranges = [
    {'min_ver' : '15.5',  'fix_ver' : '15.5(1)SY1'}
  ];
else if  ('S' >< product_info['version'])
  vuln_ranges = [
    {'min_ver' : '15.4',  'fix_ver' : '15.4(3)S9'},
    {'min_ver' : '15.5',  'fix_ver' : '15.5(3)S7'},
    {'min_ver' : '3.13',  'fix_ver' : '3.13.9S'},
    {'min_ver' : '3.16',  'fix_ver' : '3.16.7S'}
  ];
else if (product_info['version'] =~ "[^A-Z]")
  vuln_ranges = [
    {'min_ver' : '16.3',  'fix_ver' : '16.3.6'}
  ];
else
  audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd75185'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
