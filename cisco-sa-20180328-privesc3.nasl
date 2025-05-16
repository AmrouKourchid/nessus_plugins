#TRUSTED 7ab0976ec15b7afb91782d65c5a09b0bb920efab232b90d5ffefc368e3c890f090257dd3fe7e3551eedfb060c08cb259fefffe94b9fbee839a2221e312e425c845458b16ed24497380c5ab26ea138b4055f3d462c1ae40c8b8c60c989c1fd75a46498e9f7d08aa82b5717f058081888ee29d94d6faa22282cc893aa36cab4487ab982f9a8ad29b0e480503373028b371f30db8e4f58ab2d27ff65915d2428ec64becbd125606be5246e9f2d506b8353e45c9394daf9d68cc4e33284c90914c47cc3e64c4f67854bc5eb80d1048f2dc7fdeec9efd4860fbda92704ae90f7feda7d477bfe6d86cb6eb5c18d42db834523e2501a30fc4154c0ed89b71ce82fc9ac58cadb10ab78c4fb59fbb81eed3fa1c550aa60d331ccc094ee3c494cb0a37ca0d3e2b4ab0caaf03c2c0294b4d384be29609377eb0aee755f8f3638e2742b5611ef1ad3c4b964ad2eaac9504adc733146cd781125c445d6bcdfd1009a6fefb28d61c621fa2abdb3a3098de269e32325da36c9da1d82f363585a789cdeed4b75096e349cb110c0fee66b00c6fe3929a92641e56932b814e767ce9b8839311425430bab63a24670c074633e4b4fa497855a43b73522fa667961c1ad1bbf57bb216a79f94ebcabefcc537a52d949770941fd614e974634eec1e4ca0ba3d6f8165463f8029dc6016de576c1d0c354bb52f00d2579ccc9d4450c52b444d939607f5fe01
#TRUST-RSA-SHA256 a6d8ceb92a5eaf06d0341145ccc76bd4ff1501336319d93bdb1913ca31777050b309c9334850a53c18319d203cae429e1d8dda47ea7e06e0ab96a33a1f649c434a062518033c544407ac4a982688a170318568c3067e93695d96a7bd88de641d9ab7a2bfc77505c6f60cd6fbb3bd60ee5f0597733d20603d57794f4db821a0f5ef25a1d938ff16108e01e2dc8ce815aca8279462c54a956357a9d34af88d5814d586734b95f2c8b867abb612424322909a2b5638aa59a67e81a907f55a31d4f0714bba1c3e7c4f41f18740973982527e887a426ea689a44d5a7c868073447af85a7cb1d9af669d855719ebeff701791870d5df066e3a6da73905dc0aec86fe052cd55663a0239046f343e9c82c5ae5eb2688d2ff982c0e1af97a69508c4ecd867e3fc3564877f767cd0acb3d91ed52b14f16791dc3729d72417fe491e432d8af40c3f30f1ee028d5d6b0560ec9cb759b5b4cc30dafa7ac823b2523491fc908adb11b81795909cc9f5fcfa696a0a63ef8d1adcfe9720a166029bafee7a7e2f36f66360332fc7d5f2f1dfe955964400882ab7e8898a760eb2aa17214fb56f758ceef8137eb13c45800e7692b2a3816fc3174877870a43470ba1612f89e8821ad78111980cd127af3201b765b0580e0209d056548d931645c6337ba389f39e7cad4a83b59626adc8b36e3b52951410d6e5131921225dc83cb69a61e54f8994a419e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134712);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0183");
  script_bugtraq_id(103555);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv91356");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-privesc3");

  script_name(english:"Cisco IOS XE Software for Cisco 4000 Series Integrated Services Routers Privileged EXEC Mode Root Shell Access (cisco-sa-20180328-privesc3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the CLI parser due to
improperly sanitizing command arguments to prevent access to internal data structures on a device. An authenticated,
local attacker with privileged EXEC mode (privilege level 15) access can exploit this, by executing CLI commands that
contain crafted arguments, in order to gain access to the underlying Linux shell and execute arbitrary commands with
root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-privesc3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7ad8083");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuv91356");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuv91356.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
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

display("piv: " + product_info['version']);

model = toupper(product_info['model']);

if ('ISR4' >!< model)
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '15.4',  'fix_ver' : '15.4(03)S09'},
  {'min_ver' : '15.5',  'fix_ver' : '15.5(03)S03a'},
  {'min_ver' : '15.6',  'fix_ver' : '15.6(02)S'},
  {'min_ver' : '16.3',  'fix_ver' : '16.3.6'},
  {'min_ver' : '16.6',  'fix_ver' : '16.6.3'},
  {'min_ver' : '16.8',  'fix_ver' : '16.8.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuv91356'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  router_only:TRUE
);
