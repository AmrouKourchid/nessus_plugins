#TRUSTED 0015ca98cc87b70db4f88e5452ebbf94619a0ad2df3b641ac6f69c227e8db0c7f4b19b149f3d933e8e214811e2de1bdb289d39a833e68bb9f007cf5aea4c31fa68fc44659c5be1f5853498e66bbe581152869789541e9a8829f528f2ab45bee956c54edf99e73c5443c97a471ae9ae31cc856531cf705c2a2b67bfd2de2b2677c140f801a3410c20e9b546eae2511aa803ba942f15eb137a30d4bcf415d46e536570aedd52c573ed0d6f632955ec4a253a7a5f61bc32d21822fe5cd460f5b909cbd995207203dfb203454b480d3d8176e44e455bcaf730f9e4c699327747194a338fbde88bffabd3bb20c30786d6cd96eadb407350e19d94608de1103cf6f2009001fc16db80766f7a1dc1fbb6b6d7f18614447871dfced36d78921d3c28512518b307e88b16d112ffcfbf6276a9e12186af22381a7da13854af21b7f5c47463d5dde9e47bb8f5aef3ca55f06cb780d9f39cff3f55eefe83a17431535edce0f546bd441bb6671b3a28fd7f057cfcd27803aa0f4a5bddd0f8c34cc8ee171ebe40d0733773d9714ceb2d78744143918e6c5a29df456b2025829b02b2ab22ad87f770fdb78e3ff363f0f1c75842e8b0ec79fcd4eda41a01e7585927cd48c4cc383d8e6c0da37377fbb0cd2c989a914c8bb365255abe64d434c04632826c71632fa57bd570b6ad11b179d1ca6fba44aedc4ab9b05ad7055a0e98a554281263c09114
#TRUST-RSA-SHA256 764de9bc7af63aa0f3a478b554498be622aacb6ca655fa350ac7431b827de6f31e8f1b5d875f577b59e8e8250da7b4c1ba20cd9582e0ba3eb634b24dcf703eb47a9827b116ade77e677a65e8247e3d7144acf3a0fcb8756ae2365fd2ec5f23ffe74106c6c18ff35d8261f9e3983ab82085770fcc4f02ac0821cc9d6beb8782435045f52c681066def7aca185070e39082d1c7e1132492558b07e18b218b47476820ed7a7ee926235f2b2b5530311011a3ca0aa2289d0ad85373a635bab7e241060269bdbeecf03e10894663937aca9b16e5f1596edc91e231eef3d766f03a8fee434592c8bba91b78a3cb4cd5f629e879a648345fcd4509d5ea979c8bb8daa7bd922bf12bbc39367a0410a0f0da5f16d2c7cab8c5cbd12f94309437e84ee0553d77b835eef791f957b895ff05c4c3bc365f7086daa812557ec816dae5bd462e9482904cea63115c7a04d13d1199561d581a2679de3c93a3300ae64c40fb2bb9319530decfbdaf880ea4fecef3f2a4a3cbca2a81f98ee2792cd9840492fae3f0ee9c05ea438bc4d7c15c86aceeed92e20f01e3942dee6e7c1e25aa1a81ce345a40df583ac24476a2e14e0c803b05a40ed3fbf243214aa6ef9f390e35871ce26c9df05dbb7df4f4ae9195da5ed6e68f66f10e90579d1e9fb33cbcdf5733206f81a35c95d28973073e19b057bb24281bd71170500469b36523e22690bf559ca33ab
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129695);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12654");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn00218");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-sip-dos");
  script_xref(name:"IAVA", value:"2019-A-0354-S");

  script_name(english:"Cisco IOS XE Denial of Service Vulnerability (cisco-sa-20190925-sip-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the Session 
  Initiation Protocol (SIP) component of Cisco IOS XE due to insufficient checks on an internal data structure which 
  is populated with user submitted data. An unauthenticated, remote attacker can exploit this issue to force a restart
  of the system.");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn00218
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e59804f");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-sip-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0995245");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)CSCvn00218.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12654");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.7.1aS',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
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
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '3.2.0JA',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.2aSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.4SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.5SP',
  '3.18.6SP',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.5a',
  '16.6.5b',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.1d',
  '16.8.2',
  '16.8.1e',
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1b',
  '16.9.1s',
  '16.9.1c',
  '16.9.1d',
  '16.9.2a',
  '16.9.2s',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1c',
  '16.10.1e',
  '16.10.1d',
  '16.10.2',
  '16.10.1f',
  '16.10.1g'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_processes']);
workaround_params = {'pat':'CCSIP_SPI_CONTRO'};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn00218',
  'cmds'     , make_list('show processes')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
