#TRUSTED 9c023518759e0b3cc9c498475605d5bbbb816a8ea7829d8313e1a801b7c08ed806e66ebe9def5b3b504b04dff98f5ccbda19047b9a8460ec14307495053533c86ae71fa3115542080fe20624a3b35f91b324b9d9e610150facb528ebf15dbae089b7669803af0fca8c0790917b320f9ccf6964c6c882fb05bb19ff645adcb6c39b09254953f062d3c40dd218ff8aea4b68e30bb411b4f197e720237221bdbf0f8e2e4b5c9f85fce44b975b6338b76d1ea4265ddd18e09ad9e5888ce8158eeb17194b2fcdb5c71227b22b63d11b7b8ed857db9f420b006d9eebf8c4b2272c7e1127f33564126add7a68f0ac6fa805f2f01805e0df49e8134684cfea281b824742ded9380a44a18baa23efd7d570584b167635ec11cf2eff3b6b0c89aef154c5b38c45bb752604bd161b1caffbd218fb40838946bcc750ffaf53e819c004b2c8eadbf5ca544a3262baf0d585d947fed694094590209e8546c1e5ee3ce211d5c6c41f1296cd986f95e6a7f4978b0eb17db3e10d8bbf2f5e1c026bd0146c7caedc63eb4f919d9e5270a77213f6dc1eb18dc73347a59e1f53b4b3c854814370494316308e340e0c295a39eb965b5e81066f8f314123db2878c7d891a1ffb4608af51389bcbe51589293f5373edd255983557c976ba3412a0b563878300bb1265786872229bf1e300c53d1b86bfabd55bf49c0edfebb444b86246fd671d771299c3e60
#TRUST-RSA-SHA256 5b0faf1ffea7a91eab63de2b3602ffebc79d772ea48f6775698add3be1918410bd6f5eb7cdc6c5c51a2694cc6ba190fdab0e19b0baaf181e5ae5e641d6f67123622a1243a9a6c84f7d4a46dbd5237b103df1eb88c61829eaff23bf4892b23a33bf6769cbf9c2035d94e00938fceea0dad95204bd70426e273912039fd14b9f15e522cdde5863782628dd2d54670bf00438f607dba439ea417117b08952480ce4bf2434b178d942febfca5d5312dacf482416a4b5c792f7ef6fe1095f91747d670ba96605cb7a8dff5e1852c9971bb20d96596e4b446d422f3b4c46587e16037c86f0353ce98db3667a1fa62624119716176be2adba4ed85175ec88d5a12dec7185110ccc6ea474c0e94ff89d592b0f2089029d10adb217e486bd8b07981055191e6ca024022106b624e56a12f22fdceb836ff47ca6cf4357d5c13e11cd79c218277992b73db534ebe3cc47159abc986ee112029b1f84f6dbb93c966c57e3ba6830f464068d163b808091994f9af2f0903145b4206072c602a59d812e628123cb26ea62dc732c6bf72cddbd28c78c6c6b1334a5ae377fef6655f87d5c52e3dc36f9106ba717ff5f747e4c87454e612dc90a3f73e90f000c9c4a0bb148b176f3e4d6657151f61db20fa745d8c6815c5e84c9982efd2c65fa8efd3369e754ddb4de238f794c4497b9b3447487b419a94538340ccf2805655dbe50fc21d70527ed1b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127044);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1904");
  script_bugtraq_id(108737);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy98103");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190612-iosxe-csrf");
  script_xref(name:"IAVA", value:"2019-A-0264");

  script_name(english:"Cisco IOS XE Software Web UI Cross-Site Request Forgery Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a cross-site request forgery (CSRF),
which exists in the web UI of the affected device. A remote attacker can exploit this to perform arbitrary actions
with the privilege level of the affected user.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190612-iosxe-csrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?616fabb5");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy98103
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f9ff48b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuy98103");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1904");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/25");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.5.9SQ',
  '3.2.11aSG',
  '3.2.0JA',
  '3.18.7SP',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.10S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.11.0sE',
  '16.9.3h',
  '16.9.2h',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCuy98103'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
