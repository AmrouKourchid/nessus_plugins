#TRUSTED 9addf0f65c1afd3e84f861b35816db648019cb0269dfa213b7bc72959d2038a7879c3c07b09d75573c9e7a3517bd881687e9d923ab5bb791ce36202598b51c472a9b9acfdd632418bf27494afd0d2b147a76cd4afd66844e38f905703668bcdf5fc7313ae70dc69eb1ec3c3165cc193950ad77a5718f1a3931c9e30c58fc8e9227722c5e3465abd0da92edca21c7e2964b6ee0a954ed9d05edc754bed8443b16e31b31d473543bb8ebf5f2d8706e1dc5f743cae55a4b68d87c30c0bb682f9a26e82d4ac6d703ccfc20940ad292844a07f8b42e62d228a2f3b69fee7da9cab0cfedbe44e0323ae085bf7315fa249a8d3e4cb64746a3a122301bdbccbbd16dfde181447fafdd5939a3e9e0c8f57b6ee5700261b6935374cc2de32940fd19962585dc1c52837f5cbcbf322f3b1309c8ab477cb5ae17c507afec944099e4701184b0525256b6975227e036c1068d408a4a059c9fa02a16c15157cb457148532cb88b034d4045824a98219ca554a9c26483453755432eab82041563eb3c67ea293b8c3ef9dc14a3bac611119b2dca91a9c27f4ed928bbefce2c183d0eb55bc14d8238c780e2271114484d1bc42d20ba44feb7b07d0c00631b08c91a5733604d23d17656fc9facf5b3d231d774201c7e12e2d1524dbfd3f813b5148ce101ca2e12f6bdd99c25bbe2f173f036cb07146193546dc0adb57574210719d70beac4e22594b9
#TRUST-RSA-SHA256 42f7e667243790066baf0a24f223c7fe37373cbb43ab1b7cdc56db54708e64994d0da69352465949eb5cc32c94f00e50494534caecdf595a55d26cab9892715f53bbc77b3b509b39f8f4adfc97f252ebf581e12df36221f7dea4c0ccd9175e71ac00ad66737f467ddd9c6ba50cdaefc2a25e7532c9cdbe7e9c1bc368f287e80e8889df0b40a9557631b746ad9e7972d8b002f96620574e7eec57841e35537d496e97a726f35607399f1931554b3d913d924b2762cae5a540c23cb0fbbbccbec910a71b74670a5d25e014c74e6a64e7ac01147c56583eb1c5a002d0d20fba84ecbda7963c8e2b3c9905a471730034ea41e062e584344fb66418ff036a72142ed56735dba3f2e020ed8fc4b8071bc8e10087f0b7abd8e7a04fd23e5e942cbf16d81fd18fb291a460bdb3bb6e8ea48c4232984cc46f20da9c465dc3228bf57b44dbc4df99afefc08df6fc7c60f5edb81a7684327be319c57aeaf3b306a3bec66016cddfec3eed6462ce1823a88b0130702239a7e657aa85d8ba6807d940c7bbde0922cdc03e920c75a2be0f9276863c8124e3b455c5baac38d7654175991b2303f157b26a37cac8a141cd2bc276939f0bfc4548132d0b1fee1e5b222be21636b8af65b3aad64ff71f3e33ba549fc787be8dbed03dacf6c2a5c4d98a6baf815f2606a1e2176b41427c0d2900a3d70c94cdc50dad802e7676e1b30a5bf55dc7eccd95
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(123795);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/12");

  script_cve_id("CVE-2019-1760");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj55896");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-pfrv3");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software Performance Routing Version 3 Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in Performance Routing Version 3 (PfRv3)
    of Cisco IOS XE Software could allow an unauthenticated,
    remote attacker to cause the affected device to
    reload.The vulnerability is due to the processing of
    malformed smart probe packets. An attacker could exploit
    this vulnerability by sending specially crafted smart
    probe packets at the affected device. A successful
    exploit could allow the attacker to reload the device,
    resulting in a denial of service (DoS) attack on an
    affected system. (CVE-2019-1760)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-pfrv3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?250f85b5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj55896");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvj55896");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1760");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0JA',
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
  '16.8.1s',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
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
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['pfrv3'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj55896',
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
