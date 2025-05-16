#TRUSTED 4064c54838ade8d8fe6ea524cf66d4e4149ff09564b74eaae8cbdeefb48669ea5039357fb042374c9e02bcb7fc77f40154453180074cb112af3bb3d66af1649f752fb35d1ce0461aff8e91941233ab44bc0218643dfde3d7c3d8cbf0f8a9ff45887662d4a3f49ec9ea75aef76561bfb1d7104d838f1a30a3f95bcafbfc353cef98cbc2db4d6a9e11d93dcf0f8dde622eb9b450cd4ea931032c8b4d75b1c74c479455b9789e7952d82f218175a9e0ed51fb4126c860893dc9795e9eced44be7fd22652d349069c59c33b26fe0076c687dcbc40139e1b445ab12a608ee1a6222f9802cb73cec7dbb20a766b07cd20ddb71a175c38f4356ae6184bf0151700d7f0a718e0545fef791af6d16a3e9d3ba0ac5c1a0fe9c319a54920f7cda9dcfe04a153f7033c51fd5c2fad89abe9de4cfe207c80ce952efcacf13abf1920ab56097bf6f45a15d6e781cc442f5e80be65de0fd9686b6c7c28dec520b93631f7e8e712aeb6f0df61df6700aec14c4a6e76aaa9ab47baa430c0b30e3595f2866eeeb830528a3bca93c356af9ff234f0d055ae9f03f2b492ea1c9adf4c29c034f2ce56f0ab0dc9d2b962d81234cd633a99c134be34ead3728b2731e3fe9a2bccf50849fa86550ad37f7b8434d440d1bc3de639a65fa0939aa05ed4d56898eb0404510ae58d3fa5c4ed0d6e8607ab935eac1f0f4c029d6b8967472de5637b6327dfa71a059
#TRUST-RSA-SHA256 8c9934a9661ec1f6880fadd355ff65f4c42f2feb7d6cabbaec3d03f6d553aa5eab2158611bfcbeac84e29444934169ea697dfcb4f6fe4aa9798e18b42ef223aa3a3d3d9ba3eef66ac19beaccb03c179272307f2a6b7896ca1edae2f0920eb3d69dbaa1454fdf118ba5b4669ba787616c1596f6aec050f787292681c56d0ebd2202eb3d1b3fcee38e2a83f350f67527957ff503ee9372becb01e40d2788829370a37ceb26df6057540652810738db8a0fc3781c8acd455a173ee65497d343a7473fcbea4509df53830898b130623b43228ada3548010e09b628764d75aa36e32595e229445c2bae54969c8209a5224a11f31e4331eb83bd3308297244bdc1ea74e31b78b4d42bd28e81f964e90cdccec9c71e8fa67e26c1a3c73230d1485943ba25e702dd5a20bd1db207690f5f4bf321255c005382078e613ce2dfc5b3f108a9f47b427ec7f30ba921154e1c828d7f2e1b2b1c5b9c489789a12eccbd6bb3cdc528248c7465ddae11a1991b18027503ec42097a464bf7216372b87239cc998645ff8388a93542b2062d35bf9d541901f11e711a3838e4586a2de45e70f823e149751a60c3f4cd946d780cf64bb4d9f88059f6ce7e80bc643ee832edac2920d8457f9dca01f37ea497aa874458385731737ab80ae2a8e8a7ba0778d7b864b552ab043bbb35e6643a3526b6ddb3513edc22168a2896be0c12f3034fd5872e4e8dbe
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129827);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12670");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn43123");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-iox-gs");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software IOx Guest Shell Namespace Protection Vulnerability (cisco-sa-20190925-iox-gs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the filesystem which
allows an authenticated, local attacker within the IOx Guest Shell to modify the namespace container protections on an
affected device. The vulnerability is due to insufficient file permissions. An attacker can exploit this vulnerability
by modifying files that they should not have access to. A successful exploit allows the attacker to remove container
protections and perform file actions outside the namespace of the container.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-iox-gs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0e1d008");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn43123");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn43123");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

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
  '3.2.0JA',
  '16.9.3h',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
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
  '16.10.2',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['iox_guest_shell']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvn43123',
'cmds'     , make_list('show app-hosting list')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
