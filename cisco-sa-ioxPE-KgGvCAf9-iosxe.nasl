#TRUSTED a71450ac97f0e000265cbc176b768fda5f5d562d713d868941f62a4abce575218808f68f6a1c71f0b50966fdb843d73ecd3ef8deec4e5c52611549ff5b2f3e25b73225b8f9fadc7aa807517d2f9698eb1ae5c92be44ddfc61f944cec75e1110a19863b918da9e43bdb584f925bddfca7a3bffffe6139ff524941d01a717dc604a009c55b9842a96430e8ab6ac8f9da24bcb38c3469a903689b4b3605b2ce0dc393582604fcca71e407144f633f28aea7849321ff131466fed252dc2fc8aad3a7d97a5d4835e286c32b3061546610014219cb1222d0efd12bf18db3eec5886fe2124ec3b204f89988c4e2d02db9b51a0b35c48d76e1bcb5c1e04f5153eafb794e0e7a8e8c408f817250db1ffc7de63ea4cd0d6fbbfa284e8cf7f67ae153ccc1815652fac7dd9984547b313be7ae8015640bbc4b056e62ccb5c8ffe1f0872a5145e958c59d0267580f78c3334dfbab06ec0db8452af07d6debcbe258cd5c5ff74a186cbfc74ca2049a34ecbe913c981ae8b8b595944af768fc95f6049c3a8feac791ba9d912a89514201739f0620259860ea94a25f591e117d08a9951cd92654cc8dc5f17de0468122503291c239529b133f7e226a5d73cda02b44663ea77f6419d0e58d6ddcd2e5921c5afdf365b27c60dccd004750bc0d21811b419c0e355d9baf18d7b6b6f7fe4fa490f8bf0987c566b83203106be1c7ad1b0d9921a7d6a4bc
#TRUST-RSA-SHA256 84df403b358e23d38ffe3f66a48243c2b6725ebbfbe4734265d2d312fb0bf5039d9a7df6246d86cb2a70a3b91744f63be4fb5eac425642a86068aa1c7cb594a9378fe034e45e67af6d004da62a501b90e40f0c9ef0e014a399b8b0f03040f94c5c99246c0bb8e10bc1af3bfc22ea7519523e3444d1bd22a9477120f71b0da8a7d1cbcadfeec3ceab55712e27ce613b98c1c77cff0554776718f9eb4c9f85a9a8cf061d7e71b6d11043fff0718a23d48e295a3e00bc7a00b02dd3b20ce6f80c5795f3bddae6d0d3a9f296e713f5697ef30bfb4edd06984bce28cafca527ddd0728b94541d7e957a79bc0527d6dfb987869466571edb0b5a04565b0518fba167913303cd386a56ac4a649cf619c936c19ead00a496f7676e1035e16e0acc97cae3304afe2ec6f87f9e14b54c2c2f76a5ed76fee00f752d41e07fc16b407fecf69d61e214c6e89ea0493a1448ea21eb2835abc934c70e4cbec300619d8964ecf8a4d77a10f6ac8f2216b736b37e805bc3a9f203f26434cd4eb1e912726539582760353e2ab3bef712dc0274f9181156a73f85ff641fadab39d0b0441bd67e6b76c238b11d7cdd560880ff970d06592339a1557effb6cef9cc3d79479257ba5f8b74637032bb760a306db006bdd937d4741778a12080ad47daaddb0a8ec407c6fd17b243e6b1a5875535eed7331ef4c57fb376b139a69b075cba3a5643822f54682f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137143);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3227");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq18527");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq83400");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ioxPE-KgGvCAf9");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOx for IOS XE Software Privilege Escalation (cisco-sa-ioxPE-KgGvCAf9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the authorization
controls for the Cisco IOx application hosting infrastructure due to incorrect handling of requests for authorization
tokens. An unauthenticated, remote attacker can exploit this, by using a crafted API call to request such a token, in
order to execute Cisco IOx API commands without proper authorization.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ioxPE-KgGvCAf9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc91c220");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq18527");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq83400");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq18527, CSCvq83400");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3227");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.4c',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
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
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
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
  '16.3.9',
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
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.3',
  '16.10.2',
  '16.10.1s',
  '16.10.1e',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['iox_enabled'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq18527, CSCvq83400',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
