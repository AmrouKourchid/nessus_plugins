#TRUSTED 12c495308418016b4008e3663b0e3f2110a7e8673f12585f51fc0e5cf07de9dcfe96f122a6e207808a019c24b97f9d50a7fcd5dff28d7318e369e93fac1f3907056db5dc9e62841238e8b0a5197ad6f6582b2398db31e30dc92004447e014111a934e2daf7dc4d0e3285b49d23e2db7c623679a6d09a725b3fe3320d99d5025aea9fe92f961fa38594a6e5e5269424683418d8f7b09dc309b36452f463ac3651f914bb93ae60f939dac60a3f31fc5dfdb41a721ee35588d5fdfb7ed4753647ae0406523638911327f39efe4b75863cd2335e2de34519c793748ad283a459eeb7bbfcc8c1e4c769730a150ddb957b4f19b28de3dc31d1354742e4e3b3e5422e500f31bae5a52f8fc6e40974e8d8290ef7e2ede3d44ca8026d028e38668c8554522cd96895614e975ee0dd0f1c6d30b7ae14f0ff649308a6729e1d04c6f9c9fd3622abc27aa9d5c2eb9b3c14db4e89cf16c86bd44bb66e70169f8d58d7c4be58550fc3a5f5dbe8be00de96753e16fcb661fb893ef72db6a2aa70e3529db7a67c4158d2b45ad64645c36e1c6244dae9d26100dbf100608ac1ac56d7943e2df8e2ef87b47874612ec8159b281b085c2eb32b07cab92c948640441bf3bb8a5527547730262b7013a41a7a4e36e45a88ae94715c1dcb9d052e439250c8fccae1785e0cdcb6c04fdf3ddb53bce8b26cc62ca5c038e26716f9d14033cb1f321255e838b7
#TRUST-RSA-SHA256 39179f5e9535f78ec031dc924d9d49ee55a5715b99d7f044a8d178fd373c46aca2b29bcfebf43ecc4d775824ab1dbc5a449702c53c0ad8bba3223e5b99cdf3faec4af32e2f4cb84e6b3cd46a5ec08689bab145ff603a4e992dec8724a4f364876a6a0ed52791e48a5f04ec0bc541420c9a84c220de091ee12fdfdf25937707c7007f99476a4433a77773ac95f35dd6463086f480560ce6907da27e4f7788906b1bfa333d4792bf62bccf238443015bfc60ec8d76aba418eb55ed6c125e754ceba4a4a7f55e3c2442063939cec6061a1b54fa024c2838f98a850b578ebc1f1fc2dd232898c623d31ba39dc08d54dd54401388fe7d807632a8f247cce740b075d0ed7cd3dcbae474a574e1e9d4f3df41bc29bb920032d7f3ab4a695f11b612fe115814cc94b852f00eaec190d03e5c972bc7b0157fc8b78b4b566790d3dbdf1f58677e757ae0f1aad77992dcde65cbd340fa43d021d02a9ba1d2b6aeea948d06687491532844477f4641568e311d6bdb7ea8f86643b69e4cc99d372f5918747ba12b093d3808e193cc3f680e773b3da4e4e77a3b65492fb72774461802cc565e55c55666d12aa2b1ba697ff2377ee0e76aebd825f2579836013038ffd3cb519b3e0c2e4130a71990954b022d0062a34060b20daee8b407bafa5ee32dea6c100977bd6fb7853afe7c0cdb4e78c06458d9d1ca5f95e922d4efbe5f990d1d0be4eab3
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131395);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-6770");
  script_bugtraq_id(100005);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva74756");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170727-ospf");

  script_name(english:"Cisco IOS XE Software OSPF LSA Manipulation (cisco-sa-20170727-ospf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability involving the Open
Shortest Path First (OSPF) Routing Protocol Link State Advertisement (LSA) database. An unauthenticated, remote attacker
can exploit this, by injecting crafted OSPF LSA type 1 packets, to cause the targeted router to flush its routing table
and propagate the crafted OSPF LSA type 1 update through the OSPF AS domain, allowing the attacker to intercept or
black-hole traffic. Successful exploitation of this vulnerability requires that an attacker first accurately determine
certain parameters within the LSA database on the target router.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170727-ospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c4d1c57");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva74756");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCva74756.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
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
  '3.2.11SG',
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
  '3.3.0SG',
  '3.3.2SG',
  '3.3.1SG',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.0xaS',
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
  '3.4.8SG',
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
  '3.10.1xcS',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.1xbS',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
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
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.6E',
  '3.6.5aE',
  '3.6.5bE',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.1cS',
  '3.15.2xbS',
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
  '3.7.4E',
  '3.7.5E',
  '3.5.0SQ',
  '3.5.1SQ',
  '3.5.2SQ',
  '3.5.3SQ',
  '3.5.4SQ',
  '3.5.5SQ',
  '3.5.6SQ',
  '3.5.7SQ',
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
  '3.16.5aS',
  '3.16.5bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '3.2.0JA',
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.4.1',
  '16.4.2',
  '16.5.1',
  '16.5.1b',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.3bSP',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ios_iosxe_nxos_ospf'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCva74756',
  'cmds'     , make_list('show ip ospf interface')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
