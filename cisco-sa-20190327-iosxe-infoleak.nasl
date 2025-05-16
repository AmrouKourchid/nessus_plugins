#TRUSTED 03fe95a97d94110e8c2ccdca23c3ddaef82b7ed0c86c217eeac562b321f3c5d570a97ffe67ed3dbc5dcb1cb9f7bee7ca5819c048680cda0d51211968a129ee059acd0aebe08ad748104dc56ef6a1245d9c3c2bfe6909dd12070bad0c5d04c9fb90731c15aab5eb15c7931880c29f8177d89c65ad0bd993ae984752ce07d7a56c0c37dc37b8e575a24a3aa2aa440207df2a773fd2254c2f5aeedf24b6faa191b3825050126bdd7f702e056b04ef95aea3f12184688323962377ca077fddcc28b047f46a881fe0cbdb4b945e2f1c996dd18346ce195ede5c3713fed12c4764f6d530176fc56eb3c88d4f14bf5ff4b2f51ace010f880724afc7dfba9aca89431b77132beb09d956b374e37dc1e6f9947dedcbcb9460a91d75b3b91bd5ef4bd93444156f94895503df74831088ed606cf26771971073dce0612651f5bc4bb660ef09c2e399dcd2723276da774ea99579f0369eac7bfd8d82659a6ef01db39ce4b6faddbe57fe02bfef31c475d6563a9dc6ae1b63b78162d6b2f55915ec9eff4da5413a41ec7ddbdd7b7bed457c824848b98ff9d327c2c0f1b7612972dd20d5736881627d1c7614e119c26f4477f5c68c6b87e6a2a67f5e6a23f4f5339c0fdc69ccbcc345e742d68646cc15ab3f1395c4dbcf5ec153fa7d54da1a6b1267713cf8d5e19e43cfe7aad1f97c629e2bbb8172740883b9b36360fb60bd3c53e729bb3a4aea
#TRUST-RSA-SHA256 762a20f45872455e2309f98e481ac5cf237789a69fc91969b77cafdf77adfee847dd1fbbf7c4a7105065ac9e9ab70a3773a5955bdc910a1011b06737698b15175e9fe09405a8d0fd1afb17e0688364c50390ff9f143afacf9ae2fd308ca609be68bbfdfb1b7c4fe15fa276b1b74924d3ca8b8cfa750d2a3e2e63324b6eb3239251a5bbac9c68639c8f1445049d2e4c0944d024c783d5ea152ccfec6784ce3eede449f4079286987a9f49524135d3ff991889f5b9a96c51625c3ba35f862539baabc3c596e8fbb992dbc739598707de890eb3bd99bd1562812ac2edbbe7c858c2c3b1eb046939204eb390542d0b2a5f6771b7564f9bb87079f063066b79efde4adb5e40d159b79995db6b420c1a607e2af7741f199a3b012377b8a7fcef014729792705db93a63a618d47c43200766bf76acc3d3446edbae35b9cde1b810f1ca068713b22484e417aa901963e7b113a19566ffd12e9293fe804cfb77e8ae2b1d0a2893d0a346703d4c0f0329e3a32417c4a4329a921ce33cdafa929ef94ab876e85535ce667df6c5eadb43b37fe4f35745dc5ca7a1e7d5fa66a2d89eb5a16cbc08716df85bbb558dc790eaa3900d8b86c0c646c4285a1acc2878320e0e5f48ce8752fe138e3e09af5efb3d95fa3c5dc51e1231aa043838f8c6dcc286dacda5fc1146061238ab4bb3f5a04ac1ee2a8a479d549066a36e57ceb8b6116e2387be60a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126507);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1761");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj98575");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-ios-infoleak");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software Hot Standby Router Protocol Information Leak Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the Hot Standby Router Protocol
    (HSRP) subsystem of Cisco IOS and IOS XE Software could
    allow an unauthenticated, adjacent attacker to receive
    potentially sensitive information from an affected
    device.The vulnerability is due to insufficient memory
    initialization. An attacker could exploit this
    vulnerability by receiving HSRPv2 traffic from an
    adjacent HSRP member. A successful exploit could allow
    the attacker to receive potentially sensitive
    information from the adjacent device. (CVE-2019-1761)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-ios-infoleak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46d52b7a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj98575");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvj98575");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1761");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(665);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");

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
  '16.1.1',
'16.1.2',
'16.1.3',
'16.2.1',
'16.2.2',
'16.3.1',
'16.3.1a',
'16.3.2',
'16.3.3',
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
'16.6.1',
'16.6.2',
'16.6.3',
'16.6.4',
'16.6.4a',
'16.6.4s',
'16.7.1',
'16.7.1a',
'16.7.1b',
'16.7.2',
'16.8.1',
'16.8.1a',
'16.8.1b',
'16.8.1c',
'16.8.1d',
'16.8.1e',
'16.8.1s',
'16.8.2',
'16.8.3',
'16.9.1',
'16.9.1a',
'16.9.1b',
'16.9.1c',
'16.9.1d',
'16.9.1s',
'16.9.2h',
'16.9.3h',
'3.10.0E',
'3.10.0S',
'3.10.0cE',
'3.10.10S',
'3.10.1E',
'3.10.1S',
'3.10.1aE',
'3.10.1sE',
'3.10.2E',
'3.10.2S',
'3.10.2aS',
'3.10.2tS',
'3.10.3S',
'3.10.4S',
'3.10.5S',
'3.10.6S',
'3.10.7S',
'3.10.8S',
'3.10.8aS',
'3.10.9S',
'3.11.0S',
'3.11.1S',
'3.11.2S',
'3.11.3S',
'3.11.4S',
'3.12.0S',
'3.12.0aS',
'3.12.1S',
'3.12.2S',
'3.12.3S',
'3.12.4S',
'3.13.0S',
'3.13.0aS',
'3.13.10S',
'3.13.1S',
'3.13.2S',
'3.13.2aS',
'3.13.3S',
'3.13.4S',
'3.13.5S',
'3.13.5aS',
'3.13.6S',
'3.13.6aS',
'3.13.6bS',
'3.13.7S',
'3.13.7aS',
'3.13.8S',
'3.13.9S',
'3.14.0S',
'3.14.1S',
'3.14.2S',
'3.14.3S',
'3.14.4S',
'3.15.0S',
'3.15.1S',
'3.15.1cS',
'3.15.2S',
'3.15.3S',
'3.15.4S',
'3.16.0S',
'3.16.0aS',
'3.16.0bS',
'3.16.0cS',
'3.16.1S',
'3.16.1aS',
'3.16.2S',
'3.16.2aS',
'3.16.2bS',
'3.16.3S',
'3.16.3aS',
'3.16.4S',
'3.16.4aS',
'3.16.4bS',
'3.16.4cS',
'3.16.4dS',
'3.16.4eS',
'3.16.4gS',
'3.16.5S',
'3.16.5aS',
'3.16.5bS',
'3.16.6S',
'3.16.6bS',
'3.16.7S',
'3.16.7aS',
'3.16.7bS',
'3.16.8S',
'3.17.0S',
'3.17.1S',
'3.17.1aS',
'3.17.2S',
'3.17.3S',
'3.17.4S',
'3.18.0S',
'3.18.0SP',
'3.18.0aS',
'3.18.1S',
'3.18.1SP',
'3.18.1aSP',
'3.18.1bSP',
'3.18.1cSP',
'3.18.1gSP',
'3.18.1hSP',
'3.18.1iSP',
'3.18.2S',
'3.18.2SP',
'3.18.2aSP',
'3.18.3S',
'3.18.3SP',
'3.18.3aSP',
'3.18.3bSP',
'3.18.4S',
'3.18.4SP',
'3.18.5SP',
'3.2.0SG',
'3.2.10SG',
'3.2.11SG',
'3.2.11aSG',
'3.2.1SG',
'3.2.2SG',
'3.2.3SG',
'3.2.4SG',
'3.2.5SG',
'3.2.6SG',
'3.2.7SG',
'3.2.8SG',
'3.2.9SG',
'3.3.0SE',
'3.3.0SG',
'3.3.0SQ',
'3.3.0XO',
'3.3.1SE',
'3.3.1SG',
'3.3.1SQ',
'3.3.1XO',
'3.3.2SE',
'3.3.2SG',
'3.3.2XO',
'3.3.3SE',
'3.3.4SE',
'3.3.5SE',
'3.4.0SG',
'3.4.0SQ',
'3.4.1SG',
'3.4.1SQ',
'3.4.2SG',
'3.4.3SG',
'3.4.4SG',
'3.4.5SG',
'3.4.6SG',
'3.4.7SG',
'3.4.8SG',
'3.5.0E',
'3.5.0SQ',
'3.5.1E',
'3.5.1SQ',
'3.5.2E',
'3.5.2SQ',
'3.5.3E',
'3.5.3SQ',
'3.5.4SQ',
'3.5.5SQ',
'3.5.6SQ',
'3.5.7SQ',
'3.5.8SQ',
'3.6.0E',
'3.6.0aE',
'3.6.0bE',
'3.6.1E',
'3.6.2E',
'3.6.2aE',
'3.6.3E',
'3.6.4E',
'3.6.5E',
'3.6.5aE',
'3.6.5bE',
'3.6.6E',
'3.6.7E',
'3.6.7aE',
'3.6.7bE',
'3.6.8E',
'3.6.9E',
'3.6.9aE',
'3.7.0E',
'3.7.0S',
'3.7.0bS',
'3.7.1E',
'3.7.1S',
'3.7.1aS',
'3.7.2E',
'3.7.2S',
'3.7.2tS',
'3.7.3E',
'3.7.3S',
'3.7.4E',
'3.7.4S',
'3.7.4aS',
'3.7.5E',
'3.7.5S',
'3.7.6S',
'3.7.7S',
'3.7.8S',
'3.8.0E',
'3.8.0S',
'3.8.1E',
'3.8.1S',
'3.8.2E',
'3.8.2S',
'3.8.3E',
'3.8.4E',
'3.8.5E',
'3.8.5aE',
'3.8.6E',
'3.8.7E',
'3.9.0E',
'3.9.0S',
'3.9.0aS',
'3.9.1E',
'3.9.1S',
'3.9.1aS',
'3.9.2E',
'3.9.2S',
'3.9.2bE'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['hsrp_v2'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj98575',
  'cmds'     , make_list('show standby')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
