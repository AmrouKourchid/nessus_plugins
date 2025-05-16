#TRUSTED 0a5061218126fc450ff367bd6951deb928ce807c0196391c907f9149c63ad754bd1ce6e78b4fc966a5d8fa90e920ced7917f827bc386311cf49344b3c9b18cd645e27b1b8041c5ba0442877be130bac743bacf6e5ede7e4174a4b6d193f828dd4b3cdfd114b8e7455147f797d8f2715b89b063c9437b7b10b140ee0f8358719a6148e668715836a2c2f2bfa9d0c9371e19aacaf2493394b9552e9658dd48ef25cd846011ef13718fc14c1e08f5e8790fffa2adac9f5b526ccb35a78f47dc5e6fd4271dfc06c3458512fae858fb16d7e63b03e6ddc15206dad49ae620d81d82afbd9280db1d1ddd9a07ce6b6fb339ef692e5144635b7acda0ff58cd12fadf1a5bfa76c2519c47164928787f5a65f07de292ac8cba9eb90f3553779ad64cab346ef471e56e68f179e0f0c46bb5756c7c04fc18a8155332ec27422eac56eb1f0de9fa1e91644d0f293a13453ba3b1213336be39093403615c7cd554e66c069a9add5f4d8fb375ee4483e834c72502dd7aceb735d7c1a2cd940b814999fb65b2245b480c4b95895d0b81098fefe797defed721fcbbc578a70aae141b100e93e6132184f23ef33d8ff9015a9ca0aabca5c11e919854dc5e67beb56b703e06ed6c8b6ef9c1aae421696161466650649680b42d1b1528ec6f2ea9fc37ce1687b5de3120d342144f9953a3cb36cd72d825b1cadc8cbdcbd1604d566ec9289367d617ee39
#TRUST-RSA-SHA256 25ef0a081d381632538f9193c5809c8821368210171712a8e2b3eb685bf3f1da1b3e4221678204e3da300588466b7ef833ab345c09eb28af9a131effa83ff0926ee3aa0102cff9c765b040b8667c2b6e52ec463d6074b3ad3782cc559afbee6aa23893134dfc6f8ec894a33da470cfdbbd58d36df747b5e3cb60cf6af8a14964a261c486dbdbdf52632b479a27000c0ca1fcb43cf5aa0f76b188f1adbd1a0326860ae748b6174407ff570dbdf089ba16c14dec314456c7cb111b99653e6057c78d1cad8b4917c65497aca749283549f0581f1268128157c39705bdf1d0dd0341d0316b8fb4c5cf02c728f301283363df37783cce0d0e1fc325d55bd42e86b43223b6526b840b75cfd26cffdeb57cbe5794af87a53e77311d87eecead253e5658dc74c22814f1cfbb3bc4f57451915817495038ba8504fe6b3d3fed849ad8f481f3a05a7546bb84efc4374619880df7a7a37813b1eeaae07539efbd21480eea7d5ebac0c439e265a594d3d5edffd0d055f57a4bbd3657fe743e6e0da89b313c88f37cb0de960bb2c3fb822e0d34d4ab6134c76cb5fd5fb431b6eacca6512e16679594c085a7efba83cabf21c358b1a31bba88d6f443e989b9fecdc58905ebc0e3ca4c395a8cb3f4c1856388c6465eca6ee59dfba60ea92c95a4e8bf06359be5dd7b8a8fee1cd0f12ee703eb1e1d885469ddf53e86248c133864dfc411981a969f
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153694);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-1625");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv78028");
  script_xref(name:"CISCO-SA", value:"cisco-sa-zbfw-pP9jfzwL");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software Zone Based Policy Firewall ICMP UDP Inspection (cisco-sa-zbfw-pP9jfzwL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Zone-Based Policy Firewall feature of Cisco IOS XE Software could allow an unauthenticated,
remote attacker to prevent the Zone-Based Policy Firewall from correctly classifying traffic. This vulnerability
exists because ICMP and UDP responder-to-initiator flows are not inspected when the Zone-Based Policy Firewall has
either Unified Threat Defense (UTD) or Application Quality of Experience (AppQoE) configured. An attacker could
exploit this vulnerability by attempting to send UDP or ICMP flows through the network. A successful exploit could
allow the attacker to inject traffic through the Zone-Based Policy Firewall, resulting in traffic being dropped
because it is incorrectly classified or in incorrect reporting figures being produced by high-speed logging (HSL).

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-zbfw-pP9jfzwL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?025c1b54");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv78028");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv78028");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1625");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# can't detect snort currently
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var version_list=make_list(
  '3.16.0S',
  '3.16.0cS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.3S',
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
  '3.16.9S',
  '3.16.10S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4s',
  '16.6.5',
  '16.6.6',
  '16.6.7',
  '16.6.8',
  '16.6.9',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1c',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '16.9.6',
  '16.9.7',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1e',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.10.3a',
  '16.10.3b',
  '16.10.4',
  '16.10.5',
  '16.10.6',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1d',
  '16.11.1f',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1b',
  '16.12.1b1',
  '16.12.1c',
  '16.12.1d',
  '16.12.1e',
  '16.12.1s',
  '16.12.2',
  '16.12.2r',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.2a',
  '17.3.1',
  '17.3.1a',
  '17.3.2',
  '17.4.1',
  '17.4.1a',
  '17.4.1b'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvv78028',
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
