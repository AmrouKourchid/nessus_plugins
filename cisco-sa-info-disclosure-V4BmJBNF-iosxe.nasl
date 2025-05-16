#TRUSTED 7dcc3f4bcdc3693fb5097c17ffa55d707d609ce2e92f1aa49a3695217b91e803e061bebed752ab49722a99776040bfee78e92a675487dd5336b49051f4ca2f5a3ce6bf081fe99a93142a4f2fa9e1e35aa32cf26e6a84544befc7e0d0125462fba978becd6d38a0080708cd926bf732668b53334b525dc2682e1ed415a91dadfb0b2d0dc04c5f57b8f9600cbd82cac203e193a065a596576d55397fa17252552752572754978343c58f2704328fd57ecb42923fc8357f95ee8f79b0b0111cf81068eb78a71976bf54c934d39e86d0f529f634035a58534ef467885ee0958193c14e9223dd40616fb5fd99a0edc39514c7c330e088b1c7eef44a2de230a38c55e2765f9d263ea56fcf8b2975ac83bb30d6048371b5b39bde14a35e170a27370172904edf8ebfb1c5366b70e0e2799ee8c66bf6b0a268a39e16e6a26a52f0081fbe59ff9e736867106fc93a47e4efc4693d4084e886cb567a292da543706373d0150aef0436fa5fc6154d247dba38a9b9fbc3ea14d554cb5f88b19e50199b32ce2914d90bcbe8d0f7a5fdf014315507190a0fdb19b17349ca1f1ca22e8abe12ed7c41ca8188188cc78d95b9acb68b00cb066225bb31525c6a19af88a8a8939c98126d3ca354f1f4d46234c0e736a60f03c45d512caef1141de677b39ad8bb22d589bd2c734e3a179337eb83df727ed43ffc05fcbf4357f4070991f9b2f49642be55
#TRUST-RSA-SHA256 42d6f268283bfdbb7b87ccbaa2c2d0bd447866ef232f780f0e941b995ab641d0580abe5b83416bd6b2a31c12a0e14e460fbbe6c4ca523c0aa1b3c968f9ac7f4c50fad6eabf320de7529d86873673fc9facbe1136114ce2805c1c617b5ff69c44eb863bd613ce43b44f16e2d1582e34df83ebccf9ab1219c898262022e60ad7ca1ea5a4eb24d20582a15935248627ff1f2726429c204d3dc0673f1d78a5e335956a67caddcb3edb31dcdccf5189bf3c3c5932ccc9a2a57958b0736e14c8d6a30e22f80a08de6ca01c93caa48dedd39dfdb5d8902fc1d036f144e0c0b969231fcbcf395135f6b25059676cc74777aa17e831f61b075adef6e24261cd7f7ef33afa260c18b9fa4d2de3370c05d9739ce618619c19930032f36a4e09923cb06d4b7f7bcbe85d4bc6aa165242501b9e26f2164ce83c13d250108352238888c1ece4d3c64a200199a0ab0060aede5469242bc50334118df5c3afdb2e5909df351750402ee5514e527745b7d5e34228245eca95cb53ff19b2ca4e1ccae6476d722009f81bc3f06a75e04cb4b3c909da3cb3271097ca7ea0ce2cc1508eedc521572f7eb40cbdc93895bf6a457c8faf65a177834fd722e364d719220822bb81a28d431de252e01d7264582bcc08ae1cf43dd0bd9d6e42d1e35f685ffaf565decfe0d9011f49f53e4214ba9ad307b5b038a366bba2d5d7baa67276da2119a0a7ec2fe75d46
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141117);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3477");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu10399");
  script_xref(name:"CISCO-SA", value:"cisco-sa-info-disclosure-V4BmJBNF");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Information Disclosure (cisco-sa-info-disclosure-V4BmJBNF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS XE is affected by a information disclosure vulnerability. An authenticated,
local attacker to access files from the flash: filesystem due to insufficient application of restrictions during the
execution of a specific command.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-info-disclosure-V4BmJBNF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b353e4e6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu10399");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu10399");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3477");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/02");

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

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.12.1y',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
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
  '3.10.3E',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.11.0E',
  '3.11.0S',
  '3.11.1E',
  '3.11.1S',
  '3.11.1aE',
  '3.11.2E',
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
  '3.16.10S',
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
  '3.16.9S',
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
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.2.0SE',
  '3.2.0SG',
  '3.2.10SG',
  '3.2.11SG',
  '3.2.1SE',
  '3.2.1SG',
  '3.2.2SE',
  '3.2.2SG',
  '3.2.3SE',
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
  '3.6.10E',
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
  '3.8.10E',
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
  '3.8.8E',
  '3.8.9E',
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

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu10399',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);