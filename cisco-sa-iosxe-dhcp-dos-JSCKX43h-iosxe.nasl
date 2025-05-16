#TRUSTED 3c9d810f6d22774bc5ac74faa42fc85fa0cf39590854e14ca92952e6e8653f54209ac93dfaefaacef12c9ba96800abba3b7fccda4bef66e27f07768e41a7448025d019d50060fbfd58a2e03bd934719e37d1b41b91e435aa4b612e1327cd48bf55a6d4eceaa7e4a6ea7890fb514bb77d4b5a396ecc3c7ecba7306ee1e2b3a1a6e68149cae6b50fab8dc533bdd8dc6d6f53be45956b5477a492328c91f0d40b9733cd5b0d1e46c2a062aad3ec673f23c6f934da2a7ec58ad5fa9df8b3a85e9562b017abfb318d73ed3d5f79a0996f6c8c83dcf937502b03c1eba61f04beffb6d866c6d303cb99e28e77e59af5d298d767a48c9b016645ce43bbbdba451f5e07a09ab5cb7971ba7464a9b2e32dfb5118f7d1180849423a2318172a961636f8b769ef8e43644a476d79093b8dd3a7fec931fe06c57676cf606147b02f8cb0ff8fb77c95290ab778d7ba6da85d1bfc2f0873f9692b40a30ee54e35983db763b84d56dded64ad3a5ace2cf99063f3775941df6f4b664c822284bfbd2a11ea506fa648ac12ae213705d30b2d4e23a2595b03c9907103b61a3307e2eb17f333b95949574d0d467380cde618df29f2129ad74f02fdbb6a44d0dd74a61e9aaa32cf3442f7fa6d8466b6549aafdd3d54a995fcbc80e94584e737fca2d90fc2714b6f2e161823b8e0e112a13b59c1c0e80ce2b574a1271f192f3839f9b7bf7986667123a644
#TRUST-RSA-SHA256 7eafea70f6b71e92bd47a679d4da4d5b68a25a4d9cd82e8c11047e266829513b0860809489585dc4e679236510390bcf394ccc030eb87fd1827619a550f437d25276275ad7680a81ecbe690a9dea834801c70f24364b48bd00fd4765a9a77d4f52ff0e711935a0b1dd5d8412eb7f6c5d71b8cb902f65c225a6c5784729ac6459595d901385853ff90e805a39d6c171cb321c43fbf4a952907b03ae9a0e7b7965c25f954745d9ebbe88402485385ced8ec70dfb1f71b3e4c2c1a13faf189a45e59000513091bb3abde6d59637452ec734cd5abef3d7cbd54684ec672e6a66391aaaf0e8522987638c98b0021af6164c82f06eb5e07cc7916bd1898d1200394e17c2f7d1ff342ce5f1b144816ad9f04058f16ce97d9e8314cf5bd0fce0ac83f0cf5524a0cab2cc43f93bf0d0497e1fd9088c9580596307c1ffa50f7de268f3b0e53563bb76384424b4be1e2ffaabc20a8bde197b2fd6f98ad8278c997e912432a1ef45f70b91874089685769a414db8bcf8b9d0e6fc647df992383f3446c8915106db183673e2174fd4bd103cbe22939386eccc2397deddbdff3aac5228271f4432f482b946689d77ef06b7cad407a1c9cad6f616a912491b43d89f4ee1e9c676b6f21d60c84a76146fbd101c8f288f9869b0aa1aa27cc525ba3c06c6139d28ffea12f9f0f1128b301e6631bc25a1550fdd8c28475a5ec3e32b953ffb6c1dbd744
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141397);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3509");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr70940");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-dhcp-dos-JSCKX43h");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software for cBR 8 Converged Broadband Routers DHCP DoS (cisco-sa-iosxe-dhcp-dos-JSCKX43h)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a DoS vulnerability in the DHCP message handler of Cisco
IOS XE Software for Cisco cBR-8 Converged Broadband Routers due to insufficient error handling when DHCP version 4
(DHCPv4) messages are parsed. An unauthenticated, remote attacker could exploit this vulnerability by sending a
malicious DHCPv4 message to or through a WAN interface of an affected device and cause the supervisor to crash and
could result in a denial of service (DoS) condition. 

This vulnerability only affects Cisco cBR-8 Converged Broadband Routers that are running a vulnerable release of Cisco
IOS XE Software and have a WAN interface connected. 

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-dhcp-dos-JSCKX43h
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f0db92c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr70940");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr70940");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3509");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(388);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_versions = make_list(
  '16.10.1',
  '16.10.1c',
  '16.10.1d',
  '16.10.1f',
  '16.10.1g',
  '16.12.1',
  '16.12.1w',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.4.1',
  '16.5.1',
  '16.6.1',
  '16.6.2',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1d',
  '16.8.1e',
  '16.9.1',
  '16.9.1a',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.3S',
  '3.16.0S',
  '3.16.10S',
  '3.16.1S',
  '3.16.2S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.2aSP',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr70940',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions
);
