#TRUSTED 9c81ba5adc0bf0248d96477c58f2e01cd481219ef88007f6310edf08c36d7fba03860cec0eb92d2424212fe541ea600bc5e6a53d0e8bd1620868dd363d5b3e10e85d56510d76fe8ece2b30d6199591faafeeedf88c36a46dac70b0b7cdd8496cb0fe886e59f40300cdc5b7394de4eddf0e568206d022d12a97e2d92a9b42d0377025ee4333dfb3cc2b6edc440f3f20865d9f42093d7fe2c65b654728e69a9c2b87018cd525f6844d10ef6b6fbea940929eaaf0d5601dd030744a5d10babddb548f2b55db60b6b2eff57ec8452971ad6addb5505ff932a7954957ffa3927b1bbadb47bbed40f4feacf8ca46facb9b20fa8923e14f12af82460b62c02bef3f2626dbdc87f079e1e0104959e748fbc95c9b368d694ac0d2f32b4c54a32269d36212d21bcd45f994ebf0ef779f813aeaf88fc6a1a7f57fd079a6fbc9f6589ddaaafd17d0171f40b041efbb3089fa15391ab6c2a6d71fe9919489dc0388c2140285d58014c4af2f5702018cec7251a3359b1670f538cbdb19cc69e8c1911bf54840b492292416b2d67eb49d4ddf91252338fb6c5d2e44fa02a26f95d8234de770db91e63874b42dacb9f79de07d3d1badcb77a40e3db08c81fd18979b3742c57fa2e4757449d0db6e0dff5d9b642869028d66f84cf7ce1dee38ddf211000dcd44cc66e30022721c477189c11ec5dd932206de5383438bdbef2452bc9090094c5edbe6
#TRUST-RSA-SHA256 02f42e0834676a1f60fda8737644b396634a4a9cd2faaeb1a83f61f5b8c6f5cc97c4ea4134e2797d47ca90231e077f3e05ce665c958115f0fbafceae43a1898f4736395010581a33c8c379c4380777fae0080fbc4e37d57a4dc242d260871366f67ea6a81afcd11452c47f0619b84ab4081e6763e0b4f570a2d28cb31a78d25b283e8ac36fead30919462277913143ce1e1be66478f869098bf732732fbfc4e2a92c66a12d0cf2c6ed870bcd139e1ed14098c418d287ff72ec99640fd2c5dc3d222a28baa9c34e4114fc320fda1f6dc68c42b56175f141711f2d8dc1f7ef8fe5343df9aa4b1fb6230f9939a66be618b2ad4a2248c4a4f826c9b4ac844dc76d411c40983595ba5855641b10566f798fe6df97d26ec96d97328a7991b580fa1bf2b0a7bddc2cd1cb9392af09e967df7f65e85ae3aefac7467a13886035b37c7456af55a6d17b7825772ac1c7290da150181e2b7d5b9c0db2de28b81b5b24d02e9abcbe1d3d8b836d227f6e3b39ae38fb962f31057d7d4c986d5e1cf24059264ec375cfe63baabe7b62e1a392a902d06dc5ba0c22397ae7b42245e62d68d1b192d9f21f3c8d926478010053c2c2fd83dcf35b5c52235f29d238424e0e0cac7e1615bed2f5975d23fb8a73254d87034cbf8b4dd21d75f742a309e29fb4bb14fea89f938f19499af48329d42af0c7faa840d894575533f146efed540aa3f6833faa0d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150058);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/18");

  script_cve_id("CVE-2021-1494", "CVE-2021-1495");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv70864");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw19272");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw26645");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw59055");
  script_xref(name:"IAVA", value:"2021-A-0249");
  script_xref(name:"CISCO-SA", value:"cisco-sa-http-fp-bp-KfDdcQhc");

  script_name(english:"Multiple Cisco Products Snort HTTP Detection Engine File Policy Bypass (cisco-sa-http-fp-bp-KfDdcQhc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE is affected by a vulnerability in the Snort 
  detection engine due to a flaw in the handling of HTTP header parameters. An unauthenticated, remote attacker can 
  exploit this by sending crafted HTTP packets through an affected device. A successful exploit could allow the attacker 
  to bypass a configured file policy for HTTP packets and deliver a malicious payload.

  Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-http-fp-bp-KfDdcQhc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d5152c8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv70864");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw19272");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw26645");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw59055");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1495");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1494");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(668, 693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info, vuln_ranges, reporting, model, pattern;

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Affects Multiple Cisco Devices
model = toupper(product_info['model']);
# everything is checked via uppercase
pattern = "ISR[14][0-9]{3}|ISA[0-9]{3}|CATALYST 8[0-9]{2}V|CSR82[0-9]{2}|CATALYST 8[23][0-9]{2}|CATALYST 85[0-9]{2}[-]?L|CS1[0-9]{3}|C8[023][0-9]{2}";
if(!pgrep(pattern:pattern, string:model))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0.0.0',  'fix_ver': '16.12.5'},
  {'min_ver' : '17.1.0',  'fix_ver': '17.3.3'},
  {'min_ver' : '17.4.0',  'fix_ver': '17.4.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['show_summary_snort'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv70864, CSCvw19272, CSCvw26645, CSCvw59055',
  'cmds'     , make_list('show summary')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds  : workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
