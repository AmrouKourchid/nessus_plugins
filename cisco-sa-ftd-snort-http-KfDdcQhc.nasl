#TRUSTED 9158024fa89b4b75539c03cb5dcd6208da92ca7df5dc4b5254dd10067131b1e24ba06d68c107c1f6c5df2d0285445684f6103d03f0b3c5d2523abc14e03d1d0333902c9d14a9cfe1f97ef77e39b321526d1e13c443316601a4a6c2e7f87144379781ceac5d1dc4ede13c2e27c5771a12f4287dd7104ef28f8890aa6e51ab85f7a051791ad69a1e77e12130455ac978e8775ea3632f2768c9b009d7153a08799f6537335ca4b94f0b5cb4b18b50ad23d3e6efb26a3949e2d365afb1f11d75e0338eaa9644a9a04dd507a0c0feebd870aaf0ea03ee1d0ed0beaa475360a26b70d46dd4f36a1981ead8b81ff34c7fd10485bfc89e6d25fb62dee875097c39c7e2587ae2064110bf85196779636967d51f874812d31a74c354642121bcbef61c6b8cc03c8d1e3e2d76017eaaa87ef243083ce6db97f95241aa687d4643b0e3c5748ad27292fed29330bf5f474befa8e27e36ec77c8ae3e69c1b0e7c8aab2773fe429b8d72678539928532217cc28be40b974efa03faa9a314dbaeed5db01b2496dcac3abf27a515b1c9297cfb87327ef3d4bf8d401542dd1c286e35a88844074c6ce3adb7bf134f98bc64bf8ff1a38da827e5637366723ac1d70dcd3eede808621880dcdd2c84335820af73d95ddb679e138ca5ec324492803762991e2590dd72b9ad94a32418b519ea09fc3b59e5d18e92dc5e77b4679b5152cef94fe9492e2fa86
#TRUST-RSA-SHA256 701da0344fcac5d82262fc978e3c22bfaf9a745e666c8ccb89781ec76589f8d29b3285d39f11915c3b69f2c3216bf7b703b477451369267f8584fafd8a56467f6243c2fbe138eb7145bb6692e65aeb275045a50c9cd6e504358b515a22a7537461d643dc4b79145556dea0160b442b10c3bf8d21b643b79fb16dd1a28f95fdb3862a7df65a2c4205e8fd267a228aea1c90731f4b7d7eb747b57bf773a48cb4a40058c2a0507d6b21d3e01ee8ce4d389ad3776bf244b857dc0b4b62a695b2d43a49ba1ef56d08836a11c4a616394091b71acef0e6e298ff700e2cd264f1c882a23b7ae26c3ad75bd8fda438a381447c5b80f371d7b8754a54abcb71cf7b85db15fae5978a17abf56c0950eb690bb703d924a96c6769d649901ef284cacadcc1b9ba6ad873cbc9bf8abb594ab8681996cda526c45c005b7320157ce122e7773852d7b97ae8c692f9a9a7d0ee80e0c66705af2a574367eb337318de3b8ee3b34b0efe31aa562c8aaa5d50007c3eefa7f54795e73ad059f0ca7c8d61934f703704444182363faeaca701b2011302b92a98aed934536158a8179a761494d0f90482426c8f6ab3a9e9bc8a6c02bef9eb81a78d2b12b539469fdb1c07fc1fae4c8b8fdb4faa6b208d70b15e4a0321c6f8b0781a38c983b5b309b344ff310b21655f06869ada16044dfa7e5452d2461e5b885336a9519e078197906ffbdff4eb1ac83182
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150059);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/18");

  script_cve_id("CVE-2021-1494", "CVE-2021-1495");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv70864");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw19272");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw26645");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw59055");
  script_xref(name:"IAVA", value:"2021-A-0249");
  script_xref(name:"CISCO-SA", value:"cisco-sa-http-fp-bp-KfDdcQhc");

  script_name(english:"Cisco Firepower Threat Defence Snort HTTP Detection Engine File Policy Bypass (cisco-sa-http-fp-bp-KfDdcQhc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE is affected by a vulnerability in the Snort 
  detection engine due to a flaw in the handling of HTTP header parameters. An unauthenticated, remote attacker can exploit this by 
  sending crafted HTTP packets through an affected device. A successful exploit could allow the attacker to bypass a configured file 
  policy for HTTP packets and deliver a malicious payload.

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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}
include('ccf.inc');

var product_info, vuln_ranges, reporitng;

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0.0',  'fix_ver': '6.4.0.12'},
  {'min_ver' : '6.5.0',  'fix_ver': '6.6.4'},
  {'min_ver' : '6.7.0',  'fix_ver': '6.7.0.2'},
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv70864, CSCvw19272, CSCvw26645, CSCvw59055',
  'disable_caveat', TRUE
);

  cisco::check_and_report(
    product_info:product_info, 
    reporting:reporting, 
    vuln_ranges:vuln_ranges
);
