#TRUSTED 09f26e5dbe09bde4fdab6111eafbb0d9843c14bba0c8296ffb11ffdd85d65cdcfc596d062bfe8c9e58600ca0d2e8b33dcee30d2c9eb24ca1062fd59ea653424170c9d9e48fc00ba60bf1e05e5ab3539c34fcb47aae4ffdfc583e540c098cce387552e3fc9837c042675e7c91a15872ed40e014410922199ef1f783ccd45c9b774d030b02383ff5cb90ebc23eb45adb30f6b2464de036373cbed4d6e21d70f012e470d41600e443feb58ee41654101b9d3ff84c35a4e48dc0882e77a2907742364dd7f485eafb3cc1254b0a61ae00b9219396c6c3051439e184b527768015f564e3347ad983b9c5be12fb216cc0f303787febdb35a9f6b156da91cff2ebba153c855d78e3ff5b32c02bdd5691daf34d0275ebff4c4031a1923249a47a6da3c7961ab455f6bdfde726f821940a04e1c5edae2e8abca42c8761cd8f777646734125582009d1a93a3ab9b51c20c8ced51cb06559b0686352e1349fc714eb5126bffcb118dd1e71762f5116b71e8f82d41ab56b4492dcf946b5359de2333b3c52145a967ed5bde4555a60a002a07087ac8cee006c76e324338eb74939e854d6757f6b12ca8917ded295d85dbe87cbe7c4bb19be0af02c7e986e19d298ef1cad68591c204d2e41d74abce6ac57271f8e31563d6fcd5130ae0e0e10e2e1dfba670a70005bf12ddd0658850c7aa17c58ea3597df925536c1cbdad631841838d3ee311e16
#TRUST-RSA-SHA256 3075d2a9083dc01e4fb9868edd2c5e69bf3ccbf1920f66239e03acc2cc62ef8713449a7c63b304aed3517fe2e2d15be28d71b774d354d10f7147529887bcfcbd4da8b5e705b45c5f0eff5aaac298c08dbf54dc6eb67c0b1903bf48ecc5ebfab9f5c93002bc75611b4891b87cd79ee6721aa8a71c1d532b983e36bd86adbb9ba708b0e52b9ad77ebe8cd55c98552981937ccc9468ad6cece22b323b7081c0cc15f9ffa192357374a9110505343b7aa3edbb4c5941e18e51f5374e336e03f0f86379631296f6fc1333b7443d011d39bbf574f606021a6e308a9e692ea81ce34f972a4c0149179783182dd2943de9b6354d8ba9e8e8f0e7461527924fc7eb4670fc5dce632c639efcb5537a77ec456930b1082e4eb4887aa7695ab415c270d24c4c099d59764b11520f5452dc8326216e570d55c695584efd1f8557275658fa3d3647cb6ef8ce425c485c43391669955f6f440d794bcdc3db2eb9e73f6fba9f91e00cacbd650b735674f70a36b0662e919a83feab9bb059a29804d5f9322d82fed58da2045de8f83d6b5c46e310ee3e85d1d2988269683f27de447936db3831d387efa912d14417a23be82718921a153b1caf6b73e64d8c216e39fb50f78270b15b6cbf1083fd942c7a856d97f2469cb201d4f3980ffa8a00878612cd7cd0a3e726846b4d0936690be32402373965f632e54683ff01e87519e9ceaad99d3076d38d
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198228);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2024-20363");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh22565");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh73244");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort3-ips-bypass-uE69KBMd");
  script_xref(name:"IAVA", value:"2024-A-0314");

  script_name(english:"Cisco Firepower Threat Defense Software Snort 3 HTTP Intrusion Prevention System Rule Bypass (cisco-sa-snort3-ips-bypass-uE69KBMd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense (FTD) Software is affected by a vulnerability.

  - Multiple Cisco products are affected by a vulnerability in the Snort Intrusion Prevention System (IPS)
    rule engine that could allow an unauthenticated, remote attacker to bypass the configured rules on an
    affected system. This vulnerability is due to incorrect HTTP packet handling. An attacker could exploit
    this vulnerability by sending crafted HTTP packets through an affected device. A successful exploit could
    allow the attacker to bypass configured IPS rules and allow uninspected traffic onto the network.
    (CVE-2024-20363)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort3-ips-bypass-uE69KBMd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6561188");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75298
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb75e370");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh22565");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh73244");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwh22565, CSCwh73244");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20363");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(290);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var model = product_info.model;
if (empty_or_null(model))
  model = get_kb_item('installed_sw/Cisco Firepower Threat Defense/Lw$$/Chassis Model Number');

if (model !~ '(FPR|Firepower )(42[0-9]{2})')
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [ {'min_ver': '7.4.0', 'fix_ver': '7.4.1'} ];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['utd_enabled'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwh22565, CSCwh73244'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
