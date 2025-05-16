#TRUSTED 4fbe21f49cc20a862162116a751d71a3c88d14b9e1b8c564e7368e908129cfea057b0f6689aa7d922405f49dc2de8e384c7e36b19b721cb921e088b5f5c739addccb628858b046c197ea6bdea1eeb4d7902fdab474132dcd19bf2c0fdc9f70c0800232115a62c387967dd3bd276cfa9b8666dff9a703bd994c6c2cdffd6d588d56d1c3bcaf64aaad07c837b0674772ac2406d5952851609b3e0d987b268a05cf3701018fe04952a08e64c398daf49e296b274a2728b09f387746c43cebf0f6ec3fe1e0de0c53dcaa7818c99ac249b215f8fcadacd05d38dbf17ed7d69b07470380a05839d9cf6c6b0aad109ae66664b9acb078a739ed41d33ede84fffd3f09823094fdd7bfa02ee670e0c7c39b8ac797398bafb01fba8ee842a3dab0032e257b998c84f0ef3c3e235048ba0400fbc56998a50e44e0c70a4ab94d499e05c3c1d41247f7dd19b859da0bec03652fb0e87b0e5afba28ce6d62f9e1457635221af9a3a0679b1c1d55b887a991af923801a20698e3fdc037f87e1afa4a6747ac2520bb1f19be243046e3b52c9dd925647054fa1590d7022d0bb3739e23e632a83df6b9b3bbd09379dbc147d14df7b607bd53f447a521bc073c85672ade66094e95dd64972d7327db91c8fcdd782f66828f0434fca31812f4e6dda8d9753ea81af6b9f36c667f9d9a57cdf342896e4c2bb90e020b7bbecc1bbadcb606011e3f0e2abbd
#TRUST-RSA-SHA256 65ac5f311fe1376004771e14cc6c040c94a2fae5b92cbeed2b092a6e505607e14b7264ac67fdcd3bfb9d0edf4fedd92dc184f092b7cfedadf4b2579b75568fa8e98df0928b38386ae82f145ab529f53544e4460bd4c0095c3e677e2660f7255e7ab763e7ec9d5121fa585ff0790694f3f2e917ec749ad29383b8ce68ac481cfa794ed8196f09cc6f9cae7c9d49e4f3ff886abdf4f15be8b7b7da97fe70a58eca137980fbcb698a520e01648a7fb7df78e9c4a236c3d6d8c7937f57aa1989f83494a12e4db263d03a7a64436d8b1f539fa41a6071cafed7435a4b2ec5e5f2350fe29aee19bfa940f1c060668d70c0fecf22e8cec47f4713b11e41cff6204bb20364c0c68bc34b9329dcabb92285aef7d250c4c359519f0f36c8d621203c689985417169bf7cf8ffa1b8b9abaa92800c6f7e3ef97cb27dcfe252b2fea5fcbf2518fb9842a11b495f3bf5605e55ac15ed147161858c7dbb554542127f778c64abdfedb5558c24336774ca03d10e0fc6452f0a942adecdfe50a74d8ab2fe1adc6c4b26e2c00055db0c9cba603d9068cf9f77de6c4195c1042e27472470a38ea380ab67ecb8fdd36eac6b239f90bf54b4fc9103bb1d9ad351ab30ae4ca33944f6a7204361e956a0ae36802aad501f395e746ed114194ac26e9687f52df1866cc9c85e8e6be53cc9c803e0ad61a20f71c38c02bb59c81396167cded85802794509455e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216074);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id("CVE-2025-20124", "CVE-2025-20125");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk14901");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk14916");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-multivuls-FTW9AOXF");
  script_xref(name:"IAVA", value:"2024-A-0710");

  script_name(english:"Cisco Identity Services Engine Insecure Java Deserialization and Authorization Bypass Vulnerabilities (cisco-sa-ise-multivuls-FTW9AOXF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Insecure Java Deserialization and Authorization
Bypass Vulnerabilities is affected by multiple vulnerabilities.

  - A vulnerability in an API of Cisco ISE could allow an authenticated, remote attacker to execute arbitrary
    commands as the root user on an affected device. This vulnerability is due to insecure deserialization of
    user-supplied Java byte streams by the affected software. An attacker could exploit this vulnerability by
    sending a crafted serialized Java object to an affected API. A successful exploit could allow the attacker
    to execute arbitrary commands on the device and elevate privileges. Note:To successfully exploit
    this vulnerability, the attacker must have valid read-only administrative credentials. In a single-node
    deployment, new devices will not be able to authenticate during the reload time. (CVE-2025-20124)

  - A vulnerability in an API of Cisco ISE could allow an authenticated, remote attacker with valid read-only
    credentials to obtain sensitive information, change node configurations, and restart the node. This
    vulnerability is due to a lack of authorization in a specific API and improper validation of user-supplied
    data. An attacker could exploit this vulnerability by sending a crafted HTTP request to a specific API on
    the device. A successful exploit could allow the attacker to attacker to obtain information, modify system
    configuration, and reload the device. Note:To successfully exploit this vulnerability, the attacker
    must have valid read-only administrative credentials. In a single-node deployment, new devices will not be
    able to authenticate during the reload time. (CVE-2025-20125)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multivuls-FTW9AOXF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f0bb0a4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk14901");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk14916");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwk14901, CSCwk14916");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20125");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(285, 502);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'10'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'7'},
  {'min_ver':'3.3', 'fix_ver':'3.3.0.430', required_patch:'4'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwk14901, CSCwk14916',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
