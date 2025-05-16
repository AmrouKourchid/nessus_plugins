#TRUSTED b0e9dc9dc577190ebff615d1cb91ee73358ba11d254d6b6ba11cd3d26f78465be0e5a2e34f8c5889c01cb1d674fbe991908531d99841e2eb6ac7172a5938544aaf4b3022e5f643b2c3e2777ce9465f5de6f4765af329fe05566f46a9206531b3ab8ec9ed2a67a52e6987d3bd7748068104ea1f8e47484406d7fe5e15785a820af1c255469832dbc728206e9c2e233ffd66d5b45cb37572bd692dd445106bdf80917a2c8579d969e901aa672d87009ba25e4db9b17a0d7004c23de00b3fb0f43aad94e09117f8f4de621293727747b888602cbb7861764c46971aef87a62fd1c391d07a4c41a35e5531fa0443032ef3a39358982a8a63762669199ed989140abf9e080d9763ebd339655f06752ffd988c0954630b9e325cbaba7f4d2d31badd31444ac97e3ddf5257f60ac133c57cf961e07c38962df33a3e7cc619848bc6d95b5035bf3842a9467837844384a4722d3bb93f633998685a11748019a7d18998146db5d126c564977210e060c895f7ec581e1d8629ade6139d87b50e78e8474e6cf7fe51afaee5ca481959c11be7e33b59964bc46b0ca8828063a7d44442a0ee077a8c1ff2a19d709077af221421d1f332876bbceaafea054718afae536765f171dba0125ce8f25aa9cf3c073da5ae29c814d78c25cefa9d6cab2f4f71f6831682bd29da80d53994340a340403e11a9fde3114f5b1eff047175ee88f11e3e4ae67
#TRUST-RSA-SHA256 8c1a2ac143a3ba7ea1720ab574534a628d1fef56429e3b4a58a80a91ca65a401ac93894d40604c2a2cb8ad15e73bd7a515c25e52958768425dde4957b14c943f39d3a51a436d69eac3f4ffb9a88cc4e9b1ed3357bfb08d4e16319f455473e00beac22993e0d6030c9f93e0e43c78bd8dfdfdb6ff6a9458629444b7180593fa4a9e70adf0d386aec99fc7f4b46b455e15658d4be6f3e3c546fcdbcbca9cf2de7e856666e30c2d389399616d1457e25f002510b4c25e74119ed6c84bf13e7cf3e98723c10d876f8817a7b90dc19720d3a673f7c0478f652265aeaf2cdb37fb2868910fff4f1136409b403e98ecef31332dc03faccda60e5597abbbae40c09e9c8d0739ff7544ca093f56f2a54baac50aa1609cee2ab227e51cd0fb69b1aa20813ee43b5d20b119795df6c7c6136c5c8f2963f701b7aefbef5b4d07476e22e5e7c22ad141b58b93c5fe7ab1e9c724df9492fd0da1056cd2c1243bd9d8ea5fdb9d477d49460a20d17a22b5204894cbda478774e0ac4a2dc90f4bd70cd9ae13ba6f6fd66257e444a7658c8275cadc98509db0bd61f8f745277a70b5e67dc003907871e127da230c82da827d8300805302f5b34f1da13f191d66b5a10b3ab4505c41dd8a6200dccbfaba876919e525be765ed1688519ff7736ab17a48c87f9e25298e8d5edd903208f7eec11acd5bc325d0d55a66956c6972a25ab114bc3ddde3cf080
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210345);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm79091");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-vdb-snort-djj4cnbR");

  script_name(english:"Cisco Firepower Threat Defense Software Database with Snort Detection Engine Security Policy Bypass and DoS Issue (cisco-sa-ftd-vdb-snort-djj4cnbR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software  Database with Snort Detection Engine
Security Policy Bypass and Denial of Service Issue is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-vdb-snort-djj4cnbR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4eb023ea");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm79091");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwm79091");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on an in-depth analysis of the vendor advisory.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var show_version_cmd = get_kb_item('Host/Cisco/show_version');
var vdb_regex = "VDB\sversion\s+:\s396";

var match = pregmatch(pattern:vdb_regex, string:show_version_cmd);

if (empty_or_null(match)) {
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco Firepower Threat Defense');
}

var version_list=make_list(
  product_info['version']
);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwm79091',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
