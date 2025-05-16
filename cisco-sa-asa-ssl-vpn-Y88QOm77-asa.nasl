#TRUSTED aa77b4f23df637eba1a3f612af0260dc776dc54f16664d6617358cc0acc4f30b33e904bd92e53a24d3d4fa2f852744539059de051247dc542837958cdb4dd162e004ec211376e08655ce283a77c1d4480d59d8abc2bfff9809b3bebca5c2e8de54cd5f30def57c38f6640d0f1c1801afc1afa1c0ec3b156c915dfc12b76d9ac637ea8a2ee5db0af1b8f898d69e91428759ff640a502d06d7437c2627ebb37cc4dc82866c48ceed1de464136bf32aebefa213aeb4599e9b776a5b852ad2c9f0b6bb9b073bc4875516f4380b2e428dbb41a3a3a79cd0587172e5d7f3349e17844274dbfb943d9f13bf693adf2ff72ceb31d9b7d4c8548bf7e3b6cfc3f797ac6c0cc0b0421c35cc0ce0352289ae795420528c4180c49eb99bb43d7c8ae96e75f14f1d205766e969d29b5bfe6b9be376c61c5ff688f83d76819bf585b34064e28332f32d8ab44241fed13cc475eaffa480ac9ae5b049b4685e0951bbde33a0eed48551416c1956b8ea8a4bb166e29124844a59ef48dee1c938e4321479925d369068d87957ff7881d77e4b92a021f9483047c444050e500ae5d7249ccf9740c7b9acd2aeb059350d93e39a1b5244bf49d5f84b7bdc36b2a8effce17d44d3ccab011e32af04dbc08833cc7deae430e6c56332aa62a1da6fd39d99b86c80491bc71d8051c43f68aa33332141b8771a1f92fc9bb8ad990e5c8abe5edb35f09d267625fc
#TRUST-RSA-SHA256 b2c46f6b645e153aa43ea78e7a5e43b085a47253fd6e4e86dfd92885b74fae16c771964e335b9ff917c442a8ced14328056d96280ac6f2f282791650bbca2025c9aea9d75705390ca54b4d877f6fb35b2f9344e7c652816c027bff32de4f24ed3817d5a9ecb94287f1acce455cedd029da066a0474f751710d97feee4e6b71d495a2ad2fc69483fce785e482207f13eba9211d84003c57d2aadc2b70fbd58eaf804773c0bb58c8ba491c1b8601fa698381a74c0cf66fa5899c20e2f711eb53eeb877d4846d79b0f9b8dde9d81137b8fba8a35bd464293a1ce5dbd7e83cfff8d53ae4fdc714ca32d1833fdf39203dbaffba413c03b8db595a7482ccd8a7503a5e4dba650667e2bd30aac694e78a0fd2ed825b4f1b058148647c1e830735168bff2b14eec3124ef5093a38d3fb1945a5469ac8a2940accbe87d5d1c4134d515b66ebdf8f86f5d04168ff6b4a943090328d74b81c83a46d5332f6e12b73cd84716e5b5ff1591887863995050a7ae355d0bf7eb2cdc542595acfe3eabf0615fa53d7af492e491c9122a09e64a070562b1b9f58f9be8c76bfdce5d8bd674ccbebbbd0c8650d214f62ceda15be7528765a14e0cb4820ce274036e31f552e3a3e935bbae86eb9757b543a62bda078acea9a143f64e57cec60715369fbb409bb1de9ff12842d727d7d253aeaf5fb24442c3dc54469f6776b28dfd4d76c0fd08487d0b2eb
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186713);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/21");

  script_cve_id("CVE-2023-20275");
  script_xref(name:"IAVA", value:"2023-A-0673");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd98316");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ssl-vpn-Y88QOm77");

  script_name(english:"Cisco Adaptive Security Appliance Software VPN Packet Validation (cisco-sa-asa-ssl-vpn-Y88QOm77)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a VPN packet validation vulnerability
that could allow an authenticated, remote attacker to send packets with another VPN user's source IP address. 
This vulnerability is due to improper validation of the packet's inner source IP address after decryption. 
An attacker could exploit this vulnerability by sending crafted packets through the tunnel. A successful exploit
could allow the attacker to send a packet impersonating another VPN user's IP address. It is not possible for 
the attacker to receive return packets.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ssl-vpn-Y88QOm77
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c13de707");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd98316");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20275");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.12.4.62'},
  {'min_ver': '9.13', 'fix_ver': '9.16.4.38'},
  {'min_ver': '9.17', 'fix_ver': '9.17.1.33'},
  {'min_ver': '9.18', 'fix_ver': '9.18.3.53', 'fixed_display': '9.18.3.53 / 9.18.4'},
  {'min_ver': '9.19', 'fix_ver': '9.19.1.18'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['ssl_vpn'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwd98316'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
