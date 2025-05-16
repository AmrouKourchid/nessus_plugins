#TRUSTED 762d6b9d5ba864ed53297d5c22a64bbe6ad592d4752a89d9a8b5c3344cb8103aeea69cd5e11fb3b84f06cb40fad19688995aebdf0ce5fd1563aadf4735b389311d811541a65de96cb75ccdfdd4e94b3e2fb24c6bde52b51c210ed743d1aae644a9e8f63328f766ae213ee958dcdacfec729344a481bb1c37a115a9cc3ae063f3f73082d9732150297aba384f5d607c6c33134bf7e12e354b469734508f96177b626a76f560a99e202b57005c815765789a483bffc91bb844b8aab69e5fdb3cb9104f84f36a576f36d16564f13d4de32f47f3550e8555b35ade2c4e0aaf3394edc99c8485665bd73a36459ec93a752f39b18f80368909edfe8263cde1b5c55cc74b3d42df965db2ce3e062014b12e85d9e0948fbb3892de3828ddf85e9c9f58333e11fe0cba22ec9f3768b0c64f289c18e945b652d7bcaad9dbe70fd2d6432bd624a6aba6f632382ec68f6bb6bb9d8e2ed2e090d6a40be85088d41b518f7c1d44038933689f3d3980b6e1a78066cf3a749aef685e065cf1497e3acd6a8f200ac7c84dac411e249e49e856e20cf7a2e5f38930410afada2aaabce4f25a2ec48b46597324fc6bb33ba3346125046a5c0b7cc77b7ded7365dd490c8fff95997f3d6923a94484eabc197b6ea5a2f8a33008e45a29a7abaec3fbfbe520511f42803728c99a47ffe439df8483bbb8ea8a4f9da757cc5ed602b6d796a03182a5511bf593
#TRUST-RSA-SHA256 a9791a239b505d7abf9f66c4fb8448cf374121ce8a92983f944d08694913857c40e15569b2da812e30ee15798cdb54d0fddef927df2e0f266096568ab87329de14d81a86c31a98aeea7a3b1682fb95a74b1d9e8b7a16dae1b106d1de4580bd751e84d008eb49c5704b78f90f5a8cd48e06505be902dd75d48935bbfef9791810c3987186eb2cd356b559601a8d380b59103bc99d417fd422a4777312f21fb00e11443aab0a5e60cd8786e343db85662ce859dd4009b34060c4af607d1d5d08571e243b8d85822f1706415feae0edefbb1c7bb4a87e552e08c52f25f184619d2b5763a450d206edd5261a75b2826d590a7baa8c3e89f6f400116f1fff342a1e321f5a5fb0d1c5ed540700c2c27ebcbed2be3e9d8755404a3e464f75982a8b4e4e2e19a62eaf6b65d4566f84a74bfd2d828aff8f1b9a8931b4a98d15dffc4e3a3a4868c99934aa8cda7b94661323f89a0a7e900d5262f28e5c5e9d496d7dc7cf4e1d384de7dbcc26ebf8f888c12bd9050966bda6f6d46c6168c1170e1a0719dedb0a0c9c91b2b9ff55a0f8c32ae486d250e057273511e1fcc4444fe972179a0f147ef3693ab5e0e01282a0e8d902534f808cf908aa1e1a3f222f4bbbf2ff89902a8ca6c842d51b2c1322fee3eca1b2e0f945fbdc12f1b98dbee98ae4d89353f5b726acfa37175c5b32cab6056dafc3adf1cd9e062f253dd6b0957731b1c8415b65
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189994);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/06");

  script_cve_id("CVE-2023-20247");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe20918");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-multi-cert-dzA3h5PT");

  script_name(english:"Cisco Firepower Threat Defense Software VPN Authentication Bypass (cisco-sa-asaftd-multi-cert-dzA3h5PT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a Remote Access SSL VPN Multiple
Certificate Authentication Bypass vulnerability that could allow an authenticated, remote attacker to bypass
a configured multiple certificate authentication policy and connect using only a valid username and password.
This vulnerability is due to improper error handling during remote access VPN authentication. An attacker 
could exploit this vulnerability by sending crafted requests during remote access VPN session establishment. 
A successful exploit could allow the attacker to bypass the configured multiple certificate authentication 
policy while retaining the privileges and permissions associated with the original connection profile.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-multi-cert-dzA3h5PT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?330ef64d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe20918");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20247");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
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

var vuln_ranges = [
  {'min_ver': '6.2.2', 'fix_ver': '6.4.0.17'},
  {'min_ver': '6.7.0', 'fix_ver': '7.0.6'},
  {'min_ver': '7.1.0', 'fix_ver': '7.2.4.1', 'fixed_display' : '7.2.4.1 / 7.2.5'},
  {'min_ver': '7.3.0', 'fix_ver': '7.3.1.2', 'fixed_display' : 'See vendor advisory'}
  ];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['ssl_vpn'],
  WORKAROUND_CONFIG['tunnel_group_multiple_certificate'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe20918'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
