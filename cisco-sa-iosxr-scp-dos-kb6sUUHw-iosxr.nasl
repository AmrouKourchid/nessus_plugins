#TRUSTED 1c95d0f7e3bc8d3f04cf6f14b0d5bd09cb00004b129dfe963f5308e6d7eb462e8ec4840b79a07c83c3f1f61a4dde25dce1d995c08fa456d31c4eacbe097ffd253edaa6f08e01a6c29c7b81a13ae82d1f522d6701579f523c6a72515da53fbff4611f9913007206acaf5865a37ac94de1561f5131fee20067fd00e5320cacd3b35922e7811dfe392d22a863cf0f7d2d1d7027dd498042c49fe1d72ff0d02289db83875f123261ae76c99e8184031caf265f1167d0fa789f5ed844c6c5b151c0df806fc841a895a68b2a940dd15f116b0e2aaa621c772658d8ba4b2ebf908c1e752db603055078eab930ed8974b99f768badd62370e121439a5b9bea7b2f092250dbb1e6f8cf97e04cbf9ba227a6ba244401ff33201a6086dfe201354e2adc36bffdee58ae8a737e431bd46c5670ebbb5a2a991eb6bfaaf11acb3ef31c2811260a1bafd8913b9cf300081754154998498ea24d795ea7e391dcd8af4b6a09b158ca0761c09bde86e370605dc2498f1b046f01b1a491f98d8f62c6372b87fc7f3d4fd3ffa759da3a0ecdab1ba53b22b3abc93cb9b75298b2c7dcba88948412ad059a7d12d6af5b22c91aa5bea03d9da4309e6c41c3cd8cc67e7c4b751fa983e48e27cd1902bfdbda22fc2177bb7f782a4d831bb6595e6c22b55f1361d1b14a9782c7f6a3127690ff43ab054ce9472b6cd5f1c7265215af43e3a72f723938c6727f4b
#TRUST-RSA-SHA256 0034e02867b0805e1b41fa4a2d341feb3267a4e5aa46cdc5be19f9d0f0ad59f97ea1ecce07a31057107754497afaa7d15cc4e02a21027bd1e8e5312913e89ac4eae1e321ee7791617d20c454f6a2fd4603ff197f7e86891a4347be31dfd3227fa9a5fdb097d144ea5119aeae51c24f0a90bde0256d4fa178983f408a490fd1f70b35d61c175695ff04674de2448a08e5f8b650704c9ba664d5fc4966b862dac3aadf94b10480ac2e4c9fabeaf35e44b11603f1def4672751a8b292f2424045aa5a9b5790fa1060fc0bb2b6f5155741c74630a183c7c8830b810704aa2731d98812f40f223acab2a1121d4ac7203f76315670dfb227c5bfe991d0dfcd84d0066b60cacb4f4fe9e80ba603a8a346ada4a4bd5ac2ca708d242c564ecc7a882f05e7d596382a9331d567cddcdba138cbfa765c980894f11a814d1d6f7fb4a812b6c369112c77d5b2b87a3fc65bf8056ed9c618bbd7ed14507fbf17d8b7a13cac084870088cc5b5faeff306127be1e5b8e873e5c8e68b40f7c6144203e91e5900faa43f5f1efb8f49e9a29d6e8309826a2382319d72b257a53d51182357445cae44a11ce5ac26569ebca77a59d149ee8ecc6f37bc733e58c8c2feb99db02aca1ed34949bbae25e1f25ca35d3c933d0ec60d5b14d9a8d778100ed1321c4a4e4ef1bba482177cb9e949f547414c9df163079cc9af285e488a661a68e12d9bc9d6981691
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192108);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/13");

  script_cve_id("CVE-2024-20262");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf11720");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-scp-dos-kb6sUUHw");
  script_xref(name:"IAVA", value:"2024-A-0169-S");

  script_name(english:"Cisco IOS XR Software Authenticated CLI SCP/SFTP DoS (cisco-sa-iosxr-scp-dos-kb6sUUHw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the Secure Copy Protocol (SCP) and SFTP feature of Cisco IOS XR Software could allow an
    authenticated, local attacker to create or overwrite files in a system directory, which could lead to a
    denial of service (DoS) condition. The attacker would require valid user credentials to perform this
    attack. This vulnerability is due to a lack of proper validation of SCP and SFTP CLI input parameters. An
    attacker could exploit this vulnerability by authenticating to the device and issuing SCP or SFTP CLI
    commands with specific parameters. A successful exploit could allow the attacker to impact the
    functionality of the device, which could lead to a DoS condition. The device may need to be manually
    rebooted to recover. Note: This vulnerability is exploitable only when a local user invokes SCP or SFTP
    commands at the Cisco IOS XR CLI. A local user with administrative privileges could exploit this
    vulnerability remotely. (CVE-2024-20262)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-scp-dos-kb6sUUHw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8466eda9");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75299
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3206828a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf11720");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf11720");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20262");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwf11720'
);

var vuln_ranges = [
  {'min_ver': '0', 'fix_ver': '7.11.1'},
  {'min_ver': '24.1', 'fix_ver': '24.1.1'}
];

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
