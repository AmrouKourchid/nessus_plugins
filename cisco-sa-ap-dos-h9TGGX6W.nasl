#TRUSTED 3ba12352c62b6281e26954f97bbf2bf96c8d28a028cae70768c582b3dce4ab5280a4d51fc501be7274016626f63fd26e267359e52b362580eeb054d76114fac0fb47d1da2a9071f53bc7f2ecff39c8aeb542d8dc4c65e1314cd4dcbe9c30c3ee2725b25a022b366ef54100a4efce0b7d97480cbba6e5794188ca5f61b513507fddb1671a2cb99d3f07d74686251fd9d50e88b8c05a10884a3b48fbac84aa5301250653deeb1e3e5b4cd0819701ad5f3aa02407967e6145a5221aa4c32a37d25b7254a37fed2d1bccc662ca541393788c2d2dae48dea8c3f3401ffb16caecf3904e72807cfa130194c352766a752cdcd8b548370a0a70ad34897a51c259169e77e255fe01e42e7b7f4526ceb33a6328128d3c76d77b5ce602b65428afec707aa94fb337d225542779edbfd6b739aaeef1d38cc261940df5a8fd4697f28e7935d11bbf149df72ea0935849fc04b8a2560b8df98e2d1b539e06ba741c8985644106cc55cd003b1f15c8abc2c0a29931f48956144b7f9f7e8347dfb4430a9722ebef018efa1a788879f9fe8de15195f2322e130005873335ed0e6b16304d676dcb9bbd8752d49d1a608d2d76964746fc082484806a60b6537f611daefa545e0aa86295f02aa48cfda1c40bf21f26ac1103a7237a231262b025297ec8ab0a0f38b79c894a52521001b4d6eb6dbb15fcea0e5fdd92971aebfb1aaf65a04c8997932c7b
#TRUST-RSA-SHA256 6ad01bced390ae892b53c9eb87f5dba253930993e150e76f500f726b9bee29161415f9bbe31e97c389c5d851ce85c8fa0d5e9c2654d4534a33241cd4d7ae43048f86d3caa986a4d4e7369fc4227e9c6051ae2de72e2f8a1a162216a10788dd8bb2773d98ca3c6f42aa80381ab61cfb0c70a44af5db015e44c8fad17926df28727ad48854b323a416a6dceca5774c3bc8e3ad8f46f570f14deecf33cdd7b3a34244a88789940aa0760b8d3230adbc513993f2cd092ae46f4df5df90e54cc2d398d4262a203b7442df440093f3fa406b19410f152d5ac354e2df51f2d61271726cb7758e22083ed5b3e36c05b14455c5e4d0c7bba33d075505500bc64263f17ed3be9a11f7520ba12655029a18d2cc495d7bd5b0a1b1d75b56c635d561a2919421b00c4ebb9e334cfabd5af4f607c6f3a330ce07fed65ded37fe54096014acd7e1e5135aebee4e8d48fdb28f5e8961db524b46bc4287a0ce9149bf2ae8f97ee9061f5996aae5205764d9567f0557b6cec93b6624c8498580ad73198aca08a56351856c5391d1bb1a6fe7f181ca5ad119d73e3ff31470146ae03d15cc42f3965640bdfad88069b9c9eca5765b22eaf9c8f7d791144d363ea1ef88dce4fc358e8d187bc0f5c19fcfc26291611d330485c51bebb718ddb5938ce69a0efff9b604095bf133888f02ee05cc8a3dda673516244340b91eb1b8b01621b76f83b1d5e4c836
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192919);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/05");

  script_cve_id("CVE-2024-20271");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh00028");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ap-dos-h9TGGX6W");
  script_xref(name:"IAVA", value:"2024-A-0193");

  script_name(english:"Cisco Access Points Managed from WLC DoS (cisco-sa-ap-dos-h9TGGX6W)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco access points managed by this Cisco Wireless LAN Controller are affected
by a denial of service vulnerability. Due to insufficient input validation of certain IPv4 packets, an
unauthenticated, remote attacker can causing attached access points to reload unexpectedly.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ap-dos-h9TGGX6W
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4c9a434");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh00028");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh00028");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20271");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:access_points");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['vuln_aps']
];


var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '8.10.190.0'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwh00028',
  'cmds'          , make_list('show ap summary')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_ranges:vuln_ranges
);
