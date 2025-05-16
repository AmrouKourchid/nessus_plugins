#TRUSTED 00c970d21949a84405d46d9935ee940ff295d8b5fb1d75adbbfb2a84f48bbd70f004c23897b43414f870cec6d687fd10542b7c7d34b1db7c8b8a528092a4aeade14fcaca2f4a4fde54354d473e75c4590c03c54aec60aaae400ba091a0672170f40b0bd7a79c16022e2b73906321e8246052e4d28d97e911eb18f7878d376cc6e79fc50ddda1c8758e5fce6789fe787f159d894d342b39dcdcf0af5347d563ee662d28671ffbb2d8267bc75362e7fbbed4d65a3ebd064688b35aaa8c960df3f0dbb1155ff8027e2ae7e89ae0412496e9625d5291fd3f161b486b72a8e3f37135949d3af4f7de621b86c87f819d82d106227c4bf1033a53dbdad124703e473d816ec6906ba567621c10aea207eac4ebfb08c48dba8d61dbf789ebed7a542bfd5b1a2f3bdd268c13fc51bb8bb53a426d110126ca7f04f5212e23b733bdd20b4840ce58baf752fd8b4dd4457b70a6f706a488a946fdee04947ebb68a638e311fbf3843a688642ad33fdb742b6955a20472a5f3446e7dea8197d00f124d61089eb2635ee47473542bc81ad7ded414fd6ba3eb6489c9952f4afb999a277b1e08fc09bdccd6ebaca57d4cdcd470386f23f5742cdcff8987c9ac85a45ffb49659ff5429b2d0af67db90b70ada641b815edb143a1cc531eecc81d66131c010224f18fa448962db75e4f60f122055a6101213f4e31450226a7d302e6f14d3eb959dc63609
#TRUST-RSA-SHA256 848b9de085aa599c9d80b1457d677c502c9dadea6994a19231f73dc2f20d2f24276c374b0b8fb257bee518d0652f86e8ecd4e33398165fb4b632067dcd6fd8979aa57e4c4311ca53177a65b548680adc6051631e9b3d05e9c5c82c1607863c80f52bc6172932925311f262996465a8492bca41342c54a9d6570c6c121689a2919df250a11ec5c7ea7b27772aa596d8b6033eb0b96ae51861486a213b5a48f671396184086780a43b502c8ce88b356776cb6239a6bf5b9b874b4d6b5b21e3d623560f46f520b0f5b7174af6dde66ddfef89bc1053fa600decb253322e1426d5fa6f0a33b67db48e7df11bd3b6d3520a8dc353993a8dbc9d369984aff0e5f5882ec54190032edbd4e238353584e5471cc60a2f1252bbff6f7fe3b077f529703900e3f6f78a0de028a73f80e96190e1d66034382ebbde755566abacc8a3d9ee9b858089524e883c933b96264daef5c58c231922b4d9c85f5a6f323b67800bbf8f09b059b631e64ad0627805a29d0e5608fe70b6ff88552a75c536bf9d8956dacdb163248ceb960508b6010116f50f6d54a71c769b9d26c9d00bbdc892b6d3e1b317a534e30651242c1a025116a7f1339609d4ca34c846eeae63323d331ad5357ecd1519ef81266e8e4c19dcadd2794adee44ba848c62f55b8ca9685d3fef7b3d80a4ebda8a744b99d2167e0928467f67bfaaf78184bd7c30bc254e57ae31c290232
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193334);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id("CVE-2024-20265");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf62026");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ap-secureboot-bypass-zT5vJkSD");

  script_name(english:"Cisco Access Point Software Secure Boot Bypass (cisco-sa-ap-secureboot-bypass-zT5vJkSD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Access Point Software Secure Boot Bypass is affected by a vulnerability.

  - A vulnerability in the boot process of Cisco Access Point (AP) Software could allow an unauthenticated,
    physical attacker to bypass the Cisco Secure Boot functionality and load a software image that has been
    tampered with on an affected device. This vulnerability exists because unnecessary commands are available
    during boot time at the physical console. An attacker could exploit this vulnerability by interrupting the
    boot process and executing specific commands to bypass the Cisco Secure Boot validation checks and load an
    image that has been tampered with. This image would have been previously downloaded onto the targeted
    device. A successful exploit could allow the attacker to load the image once. The Cisco Secure Boot
    functionality is not permanently compromised. (CVE-2024-20265)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ap-secureboot-bypass-zT5vJkSD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f22cdd0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf62026");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf62026");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20265");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(501);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9105AX|9115|9120AX|9124AX|9130AX|9136")
    audit(AUDIT_HOST_NOT, 'affected');

var vuln_ranges = [
  {'min_ver': '0.0','fix_ver': '17.3.8'},
  {'min_ver': '17.4','fix_ver': '17.6.6'},
  {'min_ver': '17.7', 'fix_ver': '17.9.4'},
  {'min_ver': '17.10', 'fix_ver': '17.12'}
];    

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwf62026',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
