#TRUSTED 87a80367cf8ff68c9abc4676826ac5019fda5852cb067ba2d39d33a3d642763b841995b3a688188cffa69e12fefa6b22aa22c7db1d61af31ba62cc8a651c81bd75f3e998b996c0a495fe647501437adb67d78dad75803cf453e3221aa80d49a27a422bf56a14b6374733b2943740ae50a28c8000a9208dab08d2dba12ee409f949ee67a7b4e31f8dc109eda6c947acd1948fa3f10a9f35d608ae45a59428db8b3ab4f0e091b1037f222a65b4ef28656a9df34f46de70c52f4b84956a30f6cdd7ff29ce6df2e81c5e895ed99b12e7ac7a401a295c8086326e184b11b47ee7a452e95f87082d9a4686ca753f31d624c813c6ba3231d28fb901d47bc8c9e118a97c7617985bd221f42f05c89f581e8103c33e3fe9c57efa28d7125d82684aaea76d766df70d23a45377afaa89473b85cb7fd6592199b45bc0b59354bf653b10ce5ced40a5283df9e1ab45a4e06266d828ac2e01745eac8d64a63fe9124af78d9ded216e233d8bb8bca73563b253998ebd8337dd3ffd5eb3101d2734c014094d0aab6468398609d1c11cfa5a2fa8f4c34e207bb25ec48b8131932e3257210561d3a3b0906fc0d1d6892f422705d330185771a3cae1c72b78e89bbcdae920666c0d0532d483dfd7d681fc620d5a1770f4acd1cfc0dfd3065da41e60716e7bb675aecae8ebe4a3f95d9ee1ec051d84b6d5f2503632ddc30268e8a292f9578cda6d334c
#TRUST-RSA-SHA256 9db6462b36bb6bf769f991b4f291787d0870550ead77f710f53026cecc2be67093842b4f8255d11cbd6d5a43b39be3c350d6eb709b44c8bbd3d899c6a886e699ef176544e35988986b1c7ff4f1b083d51b17a14c40666260d53b7ec93fc121cd94b96050afaa0f0a84bd3ac402098cf7211f6d06cde7a275c41ff5e048e4741f8c7af0499b52bdb5d9d1ee878fe126e34a81f8a77549b03973f490fdf08e772494612b092c048c757b1196bef9e91dabad0d5f4e5da0382d0768e224000028df8398d61f15318a05c423066553614d3d6dbe82737feb71653d5ee8b03694fd2ae64d02ea4b776a41e92b0bef867bf95c7eb4176c4ef7109d7b380c5ce01bfdcd305d5bfbb0c51b9bd932617462c0c9e4cc3e208b5c9e70ddf5ce9465f75f525715bf6b5504ee890881866975245bb29c789008dd5d658535f51a1d01c2ad29a8eaed5a7a3f4072d2194a055b4958620b4f57cf27af2f363beb2632a6252e45a32864e9d86cb179b315bb885b7932f0d777d489d68c0b5403b666a3c804de4b8dd4acd3f55c6da84ea01fb81faaaab7e5fffdd3b7ee8facdaac23c0ce55d2d385d2e0c0788ec1844134d73a27d499542e86bc05da24f54b0835913631d655d23583745ff27da3f90bda0ff21d705e62e18c0bfb75df0cb4f2aee25fa33a708f704e8e3b463e63e33984b2c3e643e1371397f26fc353579fd04e41e67c913b2ed2
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207787);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-20414");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi59624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi59625");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-webui-HfwnRgk");
  script_xref(name:"IAVA", value:"2024-A-0592");

  script_name(english:"Cisco IOS Software Web UI XSRF (cisco-sa-ios-webui-HfwnRgk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a vulnerability.

  - A vulnerability in the web UI feature of Cisco IOS Software and Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack on an affected
    system through the web UI. This vulnerability is due to incorrectly accepting configuration changes
    through the HTTP GET method. An attacker could exploit this vulnerability by persuading a currently
    authenticated administrator to follow a crafted link. A successful exploit could allow the attacker to
    change the configuration of the affected device. (CVE-2024-20414)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-webui-HfwnRgk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15ee0ec4");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75169
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0341eea");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi59624");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi59625");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwi59624, CSCwi59625");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20414");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS');

var version_list=make_list(
  '15.1(3)SVR1',
  '15.1(3)SVR2',
  '15.1(3)SVR3',
  '15.1(3)SVR10',
  '15.1(3)SVS',
  '15.1(3)SVS1',
  '15.1(3)SVT1',
  '15.1(3)SVT2',
  '15.1(3)SVT3',
  '15.1(3)SVT4',
  '15.1(3)SVU1',
  '15.1(3)SVU2',
  '15.1(3)SVU10',
  '15.1(3)SVU11',
  '15.1(3)SVU20',
  '15.1(3)SVU21',
  '15.1(3)SVV1',
  '15.1(3)SVV2',
  '15.1(3)SVV3',
  '15.1(3)SVV4',
  '15.1(3)SVW',
  '15.1(3)SVW1',
  '15.1(3)SVX',
  '15.1(3)SVX1',
  '15.2(6)E2',
  '15.2(6)E2a',
  '15.2(6)E2b',
  '15.2(6)E3',
  '15.2(6)EB',
  '15.2(7)E',
  '15.2(7)E0a',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.2(7)E1',
  '15.2(7)E1a',
  '15.2(7)E2',
  '15.2(7)E2a',
  '15.2(7)E2b',
  '15.2(7)E3',
  '15.2(7)E3k',
  '15.2(7)E4',
  '15.2(7)E5',
  '15.2(7)E6',
  '15.2(7)E7',
  '15.2(7)E8',
  '15.2(7)E9',
  '15.2(7)E10',
  '15.2(7a)E0b',
  '15.2(7b)E0b',
  '15.2(8)E',
  '15.2(8)E1',
  '15.2(8)E2',
  '15.2(8)E3',
  '15.2(8)E4',
  '15.2(8)E5'
);

var workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
var workaround_params = {'no_active_sessions' : 1};

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'flags'   , {'xsrf':TRUE},
  'bug_id'  , 'CSCwi59624, CSCwi59625',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
