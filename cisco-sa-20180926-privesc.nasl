#TRUSTED 983027d197dc261a93d8a6b50b43292e310f739483f20643de74744dab06086b4e17c2a348f7988358c6798cedec3b5282433ee7752d87665b2f188f3f357fa481feb7840b7a326c6d49981e3239b894678073196694c2520661746942ec18e9a1b7aef8486aeea8ea2f4c02b108ce58f3a786de20352126fe1e15dbe437ca75db63faa43cc9941e8bc3ebe254a2332c50dd5bf277b4493769ac5deedf55238c554f4a7bdb5c2f4106da0cc1ab10fb6267805b9b5363e8c8f63604b3bfbbf80b24f35a5f87e098a6840d208804f9a86840a00f4cac01749ce2357221568e14a2e84a5b71656ca42bff4e65a3f5e68d989e22d48cd2ed44d13c42a26b5f3c5c45712b3e865d3ebdf31ad601699d6e553c1289fa3f02c93bf20711d5f93c2613d407dfa2cb2c0c18671414bf8b8d5978261973ab516861919afbc99ff2d1a1e9c6eb5ba679e366ba0eb24d0fdbfd472b75b3354b2a17767c35ff026366877790415793a98182823fd8bc140d0f328f7275be82338e2c1ee66eb8213e129463da2e9f0162f4897c071d0d494c83a0f4654c6c3652a6faf91501629f9546d4cc599ef2bd334a9863a2f92ae5eff2a9452e1bd30d3cd18dc1ba241a2576a488acfd9f4486e8c1f28d7952c1e90994a6d19b7d7dd9852176dcb9fed2a817499031ea0e080af5bc417b11690fa64dd8ee85f8e26c2e494c0bfef3ef4393b8b523a599db
#TRUST-RSA-SHA256 196fadb87e52970e040bf3060c51a3625e94d4f4b78734b719816c82a4debef275a07a84163e22cec416a714f61ddc0519eef6f373a9eaaeb4a151e506ff42c9bd0726288a5bf1c12fca17eb6ba15199864dcfbdca82fbf08474f750b4e6c1d9e7d975dfacc815c384e333cd1959938541d4608cf234d929779299abda771abc6b7b878eca28ee6cfc25125a6db2153599e35750dd59bb8902d4bb4db06ded8aafaf898ee48cdbc37c599f373dc3066991b1465d3af2dc126ddc98c10a82a62cecc86e6c1560c075d0e9fbbe83341d53e71c81222f5a6edb2ed32fd829807de0df44a8e3e6cbbcc7ddfc288672a8f9bd2cfd741bcca6c1aec51d099108bf852cc9e045254159e3a0823032f7f131ce7d99d2154302ee24f3081c17e6072d1315db52ca79b2a07d8e98809f9ab3d7f9f40dde20136fa0b6a7dbe85449fa5c56a2f4f6e4dbff75d50729c80685c2f14df4a1144450f2086ad245a0f67a56661436a6842895d39fb20e8443abb7ea5c147a795e342584b1c290404a291c7a69a1f5c5d80dd9f488819f9f2fdb934b07ca120daff6855c3f8fe52ea5151d87bdd437ef4f4313879cdcb360895caf4e359508cc323c16dbcd333a9b8f0d07e0f5171667a82297de20fe2a98c23ed4a292bee311a6dfc3f44f96958a4529a95e28a496d38b6441eba44ddf0b6788aff652103045ae53810cfa78b754f72bb21ddfd520
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132044);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-15368");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw45594");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-privesc");
  script_xref(name:"IAVA", value:"2019-A-0264");

  script_name(english:"Cisco IOS XE Software Privileged EXEC Mode Root Shell Access (cisco-sa-20180926-privesc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the CLI parser due to
the affected software improperly sanitizing command arguments to prevent modifications to the underlying Linux
file system on a device. An authenticated, local attacker who has privileged EXEC mode (privilege level 15) access can
exploit this by executing CLI commands that contain crafted arguments in order to gain access to the underlying Linux
shell of the affected device and execute arbitrary commands with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-privesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06dfb1b7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw45594");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuw45594.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15368");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0); 
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.7.1aS',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.2aS',
  '3.13.0aS',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.17.0S'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuw45594'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
