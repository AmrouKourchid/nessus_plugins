#TRUSTED 65ae45a0fa45c45efbd1cde8201efc0a04d3b9bac85078725e0d0cbd2f289822a15bb33245f127ee9afd3d4cee3addef0244bea3f2476e4e1f4d1fd3c30500a38d7c3e591d9560fee19eec4d6796335dd184c6b975a5a3acc3da327cd653ec2de44a28696c57855f4a2f7f3f4e5753bd240169c86bd8e996417937331e442b4b6e31afbf1b597d97de2d603a886d36cd51898056de5541cab8ebeefb9715993885a224317d1eb44485fbbb923468d6d2ff0250c1e234cc043988e40d7e3de0982c30de3b085517b56e03d6b44f82782a04f61957066dcb8d2ca297b0d0b38ff16ff8720c3f145165d7125739db28e6611798dcf18d1a48499197b7acb5232afaa203f8fa072c9e12bbeaaf0da3a5921863f068695296ca41dd65b72ba114952aad002c5ff7ae6100c8667a1123cee47ea3aebeaecd22a7e191c1ddba6254c0213467760d676d1090294258c6d761951b370dc2c60de8aa502931d9beb0effa387498bf6ad9ff66b5e2349f2a15476d40466053ae19c9c1c262033ed382619abc9f6cfebe9b3613cb29e80fdff818401f9b55e81a97eb9fc40fc1677effe8b2e07c00ae758c092677bbcc5148aa4b5088c47fe23fd24ef4b1a2f115f5163ac277799e1cfd3659e628e79f5b45b597000802c6af739d55015252c81502fd603712c44e6987ac2a01905c50de642ba4894ef2f6ebd1ffd60efea5d6322c548673df
#TRUST-RSA-SHA256 7db1d37f023ac22e09bbd388f23e024cd82b73cedce93f4474f3d0fe715b74566e76f2cd6812841bd6f65c1055c0f5749891f434011e50d653499d9f228a59a3610b2e79b8eb4504507122c98c0d341538095e5c87961115fae71d39d3bfaf7c641d26e4d0a5c5ad5ab8bda0ddaba58c457eccbdd8f0d39b1f1be802041c7c96a05ee73e8c0d6e188df9833d6705512380b178f4b1afaaa136a7a69d84b47c0655a88711514fbbf848dc207ddf31cad5e83ab4a44d35fb3d80d8d29d39bf1678438823bfbbf5c12c1e05cde8dad525e6c78d7da9dc7418f52b6afe6a40f0e383f0b15ce24dac220274feec377f929e3078d2617afb6d85ee000f8277d52881c971c6157469a39c9072a046c2c74d211924d8c7ffae343ced39dd4c427d307559990cc0836a06c8174d39609b7eb3758e5771b04f32306777cd32e2bea6caca997519a40596f30edcb3b4f643760dff58e750b65af80360b72e768f53926f8278c7b6deaeca8e369ed41dc275e441ba009679f137437f11baa2ef159e12409db84f22d2c08b184cf88f51a4e9551627ffe6d841706b3401ed61683040996529cf0d996436d30c1903d730ec6fb77978bd8180fca59f153f69547e587e5d66d5426c11fef1afb5338d209b64c87e9a50d7495978f20d0e63a9af2a934203f61673d9e6b07eb98c2ea6c32662362d113c4400d615021c4d88800a96f91c4bbf0916
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232289);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/07");

  script_cve_id("CVE-2025-20206");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwn03265");
  script_xref(name:"CISCO-SA", value:"cisco-sa-secure-dll-injection-AOyzEqSg");
  script_xref(name:"IAVA", value:"2025-A-0140");

  script_name(english:"Cisco Secure Client for Windows with Secure Firewall Posture Engine DLL Hijacking (cisco-sa-secure-dll-injection-AOyzEqSg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Client, formerly AnyConnect Secure Mobility Client, is affected by
a vulnerability in the interprocess communication (IPC) channel of Cisco Secure Client for Windows could allow an 
authenticated, local attacker to perform a DLL hijacking attack on an affected device if the Secure Firewall Posture 
Engine, formerly HostScan, is installed on Cisco Secure Client. This vulnerability is due to insufficient validation of 
resources that are loaded by the application at run time. An attacker could exploit this vulnerability by sending a 
crafted IPC message to a specific Cisco Secure Client process. A successful exploit could allow the attacker to execute 
arbitrary code on the affected machine with SYSTEM privileges. To exploit this vulnerability, the attacker must have 
valid user credentials on the Windows system.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-secure-dll-injection-AOyzEqSg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13159453");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwn03265");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwn03265");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20206");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_client");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client', win_local:TRUE);

var constraints = [ {'fixed_version': '5.1.8.105' } ];

# not cheking Secure Firewall Posture Engine, adding paranoid check instead
vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  require_paranoia:TRUE,
  severity:SECURITY_WARNING
);

