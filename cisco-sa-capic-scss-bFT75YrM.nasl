#TRUSTED 1dac9ce787907dc4de64b18ed33ffd8e1c625b71a41dc1bc5311cd6988592d46310c94572a2867646bf04bd63c44905db73a79248261e0080f8098740bebbf3b01364ec3c0c79fcf034b5552c56350a51719dfecf2c12753b0968f933d9ebdcdf30ca6ec0466200879c4c2fc89f26c276b093673c102557db6609cdba9488a2282bc26bcec1a80f954d2aad8dc7a2d3af5f8b3d7579540187d5e263eebd2b64e756ef6bc83d4a0058154d79214dd043a417436b71b345ee24c9157a1406de3512b79b207b56edd771b8c0b5a296971c4a7d922b87156bc07815d94d01b4d625e1bbe889c2f13e0aa09286972940e7402c1a3629c11e7adb40de54adfe6a6c1ba436bef829ea0f76ca586140bb36e5370af1b4dfda2ca0c19d570700a6068366b8ec3ded3ecf0ab2330c265429efacdcbb6c5be2b7f9f562e910cab36bb900126bdb9d626275daa7c7048d8d0752747f279e3d953162297f9a71b068b39bd560657cc612500b5586466080608b9a61b3d9c22b20fbdbc4667b8f040737302c30940cb6fb576ed80ad935ad41299a23e16bd9cc752e17125c8ecdbfb004f96b07a32e3c9a4b390a21b08de6a2d77d44f0049f8dcb7d67a4221d95087dac72df4ec6ba5f72664767f0daae140508148829090f26ea3e49b3f238d8624159487a4596f073efd7598cb3afb3c4c192fffc776a84b59af7a5b186c8fe5bb40c71ac77d
#TRUST-RSA-SHA256 4e25aecb8a9798668313ada250d5acd23037fcb9d743d90e09ee110c4775ad591239eed23f1635d01503e7ff11cb5d778e094b367a3bb4f5fdbcfacc26eb80e198fcb5de9724edd149ef872386409bc91df33de538fb3c36e2e6837ae3f330e6bc535aed3e5f22809123e7a797f91fb2a88e6c100e358f17c8f8b232f3d1880de76c3eb82bc5b34e21d8f7cd067b29fdca1478cadb461fc5756a8742a88ab937447aef1f502d0508e141004c0160c3534cd31a60a80ad3901033e57b0ed730993a3ea8c985c780168102c573e8ab9bf8eba93e5faca7e561738a2c82a8a478c58a5edd34a709e4868bd1c9cb5f106e69813912d78d178b0353cd93cc8ad60532944940e27d827ed80b4fe6b33ab758c5b93f1402d1797907ba93188776efb951676229954edfe52040386743458099c30c17665811fd88da2894875663c075fa5d3f3f4045740c490d9b06dc9a02b2caa2a2c213f093d88a3139c0286f7f14a52240da4e4f6ab451b20f3c7db7e1d0f8f4605fdba0baee0b7e4f04476fff83a7954f869db4f76cbc538e2b5a630e53c2cedeb6f6395b59c2a6c3a119e77e220d3bff05565646da07bce8d4edf69f1f5fcb4beec27baf292141d6c0fe1b2d2285ed805b2d3807e49002627378f0236577996d877bb249aae2403388ab04ccd9cd67d1c74e2d1e9717c70d08fec36b767310d020cf00dbb49d83daedd1e8e5b9be
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152961);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2021-1582");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy64858");
  script_xref(name:"CISCO-SA", value:"cisco-sa-capic-scss-bFT75YrM");
  script_xref(name:"IAVA", value:"2021-A-0403-S");

  script_name(english:"Cisco Application Policy Infrastructure Controller Stored XSS (cisco-sa-capic-scss-bFT75YrM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller is affected by a stored 
cross-site scripting (XSS) vulnerability in its Web UI component due to improper validation of user-supplied input 
before returning it to users. An authenticated, remote attacker can exploit this, by convincing a user to click a 
specially crafted URL, to execute arbitrary script code in a user's browser session. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-capic-scss-bFT75YrM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9366d73e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy64858");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy64858");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1582");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}
include('ccf.inc');
include('http.inc');

var port = get_http_port(default:443); 
var product_info = cisco::get_product_info(name:'Cisco APIC Software', port:port);

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '3.2(10f)'},
  {'min_ver': '4.0', 'fix_ver': '4.2(7l)'},
  {'min_ver': '5.0', 'fix_ver': '5.2(2f)'}
];

var reporting = make_array(
  'port'     , port,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy64858',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
