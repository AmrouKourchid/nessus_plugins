#TRUSTED 1ffcc25ca6df87c9075af337bec1d4fd658ce93a9b2a4664f9e5b72c2d86d0cd27382227935e1deb76168ba40dd870b125ba499bfb7c29cc67c829de7505a9cf15f96f7120f6d656b241569175692adf076b79dad660bb599286f5ed1295d7669f2f7dc29f4e61c9ac397197332be8ae90f921bc81b65a47b2349c4aff09d69f94842633f5d78f3c247129e0ba3203fb3e845724204b210cc9798086831dc28b6884094757231ea7821a21e341369d384ade52a4732135dec8dbbc8a7c3d8fd3ba54a19219150360096ac9ae8d34a205d58ff628f105390d8012394dc659473f5d8446e318d6173ee0aeec26133bad71d51ec5291c5ba94ca127abbf6691e0f0f7bc27438da9bbfaba141fef23fb3c7c7f2901b39f276aab79edbe2749b7fe208395fe989eb517b49fb91d443cfa80f8fdd9887a46a6309d489ea2c815db1e40b817c139c1e6a1e71cdad3fab66b06a86994bf57344ab9e8c6c00baced2ce414443277f518986c6e56a1d7a35171eb7f443026113b029ad8ff35c16d1328e815b3fef533710dc4ef30610351184dfdbc4cf544f59764e97063f8bba4f73ec73ebc6b69d8afc3471a919f3b1246a150a70d1efa8b14cc5c0592d2b78ef410eb3c66de0a57c2d851f4e57b928a12728afe647d72cbf7cd0f941c4e88010d638a409016ae04e375cc499b71c753e16e69302bafb65d7a1be8c432603a729c878026
#TRUST-RSA-SHA256 82b8ac66c219cd4d0035c95f3b66f6d0422dc10619232af86b24f6a06998837d87cade9a5db661fe53a8aec461ee17329529a19d45d250ba89a62d242e27ac1e928140130b3d3171e301a735cb6393d43d377d3e0ea8a0bda8d1b4cfcb2bbc66d8dcbb38f30e52e70d14728d4f5976526205a6df9e47dbb66e0d98cd564ba9310e709da34f36d8b30f42198a4c69e26d2a64a8db1bc4baeea74398a9c6a10f503f2e673a2c856dcf72dd9a3903368c10173f9f6c02c2af1477f708258ebd64dc51011d298b2263cfb50edd3b86dbe391ba7698606f870083cb26d2154ca713b10d5a9601ac0601caa985f6bb9d19dcf0de0ab54da51d25fd3b0536fff5b04ca870ae92c54ee55a127511011d5b3db019d78f69f835216dadad5f591f95dedfd0108a77c3dd2d12f228290f10011a990348936b3bda2fc2be4172417ce01818a34ea4028b0500b0f9ab5d7b28075eecdd4d546bba3e5adfb0ef2625e9dee4803cd5fbb66512e9cc64d88f91bc1961f7032594f2399beea5074e85dfdeb13188a4d8a774bd0a68d6e39156d29ba35a51c9f57a17a29c983b2575fe3ea87b0e8836a3dc77dd77f6990dcdfae4622731b2783171be022367ae8d59d8455175deb969edf1300886409584f548561da552885300ece58c74e50b8430b7b09749e38a3ca999a3c1a163ce78beaad44729f317770b5128a1067f0f7f3d5589752719dd62
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140222);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3315");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt10151");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28138");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort_filepolbypass-m4X5DgOP");

  script_name(english:"Multiple Cisco Products Snort HTTP Detection Engine File Policy Bypass (cisco-sa-snort_filepolbypass-m4X5DgOP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by vulnerability in the Snort 
detection engine. The vulnerability is due to errors in how the Snort detection engine handles specific HTTP responses.
An unauthenticated, remote attacker can exploit this vulnerability by sending crafted HTTP packets that would flow 
through an affected system. A successful exploit could allow the attacker to bypass the configured file policies and 
deliver a malicious payload to the protected network.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort_filepolbypass-m4X5DgOP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bff42201");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt10151");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28138");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt10151");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(668, 693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

vuln_ranges = [
  {'min_ver' : '0.0.0',  'fix_ver': '99999'}
];

var model_check = tolower(product_info['model']);

#Model checking for IOS XE SDWAN model only
if(model_check  !~ "^[aci]sr[14][0-9]{3}v?")
  audit(AUDIT_HOST_NOT, 'affected');

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt10151/CSCvt28138',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

