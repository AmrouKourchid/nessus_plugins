#TRUSTED 13b5830668952eb5d26f32b1be37adefd223d9e31bba398ffefe7bafc0078171a5fb094d6a248e2b6e0638e0da9bf775f2b49dba2b29e8c6f8d4166941505e96501262a2d5fde04c24bce4c2fd365894ab7ec459d6c5a8a14815690060f0d321a6cc04dbaece383c3109fe02cba24f0ba689c219f5b4026543357f5f30c8ae905441db7fc54ec523b07daea0aab124303c850ad052c38998755910d6f888b7098d983639f4dcc0ce838cee81962e1fd825dc366f9cf8679c51ffcf4541d176e26ac24a077513261afb042b8a46fda28d381ed62c53d75808894eecd75d7284d10391836aa526cfd11b45601f3e1b6cde6313093e388da7ed989008372becfc605f9f136f920c23f1fd0d82ba4e66e785b10a189f991078852527dbb8d4ec3f7446aa15b28bb4a1bb9851ca80e98144f2b9e24b13fa582149619a7144688f0f10c07baab6987956e4bd878ed67930604bbd1c167ec44c8729542dd7b29d917ceadfb0138216cb588dce713593b3ed993653c828b84fe3fc8a0d5265d1f5242972835f06a5f40c9189cd06214bbc746bdeb2978ac9bbc860dd78a40a8b70ed7387c122c7e0ff05c04d545a7e9a1ef72a1a66e13ec22dc2284b8f0ee5b75e88e46d9b69e030ebc1c7d580979e3020f550ae0f4a4a6e4fb0ef0e94db0dc6f405d52910a39314669f22fa26781c060ef9070196d9b596172ca093ae340c034ec257ad
#TRUST-RSA-SHA256 3952a0fa1e2e863c84bc2b7afa9d2db27e5861b3918b4b485304c7d2962d449b47e858dfa368fe2df7e826d724233aad7cef69c47e9e6f673411cf0a17e3ca10289bd7828ac73b5509857aed472c73d645186d64d96587788d42a0e8701abb995c4757612dc157ed1e762b3d06cca17c8b022c065c1efbf417967d9b558cd262f389e93d4178882be3dca445f6a6568127c876e71319126712986adf60786afdbee5914a458753af082f9ecfa897fce48d6d67165bb2d82206b6f3b17111e926f1a17d79a3b0a88fcc6cdb1b187d9f3a08d38c91af1eba73b2972e55d20357632855a294d9ebf48044344c58bab95382977c9808ba390baefe8f378bad6f3257293e7f8b2e1d2aa172c2eebd1c39bbd9eee213a8bddc9ec9c99ba0e3cc542de4b0d602798fa05be96767c7cee425da702d709cc723f6a1c79b1abfd41fe11fe8cd7183011d92464a2a3ca50ba0807162ada7e00517cf1cbce3388f9f9ee7fb057e0e3661ad06f7cf81aed71c3ead06bd6d3a0cae831283e0cfda4b6498dc7d1d00e11e420fc5649de1e079a7dbbc4b67d392c373afe27ac6b8ada069b66d87a96f1811f52d840ebe0250f0bcc3eed75ebd9b62c6d10e7d9ef2a49f6cc45a1b584cb83a445cf1a789fa07b2191850e90de2f1ba971cdac21b9a4c567b939cb96db486e14de9cf3b2012ef719dfce63699d7cc5a93ab8125884c28186f2c4660c1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138440);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2019-1797");
  script_bugtraq_id(107998);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj06910");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-wlc-csrf");

  script_name(english:"Cisco Wireless LAN Controller Software Cross-Site Request Forgery (cisco-sa-20190417-wlc-csrf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a Cross-site request forgery (XSRF) vulnerability
 exists in Cisco Wireless LAN Controller due to insufficient XSRF protections for the web-based 
 management interface. An unauthenticated, remote attacker can exploit this, by convincing a user 
 to click a specially crafted URL, to perform arbitrary actions on the device with the privileges 
 of the user.
 
the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-wlc-csrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1483a710");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj06910");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj06910");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1797");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '8.3.150.0'},
  {'min_ver' : '8.4', 'fix_ver' : '8.5.135.0'},
  {'min_ver' : '8.6', 'fix_ver' : '8.8.100.0'}
];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj06910',
  'xsrf' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
