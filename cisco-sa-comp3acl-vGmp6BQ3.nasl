#TRUSTED 7b79092ab5d2487eff14dbffefe7c6e37905a95343b4d32fce5584ab164e88f5b35b78b4c761123a9d1f3589e07ddaee054b25c801a7909486a70ad8d411682eba1a4fa10e2cee00677f46449e0103b718f5065819d1f96052661fee3f8df31e0937711778731c6f64d1eebd3ebbd4eedeba001371728bd29d51a4d941a0991572528c060afff58f0492e8e95fc0b878f77dfdcb06a2d9aaa4c15f2a518fd80b122ad67e435fc8b8da38629ec6d0bb626dea8ccc5091982881feb25e0ff4501dc71a13acc21728d3d2929232e6fcf306db7f176acbe6a8f8b40038957e0fb9a48b9c9d860884273d5b7793f2c80473ffbc983a92750ddacaaf7bcd13727333128ee90f532666e760c6304e99e5971140fe1390d552ab4f36bfea91bd75d230816aa18b8b9c782cad5ce3e6bc65d96da608822176b071981637fdf6823fc67df3a3902e72fc2fdd38f7df15aff3b19355b003a12bf41e7d90cd88f3f5c05e6e3907a7c0bc6d22f4f5fe3ebf0b5690344889b30ae3857a666a60bb5d44211148bdd8369fe074983d64374f44f9bca7d0a63a31f23b0762929bf1a443597bfe83c24f2063e95bbaa11ab911003b73425cc9f23a17db848c9cf8b8ed073df5cdccdb1b8b76ad1816b0b95d75576d8740f7e7ff669b84f834c9c4d754b074a0af19729a2953911a21b918ae4aadd70004e15569f5ec56b7d79c46d0a16fc0b13abea6
#TRUST-RSA-SHA256 57469f3dfc8520c4124c565e9c665219437530f355bed964d169e70a0f68ac4550d5f0e8e0a9a831e33bd2b090442fa9f41ebe8d34176dbc15938ce73d8109a4f1562ea9468223e4027ed544e19e5d162e9f00f44f58263c2ef43abefc2ebfc9cc8f93944a16b0199e2b175769aa357ed5e4a9b2fc418293d5831d164f6581cffb0d587b00625300a205da34f48fd58e2d4936584bc9d976f3c5359b271b2c86e0d97b6a576af41cf3e79da88dedf704da214bf635d5a0ae117843dcb12532fe0c6e1fad4ce492ade8612f0051df4876e65fe1eed7abe6bd85a65c8a8ea8131d78bddb4694451fe9a74c349d2eff23b89ca10c0296b9a39fcae884b700f14ada73c1bf61208e5ff65bdb5e6431ec7583330de94415858d6d7f40a9aa1d6cb0a24582315df129357652da7fd30035b3b8ecda36917b045ae2e20bbba318ec8256fa673563678a498c31eb06fbbd8b9e5e71ac1324d6096399f4d093660936f41d2656144751fd3a059d4205c3fa18e90193b4060c680e32b15cdc596381c1f0373febbee0a4f053284f6de69b1b8084cb2b1b78698a353e32471e04154f09a239d3b4d0a0688075484da433cad3d79bd80dd043d38f9257f45be6163524207b341d925e1ec6582b1ed05cac1fdc7f3c555ac332c9d29930438d831c44f67a5b9cc561e3e398d0f021c10a2f711e11c10d7fb9b1b45876905d73c563444cd59f59
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181471);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2023-20190");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe08950");
  script_xref(name:"CISCO-SA", value:"cisco-sa-comp3acl-vGmp6BQ3");
  script_xref(name:"IAVA", value:"2023-A-0487");

  script_name(english:"Cisco IOS XR Software Compression ACL Bypass (cisco-sa-comp3acl-vGmp6BQ3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by an ACL bypass vulnerability. An unauthenticated,
remote attacker can exploit this, to access trusted networks that the device might be protecting.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-comp3acl-vGmp6BQ3#fs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14c152e5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe08950");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe08950");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20190");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var vuln_ranges = [
  {'min_ver' : '0',   'fix_ver' : '7.3.5'},
  {'min_ver' : '7.4', 'fix_ver' : '7.5.4'},
  {'min_ver' : '7.6', 'fix_ver' : '7.8.2'},
  {'min_ver' : '7.9', 'fix_ver' : '7.9.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['acl_compress_level23']
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe08950'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
