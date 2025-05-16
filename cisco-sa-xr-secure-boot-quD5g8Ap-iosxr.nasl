#TRUSTED 2dd09d74bf158f21804918200fb0ee56f00080e6e26b12e01e942ffcb0d4aef6a03c5cb76c2a530f483f6d898149a6c272fec71be0cfeb7437352dcd1747777f438cb778e5b614644e41254b2698070e9fede9006a3ce6bdb45d1290360e0899e47d800026ddf61a982c651d9f018478e5fe79493c94323cd854804eb6221ae3c25842359ca060e53cfaab6b68560b774dffdcb82a39b18d407a08348d941f84b26e6ae85d7d98dd5f5b95d872b4f4dd4658b9295d7db44ce50dbf75358a9d5e641a6552d99a0508c6aa55b86f7a5543f5cc3ffef59e4c49d016904717f8a1c8868d6875a53c0ff156e19bb3b88e43726a76de27b18ac1ca2097ea619a9534a9667ae5ee7660ae56d4d16d4fd4dfff7f9da763fe972c1a6e1e32e88b8605415a329692aaedf8e4e654e1c7dd21d94b862054f17dd44820e0802afe5f250e8e9991c71b8f655f3e66f954f76d3f86bae4331941cf8a5442933307f4b357efc49a186791841a969fbb62d16e0917f4a78fd663f3325e4b46c326a93df6bb0663fb6447061f0079d7bc2fe157a128702ad98488a01c1709d99e4f9d81898e3521e7c6d51efb01ec8e2e79469c82728825216e2db711dfe6e3f96fc7d3ad84194e748777ee4295e006937243a93c2f2e179e17914441bdf250052fd58d8023d1ff0c9f060ccc3b92c8d73f4964ba0345df4c40d4e9b259cb1ecbd844e5c0576dc3a4
#TRUST-RSA-SHA256 82ea46112ee8db099ec1fa542af8b2a15883f93ee5111564ec630e2b1f5e51e418fa6483c9c98d2791f862706e14ad7ec0ace8d61f3ac44e61c05fad2e288d6f2e530c84faa09c27699522d351f3ca47278336bd4fa60b1c8c4875591e111af1bbfbf91c279901230b192a05fa57be6944b936b8836b67eef5a961b25bffba19186a4802244dab85769a8dde831c18681231137ada8eae774f9cef4314d446a54b6f8de1766c14fe08bcea71f2c7296d233aa01850df70a9646059ab519bf8765883c41f73270f0e18eeb1a41c3a936dd94d72120ab5516d14bee8999616b9a7033fc715c67bd3f1d1863c83d78e3f4d5c0c52339e0d8cf03792c4a68c867858a23c9872f6a3dc3d4d82ccf9dd475859f5e62d1c38aead64040ec6e7f315705befa4754c367448557e8d202fc1e8745b9209a7be4e17bcc492dd3564ad1cf9a20fcadbd40c9bea702e2ed5a2d4f7b569fb54ae43042b6fdeb72239daa6e8ae88c4224e929d0b418b63999fd23897595bebc065551756d0c64064993647ea2296d892095fc3fb6b02400c938462dab7a4772bb8d863fa3aa4d3746d5c154da123cc98cae3d0bdf265f3cea91c7274a85c6eeb0e64bd956fb6403d33a4f02374199cff4816047cda552c5426b71516f756582fb0c90421dd91c1fdf516b72c8b30050fd998f1b43b8e3c13929aff004ace1fcaa0d99759eac00b32efa35995a029
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206797);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/09");

  script_cve_id("CVE-2024-20456");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk58609");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xr-secure-boot-quD5g8Ap");

  script_name(english:"Cisco IOS XR Software Secure Boot Bypass (cisco-sa-xr-secure-boot-quD5g8Ap)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the boot process of Cisco IOS XR Software could allow an authenticated, local attacker
    with high privileges to bypass the Cisco Secure Boot functionality and load unverified software on an
    affected device. To exploit this successfully, the attacker must have root-system privileges on the
    affected device. This vulnerability is due to an error in the software build process. An attacker could
    exploit this vulnerability by manipulating the system's configuration options to bypass some of the
    integrity checks that are performed during the booting process. A successful exploit could allow the
    attacker to control the boot configuration, which could enable them to bypass of the requirement to run
    Cisco signed images or alter the security properties of the running system. (CVE-2024-20456)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xr-secure-boot-quD5g8Ap
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a912a4b7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk58609");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk58609");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20456");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(732);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);
# 8000 Series, NCS 540, NCS 5700
if (model !~ "8[0-9]{3}" && model !~ "(?:N|NCS)[\s-]?540" && model !~ "(?:N|NCS)[\s-]?5700" && model !~ "(?:N|NCS)[\s-]?101[04]")
  audit(AUDIT_HOST_NOT, 'an affected model');

# can't check image for 540 and specific models for 5700
if ((model =~ "(?:N|NCS)[\s-]?540" || model =~ "(?:N|NCS)[\s-]?5700") && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN);

var vuln_versions = [
  '24.2.1'
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwk58609'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions
);
