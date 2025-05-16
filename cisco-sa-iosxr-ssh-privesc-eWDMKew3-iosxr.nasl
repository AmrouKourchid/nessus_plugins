#TRUSTED 3146928ab2d4a4c4e6362e65a8fb3e992d5354b385c5593aaaf7b992abb467fd0fa0105512846ecda2df1625979d60daca781e11aea5ff0b149917343ff6869e82402421f30c01707aa6e6306eb767bdc0a0e06660a4e4a2e3ee2ca3eeda26e940aed0186e17a9814f70cfeded4dfd04e97be74be5f752b2a93c18ca80a111cfdd1e14b746ea57ddecbdbc314ba651f88d11727a29aefcb0f1f3277769c5f7c0a6e33edf9c100ed26052bd6c9d0a1abf278c6c6740370634cb1d097c2c9d194d438304f60b963697626ef391fb33e92d41298bff5cea46631d1f4892885f18ec5e73814f89e95b4c5948cd50b5c2cc2f461949536c382bbe41fd8aa69d84cec7f599af4084de52129aafa285c5b7bfb75defdbc1fc1a04d6e8fe106956f76dbe58cd0d76109e4dfed126a7432a8d8b912df891d528d25c03a726a687b8573aad15231c5f66b5ec20d919f46e174922a600a91570982471f7aa03141ef12035f8d3f5fa1b2a388d024e6a7b36f17cfdc6ab552c0731b9181b950b37cb86b3c7fc41aac3f87c37b87a0303e40d4552116c74e35c89500979049a5119696f578f85545cdd16af0463fff8a1c3f5065f8ea235519a1e1ba0f2c295120cf63feacfd9d4fdf0d4787d7a0d18784f1ffaebde58099641a0dbb4cdae3f94e5d0ae2eb15017cca092b1911003a7675a282feb5a16cdfcece5dd6109ef52e561f7f07f8117
#TRUST-RSA-SHA256 aec39dd6d3bd2d56e7bb48aed95729f673a784dfdd5e644b8ef747475d08438fd69e5ef1287f1b58d15781ad71638592e8e51c304e3fa0e5028a064c91627c4a7be42320053fe9c4eaa89db6e51178c9d474c197f05b8a728fbb4edf2c35680d8b95312dabb6a16a9bda289fb1b20f6d0a7b679928f0b916c9119caaf8aba70623e8c35e24f992a844b3a14c601c884c7ead755fda077fa059c3c185129f01d386f07eea5b5a0e6e1a2d9b4a2731da8d437e568738c03b968c3d66f693a606d904bf6b0559ba88862d31b03014acc030859c5d16761ea9ca5273491930ff2d383e9c2fea50079416a0ae22c60e261255f2b602ab8b2875bc2229dede4a4b07a548fe98c5da3d23f9e2102c0e1cf499b7b7ebf441405d71060b23d397cc41e0b7dc881577919cfdc39fd1a9a3d25446183d6c82d625ea8dec0986169a497400551751d79e562eb735bdfea7364e2210b1b3d695623f7e993ecf933f754d7a2a2f2866b39e6d26ec9f5f9ddce1e7da23f8fec2ec083d1e38d4ecfe67a180014c243976ac9052a101d234a3f44a1f0a42db9f2f0621a898f24a327882fdf606ed309a4d604b0c4c2ced2f919c9d5281a19406f26aaecef0065d0b0def04954c56575bb0c5ee3deb165f60f1747b8ecddb4e267b374722c6bf78bd38b0e9be131bbe7eec7bd4ce459546d57b261ad101ccc4a1574575bbc5ff50ffbd52599e3bdb1c
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192465);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/13");

  script_cve_id("CVE-2024-20320");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh52374");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-ssh-privesc-eWDMKew3");
  script_xref(name:"IAVA", value:"2024-A-0169-S");

  script_name(english:"Cisco IOS XR Software SSH Privilege Escalation (cisco-sa-iosxr-ssh-privesc-eWDMKew3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the SSH client feature of Cisco IOS XR Software for Cisco 8000 Series Routers and Cisco
    Network Convergence System (NCS) 540 Series and 5700 Series Routers could allow an authenticated, local
    attacker to elevate privileges on an affected device. This vulnerability is due to insufficient validation
    of arguments that are included with the SSH client CLI command. An attacker with low-privileged access to
    an affected device could exploit this vulnerability by issuing a crafted SSH client command to the CLI. A
    successful exploit could allow the attacker to elevate privileges to root on the affected device.
    (CVE-2024-20320)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-ssh-privesc-eWDMKew3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3022657f");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75299
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3206828a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh52374");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh52374");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20320");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);
# 8000 Series, NCS 540, NCS 5700
if (model !~ "8[0-9]{3}" && model !~ "(?:N|NCS)[\s-]?540" && model !~ "(?:N|NCS)[\s-]?5700")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  {'min_ver': '7.3.2', 'fix_ver': '7.10.2'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['show_version']);
var workaround_params = {'pat' : 'LNT'};

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwh52374'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
