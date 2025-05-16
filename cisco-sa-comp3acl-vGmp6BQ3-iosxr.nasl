#TRUSTED 990fe70530caa699d67e1f987f4a3b8836e606d02c372f4f9a13ee756aea4b604fe1b6fe412d52e320e9ec19ff1b468348f3076906fecbbf09b61296f4786f753f8cecde55b9ab8c67cd29156aaa217ecac213d2e440579414b1973d356b2072124aab860264693b65c3b7e9ba653664a89afa14b0f4d20702a855e75d8cc3e50e699f16577dfae01b0f0bf1b2314312fa5fc0552e719588d598c7085f0301ee50b56133e8f1fe33d4abc2b03c9477278e3d292d1e7c87dd0cc8e42e68027402b02154f4b14f51ea60ca9077451bb266b9581da8b5cda4be5e70c2c657a3cae5453d441a4e3bbaf36bc709613e3ab646febecd26b8513be6500e04eede71947941bfa43343ca99b724b23dadccf475ad7b915512af36946e3c7ad7b7402d433384ad9132ab756b5d130085289fef17b1e020b6029ee41b7890d53e066e2445ccf5a202b48e52043d2be56a193f8c56cc652aac5c2d3a9cb6c37b615ecbbbf22489ed9d8b4fde3e37256c08cee06c899628f7db94069d759a861e08873ee2792bb5349a226f5f63f8dae8334fa5e76f0dc676f766373b2a2e663214a62ffbe6aaeff3e3f337d98abba841748949f515c693a6047c1b506c91b90fb6825077c89aa118bb987eec541bf90cbe8b1ea5fd70b93eb3f0d7178fc51c5ef9e0cf55bab1d1c3016739a7a1bea7995580b308a6de707edd2aa247b3fbf053c848e6c83153
#TRUST-RSA-SHA256 3dc97343c0c1d2f101eddc893975de9eaa225384643f3bedf9339f2d5b5b2845c53f6db1e02f40bb030a4fed27bd7492accd623c957b4dc9380f5145e07a5e6aba1c6d5e2f6e42dcd7a415093cf6198f6b16e61ca8a49dd2a246452b24dff27264960f0b8ef854475bccf08b4507e64e5aa719e7f93db538808156893542323c886611f7b302e2a9035e708be405d8a4b134a47966241c625c5e20eebe7838c041a19f5466045c2c17a5590e03ca7bb30d76452b796f8aadbc86ca735a607ca01311990992ebb52fed914b64cd57c1586922ee37713210fe5e8b0acf83ff8f2b10ec1ecbb80913e8bc9c8ee6f09a397e9e7490f455f7dfb3de34b0890646e8724578467d5b7fe5f86269808fd5deedfdbdda46bc3982783c163e75f705b3fc42c67740143c1ef0ea308b8da08bc6bd59cbb06d044061cb9cfc2e7a8b9bb42eee1bac601cf04b3f862402148a5ec3e2bbea092bf6131805f33b94ace3fe9cc1f12717f16960595a6ecbcc75b84b7428b8d19ff85d4e0ceab2e030f29f30e980b3c64e4e3a4c0d2a5fe503129c375e8774abc8e8e589578bdacd92d630a5e588cddf9ced2ad11fa1823c71181c531943129487dacf9f3c4595019e2f87fb0feb361284cffade674598a17a90f126e3301e14b359fe509ef4bf05158850564919fa23667f8dc7249d601d94e5ba452786700e07c6a53b4122b0fd1f7a011f1dc5c7
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185165);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

  script_cve_id("CVE-2023-20190");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe08950");
  script_xref(name:"CISCO-SA", value:"cisco-sa-comp3acl-vGmp6BQ3");

  script_name(english:"Cisco IOS XR Software Compression ACL Bypass (cisco-sa-comp3acl-vGmp6BQ3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the classic access control list (ACL) compression feature of Cisco IOS XR Software
    could allow an unauthenticated, remote attacker to bypass the protection that is offered by a configured
    ACL on an affected device. This vulnerability is due to incorrect destination address range encoding in
    the compression module of an ACL that is applied to an interface of an affected device. An attacker could
    exploit this vulnerability by sending traffic through the affected device that should be denied by the
    configured ACL. A successful exploit could allow the attacker to bypass configured ACL protections on the
    affected device, allowing the attacker to access trusted networks that the device might be protecting.
    There are workarounds that address this vulnerability. This advisory is part of the September 2023 release
    of the Cisco IOS XR Software Security Advisory Bundled Publication. For a complete list of the advisories
    and links to them, see Cisco Event Response: September 2023 Semiannual Cisco IOS XR Software Security
    Advisory Bundled Publication . (CVE-2023-20190)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-comp3acl-vGmp6BQ3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c94a1e6b");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75241
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a0abd7f");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
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
    {'min_ver' : '0.0', 'fix_ver' : '7.3.5'},
    {'min_ver' : '7.4', 'fix_ver' : '7.5.4'},
    {'min_ver' : '7.6', 'fix_ver' : '7.8.2'},
    {'min_ver' : '7.9', 'fix_ver' : '7.9.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['acl_compress_level23'];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe08950',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
