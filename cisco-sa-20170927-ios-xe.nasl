#TRUSTED 1064656a1c0fe7ef7a9138055c32f500a0841feb5402942482c44c75fbf4a3dec7f54c250bbe04dd28bcff93133500eceb10ecbae4c1fb44d3a4321ce0c4ab06b5b7ab1029f7b1279f8d338e379d2ac78802ab3a146c6541dea31eca46e93733923e715d1b4859715e8037bd1e35cb4f8b9017289fa4195212f39eb4a6cc07d0ed343552075ee467f22d3f1bcde48633a66f9dc08f641f895afb61db183ee037e220b3b9f3e6f460199516aa0e1678f5992860b101550d104a801cdc437cfb58e17a34e634c9822133d283cc1128299510f1d7dd7938240e00514db50383d056cc6da936e5f4b1bd31f2f42ba453c73bacbb5e02d7fc99abe5ef20b71146b067e0c438d62f910e13f6e1f4a665b73c138c3e88cbaf777f99b77e8fe519936b338488c66073fb23de929a3728b2376d07cdf524984669ba7868b71348796e2863e8799a6b644053937350f10621571f618e41f2c617c1cd1712451b39bc17f97b7ece3f3485249c5c53a563257a29917e06bcfc91cd9f58f1db105997744b985d0156c225f58ce561cc50e59cb48679a438179bd5878644badae65aa2c4ccf47f18337dc6e0ee1dabc0809991ed87432b084738ddaedf8a796f21129d4d334583e484a2a1e494ed3ee39e5cbb350802c607b8aa6aa0cc8ff68e67e895b60aab5f67936c9c25926fe50d54a46c14e3d64e12735b7dab31bd263463c3f7b730da4a
#TRUST-RSA-SHA256 4b2a2db60da21eb96c094fce94c05ff4268db3db673e03dc65b0c8b406cbc218cfb786097edbfcf0ef1a08523c3170b26ba378677161abac83db47de89d72cf1f10f3cd847c141d7be2e875a1ca2ccc1b001dfb9ab2fe2bd8fb0e97f5bb566e2b24d13f1cdd56410d49e145ee62230ef93df77b9c2e5f37e6deaf4197e27920079d549e8d180001106533e2b212ebedaf9fb3d38f2067524694eee6808fe8e242692b1050552dde97db63fc948d5a530b18b87860bfcd875448e9a7bde5620b2bc5d80c6bd37536a8c491bd10166697165e2eb82238c74bf3a86cb17b2bfa1dadc179f52dd8c0b2ca9b37873b2eb8a01da63c462a95e5bbbdb9772f5c05b8f56eff63122e087087e88ae5c45abeedcae2aced087ca81b4e21d010e9a55420afd3c84f0feb452602ac42a90827615ab0175c7dfc7e2aeadbd347f0c39d9eb93aa6ced937a64f50b86e90fa48786e24c41670352e16839db0c976e8943f0f3ff006028619500be418ccf73fc88ea91e7fda4e02fbba326ab8ee44dbe347e62b88903e3b29aac15c600cbfc14c32d3ab5289ec6fbb15a240574070fffb5d5177f44dbc9b2eb2b656bbfae71534ac1f5c58e57e6df2bc0f238d3f0a07629f8b4024933616233e7acec9655ff0e0ee3a490fd9714bc5b82cd0b13f515fd9bc56ada7180930586f967cb6cee69174d12b9320e9798cf6357f5cb04258d38001f89d41b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131192);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-12222");
  script_bugtraq_id(101035);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd45069");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-ios-xe");

  script_name(english:"Cisco IOS XE Wireless Controller Manager DoS (cisco-sa-20170927-ios-xe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
due to insufficient input validation in the wireless controller manager. An unauthenticated, adjacent attacker can
exploit this, by submitting a crated association request, to cause the switch to restart repeatedly and, consequently,
stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-ios-xe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2904d654");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd45069");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvd45069.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
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
model = get_kb_item('Host/Cisco/IOS-XE/Model');
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affected models:
# Cisco Catalyst 3650 and 3850 switches
# A previous advisory had the last two digits both 0 for Catalyst even though more precision was specified in the
# advisory, so do the same here. 
vuln = FALSE;
if (device_model =~ "cat" &&
    product_info.model =~ "3[68][0-9]{2}")
  vuln = TRUE;

# The 'show version' output from the advisory contains no model. In case we don't have a model match but paranoia is
# enabled, we'll continue to report.
if (!vuln && report_paranoia < 2)
  audit(AUDIT_HOST_NOT, "affected");

vuln_ranges = [{'min_ver' : '16.1',  'fix_ver' : '16.3.4'}];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['wlc_interface'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info.version,
  'bug_id'   , 'CSCvd45069',
  'cmds'     , make_list('show wireless interface summary')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params,
  switch_only:TRUE
);
