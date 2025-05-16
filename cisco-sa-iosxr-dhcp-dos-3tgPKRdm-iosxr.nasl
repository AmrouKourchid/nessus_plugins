#TRUSTED 158df5b9bebc5b14b95a0cf2c524143b4fd0dbce513ed8075406bfcbfec62d144e3308d11282650352cb6a93fb9f0ae62341e67863b0b49692eba61a9a7f11453984ab7c2f5db9a0b2d7600e7a942bd19287e4b8446b9c384a22ba8621279bbda152bff8ea159d0a706d8ea44a338df820c4dea5843c834cfefdd3fbc2993a9075c743e6b44d0664eb3489e64aacc03eac214bc8498bd5b475febd417a397699cd3edaa8eb8416c8e53b19115f25924a0344f26d477c9a5321f80ccdca6c6aa38ba42ee58e3f5500798872c512e247ce7ea94e5b785741fb44c32a679bcb9e82b733001b967ed4dd7eef9fbf6dad3f06947e6c1c8f91fdf9d2bd8cf0183dcc2a258e47f8d301b0a712676be84067b7a94b9fd26b77bba8dd2061d864fc03c081eb9faa36841a1d27b884c393055adfa934dd7999c21c602142e42866fa5eb44000eb2cd0184f88b45a5c89e70761769d7f18082ad0311f324b32599942336532e8c9d1471073d68a24a6e3d718ecfc87313b3bfd1228b1ca77c305c518ce41030ad18c49f4d8b4e9d0dc67de755a905836886ee34e69148742e4b7f5a9c3447ed6aca20b3f9f460bf44f02837bb71e69af4d0bb1608267edd5ca1f98cbd942a547cb5c1672ba7739dbc4d3d6517602c5ab6a81fc6f359a8410035d0f953f8ab789595ec9949e0304cadd98866b4f2d7bc28863272a2c8d7c570f3bcc8adae4d3
#TRUST-RSA-SHA256 98fe9cb1744954423c88d6ccbe22930f7385fde58ba571c672076efbcfdabf5e958bbbec93d8a0c96e891b076fff74f8028bc076c0b7c39db46bec51e457ba81c58978adb5b611cdbeb667910ffb4b005a299efa680d7228949af343659514825379970467ab651871ef84c24e0982c7598947cc37b805fd1639c37c9344d2edc5ff95ec5cea43aaf75e91ed7bd5662df0714df1fc389078f144413accae02cae594802a9c4b420c44dab90a20e5a27c0bad97355b593a48064df7a851776593f8e60b5fb0e9bb1c167d1e869e11c1246f39cb5e7fe2abc8b83666ba18535194977180000c896ead52cd4c1b0690e71ec361533d04f5a2bf9bf87379e2d6a1bbba8af3fbe55264f0b2ef72503de57ffb1ee76293114e60479170bc21d7d6f88772d8003b36389268644b84f652f1d2adc85862d4183f7a7f4c293bed0c67f25f2d0db95e3e0318ab79f0912874180fb2218a11d8ae6e3841d45430a1e153ae273e5d4800078e773fb9d88d60fef768b9a599dea2423196a0a5891b5f9386199fe505b45c9d1733f619872771911835b1d9fcacf7b171a7b6c5e28709da0f5a90b1a6232f4e83601cda5405e941f10ed15fd79166a281ba7f587b493be9aab34898d83ef2b3da8f5242a6df617e1d56b4df2aa1c2ff379e4493866a23d56ac541f7c81e3a73127858eb9d802d5a40b7beb4a80edc79f8c599e37e5f32e1a660b7
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213554);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/08");

  script_cve_id("CVE-2024-20266");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf83090");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-dhcp-dos-3tgPKRdm");

  script_name(english:"Cisco IOS XR Software DHCP Version 4 Server DoS (cisco-sa-iosxr-dhcp-dos-3tgPKRdm)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the DHCP version 4 (DHCPv4) server feature of Cisco IOS XR Software could allow an
    unauthenticated, remote attacker to trigger a crash of the dhcpd process, resulting in a denial of service
    (DoS) condition. This vulnerability exists because certain DHCPv4 messages are improperly validated when
    they are processed by an affected device. An attacker could exploit this vulnerability by sending a
    malformed DHCPv4 message to an affected device. A successful exploit could allow the attacker to cause a
    crash of the dhcpd process. While the dhcpd process is restarting, which may take approximately two
    minutes, DHCPv4 server services are unavailable on the affected device. This could temporarily prevent
    network access to clients that join the network during that time period and rely on the DHCPv4 server of
    the affected device. Notes: Only the dhcpd process crashes and eventually restarts automatically. The
    router does not reload. This vulnerability only applies to DHCPv4. DHCP version 6 (DHCPv6) is not
    affected. (CVE-2024-20266)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dhcp-dos-3tgPKRdm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e30a45e5");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75299
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3206828a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf83090");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf83090");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20266");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var version_list=[
  {'min_ver': '0.0', 'fix_ver': '7.11.1'},
  {'min_ver': '24.1', 'fix_ver':'24.1.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['dhcpv4_server_proxy'];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwf83090',
  'cmds'     , make_list('show running-config dhcp ipv4')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:version_list
);
