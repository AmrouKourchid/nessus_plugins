#TRUSTED 6e25cb87fe314e50e2a7bb6297ea74c328a5dc99458c0d1fbb69b40eba8a691e088c6f77fc94fa7054a8ce034019f5d3a5eb59444a31d422983c3ff13079a618b895056087d580b69f0a161ab68a3b3dd9b62d011153421c621d31095aface5901c5ff6e44348e678e32aeb284453a7f76aeb4895bc3524658a61c4adbb6ee5c05b714fb8f752ba09879afe7ef78c59dd7836a393d9f4299d679774d6852427cfa3cae1f2d6415d840688a83c882cd0db79216218e0e6a6e9b2243520bb3242cccd36aeca9f37c09d37bc0a9dfb0fcacc682843aae955a8edfc9a51f7848e7eaf3b899400f48c465d58500f6e025030839cafdf79ba2d4fe6a5c12494d8aa601f6001d51722845018c988fa9c8b1982fbef64502fb7d0b5e63262f2615e62a1f3538e223a10d0840ba357007aa887719a568e4d0628431233bb751e325dd0dd07e50cf83d2812b9be6303309d9f3e69e6e4a9cce2c7837a2d8e00f8172971ff15f55875a4ca9605939dacf7117861302f2ce890fe93c9f171c3e919e7c55f14b212272e83c47cd093e250f9e1382a58703017b3257a754e430934f2c3378814d9750aaa3223f7b4ce6ecfdda68aca76d3f0a4a1101011c506cebc52a4c818d854d8005a83ddeba0883f1defd893e588c43fbab8603a927c132d69f459c7b5a11729040a2d49f73172893b5bc86208458e6819254711b2e026ec164cd2a5a1f39
#TRUST-RSA-SHA256 3b6aa55333d9036a808c21beeced821903193ca8636fbec88e6e8697957cfcb53013ad26174202cfedbfb3356927cacc9e5f5fd2b692b7f6d731b85a97336c5215a71397d5f7db73ed0990c36114c0235cb5abadea82136f512ded94d93eff3629d40b80dbbcc2e673185d90c96bcff03aa0de8548fc5c132df8aa25d804fc427d2be4241cf2b0739e862198a0b252f9f93282433b9ee2745b04fa8d969408b9814d75d61bd423ea3cf4f23005b460040fb05af3b4de8355a1286f6c3ffc618e076aeb69b1c33891c455c0e4a33deccf5ad037f71a784b989399bed6677fd45afad7c84d76eb3c9d7c2c4faacb055a5da422109e79e6908faafee91007c863e7ae4dfe5160e76a6716eba4b2265ce6a6df123dfb6dbb66c587f4ee63a74f127b580585616cf67855a7a7b76fe0162ba7a94afd7b638004a4bf0c3e3594c6f930734e70ec3eef9712036a425dc89c074bb2cde0cd86eba27e38eef472449d83529f233df2a6041489c57631b74e563326e1a02321efde620cc78bb262c1efee1bf9b5ea88cbd8269bf3c332d3b429ce4e6eb6198e9ce59cf6d42901986f9b158577444e5db94abfb040fa5e6dbc8e411c84a4e9b1797ef1e916cd7d9d60bc2fde6b73b82e8928ecace833035a946f18e5ec0a9a637d629c84f9eaf1843c5cfe7204937ca39f46a4c94c09990e10052bdb7a2850f29dc9246809e202cd21a933ea
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182351);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id("CVE-2023-20033");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe60256");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cat3k-dos-ZZA4Gb3r");
  script_xref(name:"IAVA", value:"2023-A-0510-S");

  script_name(english:"Cisco IOS XE Software for Catalyst 3650 Catalyst 3850 Series Switches DoS (cisco-sa-cat3k-dos-ZZA4Gb3r)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in Cisco IOS XE Software for Cisco Catalyst 3650 and Catalyst 3850 Series Switches could
    allow an unauthenticated, remote attacker to cause an affected device to reload unexpectedly, resulting in
    a denial of service (DoS) condition. This vulnerability is due to improper resource management when
    processing traffic that is received on the management interface. An attacker could exploit this
    vulnerability by sending a high rate of traffic to the management interface. A successful exploit could
    allow the attacker to cause the device to reload, resulting in a DoS condition. (CVE-2023-20033)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cat3k-dos-ZZA4Gb3r
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d44bc29a");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74916
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3520ae2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe60256");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe60256");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20033");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if (('CATALYST' >!< model && 'WS-C' >!< model) || model !~ "3650|3850")
  audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.5.1',
  '16.5.1a',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.6',
  '16.6.7',
  '16.6.8',
  '16.6.9',
  '16.6.10',
  '16.7.1',
  '16.8.1',
  '16.8.1a',
  '16.8.1s',
  '16.9.1',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '16.9.6',
  '16.9.7',
  '16.9.8',
  '16.11.1',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.2',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.5',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '16.12.8',
  '16.12.9'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['management_interface_enabled'];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe60256'
);

var buf = cisco_command_kb_item('Host/Cisco/Config/show_running-config_interface_GigabitEthernet_0/0', 'show running-config interface GigabitEthernet 0/0');
if (!empty_or_null(buf) && check_cisco_result(buf))
{
  cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_versions:version_list
  );
}
else if (report_paranoia > 1)
{
  cisco::check_and_report(
    product_info:product_info,
    reporting:reporting,
    vuln_versions:version_list
  );
}
else audit(AUDIT_HOST_NOT, 'affected');

