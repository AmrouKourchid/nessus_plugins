#TRUSTED a0c7255fa13187ee032b173964f66b735af5a14c616667c365892f28aea9c7a848ce8e91292dfdc174fb8b4798778f88bd58d2429a710131a27fddaea916c351df34ec1fdfa5f61dd2eb8d5b8bd278361763378e7b70b7060a0f04d4b2b6bd1f62070a213df28c60fd05a477f28ffe9ccaa72621fd47efa4498864b9df0eb23fb04cba3940dcc8690491dcf9f38fff774fb5b26e943015dfda4561d4738e5f856972d788217b084bbe5bc69a126219d81f50b0ea160e1690a7538581674374aee1b1deff3223ce6f0b3682546116cbde0d6691cf6a54fdb7d52a06f92bd58e36e856b82a1c7537e106f253bdc3fe9df582ed65d797511bf45f2ea9fdc5d14f16f03bfabc088b0fd5f108bdc6492abffec02a985cef7f21a2a09fbd686ddba0f6b3ad26caa1a2f12bfab5c24ff2366baa274946a88e65abbe44ff34f93d6c954e3de75b5382b516771c379df5e99a1295e835cb27892c357a7e639b79924a8ab82c3488f069a334dbeae088326e322e26c914747e6cdafe712567c21927e64726d395b20b14658f9a33b194bf0a03cc3cad9f15b14b4fac91dd39ea946f46cd08553b1d84302d199d06879c6b0980e41c742adae02a8b2a397c42b760d7c2ac8acdeffb506e0919b5f38ce3f3a6df205f4197f16538a878a7c139858662a0fffe89c349a6a9f4cecdb9968a1277cb3de1e3f601eaaf65dc108bd2de8e92ec58b2
#TRUST-RSA-SHA256 4a7c5d7736c58959e884198fc6a243ef743b106bc0d01a975ffb74586f7f1cc97e5b4b2d7465c7f9971cd38a0a6cd0194020e259aa887681ff6eeae23d3aa5eaa69a3d20f3c9c5627d25690a27d295b651847e4515ed05f269ee736a503b5aa4e5fe31ed599dad425493770abb922f96cc8d031166f69c90fb22cc36f1cf59e0501c05c2f3ed3c283c623de099d00dd66cda0e20e56e3d360e47166f41c226f6d31e62a4d23eb41430a22a41a30363880a0c074e8c46ef9bce34221dd1beab0acf8303830c00591a9585b850fee03c06d3175fac4d52edfe182e61c1733d7e07174f62c80555fb4fd21cef47bd72321b7c83e4801f223562948b286d11da7e9e536ff1f24d5a35f78b27fd584ee647f05de11bbb50bd32f6d7f8f18668e9be5fcb0e64b92190bd12b2cd007697c7ad5f9672036a28a102ff5864ba587e1fa919b6eecad54feeccf141383c64aef06bcae0dc64b40920b0e468aaf9d99052a74de0349d84405d9223fefca74acb2fc11d21fa4318a3b23f0713ef71e33d8a39dfd712e1e0adc5de48e6be53aef8eb42e9f99cbdd05ca84c289ed7464669723091fade98989fdd1d37aff20eed269c33d2ac1d5bc1d0cd721824b8ae8531c5343c34482fcc48afe27da5f6e10d1cb4a27fbcced8d2fbf4aaa9e311857afacfde2585ff998eafb424f037ac3caa47a080bb07ca38591f4516d26060aaaa43f67b22
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183505);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2023-44182");
  script_xref(name:"JSA", value:"JSA73149");
  script_xref(name:"IAVA", value:"2023-A-0565");

  script_name(english:"Juniper Junos OS Unchecked Return Value (JSA73149)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA73149
advisory.

  - An Unchecked Return Value vulnerability in the user interfaces to the Juniper Networks Junos OS and Junos
    OS Evolved, the CLI, the XML API, the XML Management Protocol, the NETCONF Management Protocol, the gNMI
    interfaces, and the J-Web User Interfaces causes unintended effects such as demotion or elevation of
    privileges associated with an operators actions to occur. (CVE-2023-44182)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://supportportal.juniper.net/JSA73149");
  # https://www.juniper.net/documentation/us/en/software/junos/interfaces-telemetry/topics/concept/junos-telemetry-interface-grpc-sensors.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?730fe243");
  # https://www.juniper.net/documentation/en_US/junos/topics/concept/junos-software-user-interfaces-overview.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6834662");
  # https://supportportal.juniper.net/s/article/2023-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-An-Unchecked-Return-Value-in-multiple-users-interfaces-affects-confidentiality-and-integrity-of-device-operations-CVE-2023-44182
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9a773ff");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA73149");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44182");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S7'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.4R3-S3-EVO'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S5'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S5'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S4'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S3'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S2'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R1-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R2-S2', 'fixed_display':'22.2R2-S2, 22.2R3'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R1-S2', 'fixed_display':'22.3R1-S2, 22.3R2'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R1-S2-EVO', 'fixed_display':'22.3R1-S2-EVO, 22.3R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, severity:SECURITY_HOLE);