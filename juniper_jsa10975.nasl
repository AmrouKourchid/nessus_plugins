#TRUSTED 14748973b6f638eedf88d7546e87fb4215b4d28ffc17acb6d86c91c6da663ce6524fb094f88521df8ca002b935e1e119648ba3a9c995e479fa762b75e065a5e69bab72045733598e992fd473dfb067145a76d4a3ab7594d63fe0c468a48cad5d1311e8e4e7783a7a5ae1429e36f765a88e178af6bd35e87c999d50458abc4904b4b41606a1e285e56cf3fe1b284a5d635d262d2529c526cc8080b3f61278c0ae4b0e3dcf5b9bad8bdeec2b93809b36fa80ed7647c938106182208e9ab8e22b32b033853a67be5033decb11abaed1f76f06db595e15e4073e270d896b80deef4cec9ac863705aae31f1ffbea5c933d95b71c8f5e813dfa123734f951a21a1e2b78ce2c4275323f52ebdef061d2d69c7a65290a63ec3984ab56e7e4c64860b0fd4e4d5d5aca2d5fa2fe8fac01333bd451809ce755512755e21d70ac6bfa826e9c80276ba43f23d81c2da992b9cfdda9aa584c250a0c3db29b28cf18cf4d5b7c808d11d54a4b787ca31a5e4e1efd229ea0d068b1ba8d94378d51123abc12954c7aaf7c770bfb612aa3a491f4d8cf3c94e0b760110b1c80ffcb4e1c41adfbb0ede825e1e8b93f5a31fc46ee63ab210449b9caeeb64c252ad8968b33989e900ade5aa8114871d990573a2bc7775b3dcbb0b05f1ad47b765dcb9059d81804754a2c342ad057302cf4b61e95443c61dd3c4ef5e7391a4dbd061d83bdf376d388c41e27e
#TRUST-RSA-SHA256 996fea758d53463d486d3d838c4dc091312ea1a9da2869eff7c377d8ae60c020a2fbc89d24e63dfa3f406f3d37160116c13e65d93f4e0d94087371f019c6fd9d166ff0918ef5a5a56beb2a6c4a989f499b45f9dcec0295afb4aef8fbd7f46b01f716eaf358c356d59432536ca1e4007e4141061b4a40bd7964e3125387ebe21e4b96ea15c022f3892dcf6f2b71e5d2d4c34193c7683551b22d1e82d5fe46def4470b1b101ed916da73e3fcdb46c66a84fac7848c831655467e1db46c6ba1dd9e0883aadb4de02d222c5c6416b2c448b4367f67800f07048895579d69287f078d88a23524500399a40b1e30defd0dae411a7e7d9f0dd8e03b69f8c3117f947640b5ce615f0eea306146246fc5f5b13bbc67666721f4a199c1397f74dd051f566b9914b9f8d46e35d83c6ef42ff6ca4233769303f76b3cc1658f715586c9998b9a8db001bda3f48a942ac664541725b2710f7bd90bb7b2704bf4796ec048e23fff606634ac0ebd1622924b14aa065ecb0ef319aaf0d5927231a755e30d344c5c4cd91e9cd1be3db8cc8c8853f521275a4be2bece59d3220f6ab37eb6b6ec091ab44edebd1f23bb8a8b3af7b6815a1bf9b4b5e6421843c0f1ad7e2f4bae6a3418619afde4b53c4203662ebdcda165ce024e597d3aa1f12689e7c7353cd8284784b9879f7ddeb1ad2cffa07b5d3632a6d28d6e3d72646ced0dde83bab94b462f5c67
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130279);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2019-0074");
  script_xref(name:"JSA", value:"JSA10975");
  script_xref(name:"IAVA", value:"2019-A-0391");

  script_name(english:"Juniper JSA10975");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to the self reported version of Junos OS on the remote device it is affected by a path traversal
vulnerability with the Next-Generation Routing Engine. A local authenticated attacker can exploit this, to read
sensitive file systems.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2019-10-Security-Bulletin-Junos-OS-NFX150-Series-QFX10K-Series-EX9200-Series-MX-Series-PTX-Series-Path-traversal-vulnerability-in-NFX150-and-NG-RE-leads-to-information-disclosure-CVE-2019-0074
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?571dce86");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10975");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0074");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX9200|NFX150|NG|with)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1F', 'fixed_ver':'15.1F6-S12', 'model':'^(EX9200|NFX150|NG|with)'},
  {'min_ver':'16.1R6', 'fixed_ver':'16.1R6-S6', 'model':'^(EX9200|NFX150|NG|with)'},
  {'min_ver':'16.1R7', 'fixed_ver':'16.1R7-S3', 'model':'^(EX9200|NFX150|NG|with)'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R3', 'model':'^(EX9200|NFX150|NG|with)'},
  {'min_ver':'17.2R1-S3', 'fixed_ver':'17.2R3-S1', 'model':'^(EX9200|NFX150|NG|with)'},
  {'min_ver':'17.3R1-S1', 'fixed_ver':'17.3R3-S3', 'model':'^(EX9200|NFX150|NG|with)'},
  {'min_ver':'17.4R1', 'fixed_ver':'17.4R1-S6', 'model':'^(EX9200|NFX150|NG|with)', 'fixed_display':'17.4R1-S6, 17.4R2-S2, 17.4R3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R2-S4', 'model':'^(EX9200|NFX150|NG|with)'},
  {'min_ver':'18.1R3', 'fixed_ver':'18.1R3-S3', 'model':'^(EX9200|NFX150|NG|with)'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2', 'model':'^(EX9200|NFX150|NG|with)'},
  {'min_ver':'18.2X75', 'fixed_ver':'18.2X75-D40', 'model':'^(EX9200|NFX150|NG|with)'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R1-S2', 'model':'^(EX9200|NFX150|NG|with)', 'fixed_display':'18.3R1-S2, 18.3R2'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S1', 'model':'^(EX9200|NFX150|NG|with)', 'fixed_display':'18.4R1-S1, 18.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
