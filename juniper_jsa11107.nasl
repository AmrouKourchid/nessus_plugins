#TRUSTED 1ff1b70f77ac538edc5c1fbf740aa7338481b096bb3980d0e980bc9e97edd90c4244400ad6d9133b86f829575c7c373ab72c7a63c1239d5caf37e5d92f3e1e5316fb892c941eb36934d9e7ef03d1004c3a7b882bd6c5c9178125760847fa2c9789c082d070d09dc19634efa37d28b84732807fbd3bd048bfcea7d91b228d6b48a4b89b59b308407b78b34e8c45ed37086c608469e62e1a61bfe42225ef2c2ed7c652087dd60d30a7c26b26dd538bb47001aae820c6d37778285e5e1d7d49293ba4a06297a27d6970941e577a65f649a1a16ea0e6786c6b1cf41ea84ac30511488fb0934cfbcb4331afe1866f77d43290ee16f2fa13b5587bf8d9cd92b574a6bd133c81e7a5158d812406f7421a40cabedfbf00a4fd719834b6294a440baee6ddd9fb714762940297452f170b470a8981a94aa71c9dab9a4c0a1fc2dd95a115747ddf12ff8b51847c105f09fd83f4a8fc05f21b58221f4f6e56fdb5b54423f7f2b1151eda68095355ea4bcf56cbb3bc3989fd0c82afcd29691098ab860610f0a9c23680fe7a62e30650ef588297e17c3d30e32bd7e344565db798a890b2841057070aa796821d09a97119948106a16117990ab647d260301bfdd4609f9d7ed182032cc425d8b6fcb8882a3f9bab04e8c50bface2ae6a5b621e981a39a700ebacce235f2cbb5e275275fce6e06804dfe018d787dcf0cbe4cef29ef168ec207524f
#TRUST-RSA-SHA256 46ea8d71623b1b300e88f62532aaa0a3c59c54a8131f8e75aae1d47f657a2cc46b08fdaa01ce89292f4a11aa4d3f31d5f017055c64898b42fa0c35bbd48fbb1d07dad96bfbb29b3ad455ee852614dbf1e2ded9418778ab713ffbc70e955c4be1fe9a0121be9f6de318f259be05d7c52b7bd64a6c880879e46ba00fbecf45d8dd1215009c010ab332ef6ad95ce366532e626c4ec35247304ad404ec6dead8a595a84f4940b9957f1936c41667c156a02e613e79e16414347165ba3f3100b184d6f7cc093cb461526f40c89b3e9a7d8f9a40275860877e93a5bd2d69147f789d8bce283e91fd00ec4eb3d17fea7e0eb5e99f97a4308e9f95a3bcfe1b314958767582dd07cff9eff9629a3dc3cfc5250f1e2bc8c32bf0d2dd97249549baccc1808d892f265288ff4bc8c1b0269be8f6cadb6271a064c54b32ef8426023936d1375ac4a9550fa85037a9e92c32b154dc532f79701f0ec7d6367f29a417dbc968e9e776209b6b9166ac5cc13a16709016bb881c92dd6e0366ebf905153481987bfaa0bb760f4d46f56c1b34365adb938ad0b15e0ed181424011ce6a09ac9823887da1cc7d0b5b7c7d98c6cda1ec51c495d940f0f4b6d5551dc12d03f59079d1d875be737ac781805550b9bccfe3816e4fb5648fb99893275843374b815fe717dbbbc6735cf1371d79921ac24543d8b162104321b4a7c0abac9f1ea762bbab3b2abba9
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144933);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/30");

  script_cve_id("CVE-2021-0217");
  script_xref(name:"JSA", value:"JSA11107");

  script_name(english:"Juniper Junos OS DoS (JSA11107)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced in 
the JSA11107 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11107");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11107");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX|QFX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'17.4R3',	'fixed_ver':'17.4R3-S3'},
  {'min_ver':'18.1R3-S6',	'fixed_ver':'18.1R3-S11'},
  {'min_ver':'18.2R3',	'fixed_ver':'18.2R3-S6'},
  {'min_ver':'18.3R3',	'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4R2',	'fixed_ver':'18.4R2-S5'},
  {'min_ver':'18.4R3',	'fixed_ver':'18.4R3-S6'},
  {'min_ver':'19.1R2',	'fixed_ver':'19.1R3-S3'},
  {'min_ver':'19.2',	'fixed_ver':'19.2R3-S1'},
  {'min_ver':'19.3',	'fixed_ver':'19.3R2-S5', 'fixed_display':'19.3R2-S5, 19.3R3'},
  {'min_ver':'19.4',	'fixed_ver':'19.4R2-S2', 'fixed_display':'19.4R2-S2, 19.4R3'},
  {'min_ver':'20.1',	'fixed_ver':'20.1R2'},
  {'min_ver':'20.2',	'fixed_ver':'20.2R1-S2', 'fixed_display':'20.2R1-S2, 20.2R2'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set system services dhcp.*") ||
      !junos_check_config(buf:buf, pattern:"^set forwarding-options dhcp-relay.*"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
