#TRUSTED 6cb61bb2ea6621cf17b18abb32bdf151a9b7294abc6e779abb8e7174896ece13eae1d1949d45f303496456df22fc5f216a8b4b94e7e4da476e51142291fb39e20255e23a6e95ec6f769db6def5ad6a85c880987756fdda5b0dc141ce91114066735fc784878bc221b312a74ace7f41e24938ecc089a741bc67d1094ee3ed48bfcf30c35ba167dd7c252addce33f013eed20a115a9302b05ecc0afcc7c417ef8a795e061bd658670874afb6f156a35d7642e99df315cbd3dfeed18a6968b81e3639b603d4b42657ee5e731ccf0a7cd234ac58c11ecb25e178973d96aac751a19a0ad36c8d97b723b3bcb82e557727e70f0dc1a0a3600775e0b2c74e1caa55146108a7a8b869e58e43f6f437f6b1193b33117bbc5f95d9df232a46e7707093e6813a25d80e57bfbf341a9add4a5f45aab66d8255e65e44087f742a9eb172c755ca41217c2aa7b2c8325f932b5691bc2f63d87b4187972b28a924437f89b5abde29b5d72255c28502e24f5528fdcd281db92c00b76d7f1403287bcedb0d66974adf0545e1ba3335b137fb621af390a4893f09e75663f3f70ac3549cc4a76677256106988a6c27fffd0ff87522c04ac77eba9970813c89e4301999e89a1685551e794668561163f3823c0eba458b69a37ab8456e43e17173225fdbd648b359d5d0370c50245ce18386dd161bcd021d6860cd33f037845871095118d6a48628138576
#TRUST-RSA-SHA256 26f3af89474fa057bd5490bb795c536e03a1270e4b9b8d715f009d855bb775a3e9cf4187e7b71d70ab63d991ecc045bc53862ef2b9790901e8d8cb698dd3498883c63887f7f72f6ec9c0d19a67a66f3eee4df43e8e7e1f4f0334a2bf4515b90fbb0f68af8ae698217d1aecd83eff532cdbffcab41192258b86d93102dc142b62b7c7315e99c04a84037ae32db4408fdf33a0f33f28f724cfac7f23bd23212aa74798a012cef66007cb422cafacdbd099570759b146ade690f0162427b44ce45e7cba66529a448c9285808005bd0bb90c4d47318a47b9698c020dfe39674acef27ad17a17052180230a1e20c3e5ca6304816f949e4f544d570f63fdf59d9db1b8914f9a8547f93c752995dc5db4227249a1098ff779cd716241eeb0ab0daab8b6a336ef1b2f7b3aa942002dbaf31d1488b3c2156bd61eca3d79ce54dd5c3f8bcf2c526cbda363a026d7b9e2d75ad429bbada38b10fcb1f9a89f5659262ee45c35980ce837ed7bfc8b93c1d02654a7c0dd9b35359136233367852742511c32e447108bdf8e06b75a5583e75b4c252d267fd6ef5d53f9c50ae0402e76da46552583857d30a13583ef5fc27a4bdf76b316cc50a496cbebb9df79c84089926363d31b3eff546c5865d821329f6035370ff1ae282c49d8422bf42d6eeefab734f22da5d24db14297735ae6853db502950d64668b04cf408c1adbc218a4be1d0b21724e
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141827);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2020-1665");
  script_xref(name:"JSA", value:"JSA11062");
  script_xref(name:"IAVA", value:"2020-A-0467-S");

  script_name(english:"Juniper Junos MX/EX9200 Series: DDoS Vulnerability (JSA11062)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is MX series or EX9200 series prior to 17.2R3-S4, 17.2X75-D102, 
17.3R3-S8, 17.4R2-S11,18.2R2-S7, 18.2X75-D30, or 18.3R2-S4. It is, therefore, affected by a vulnerability as referenced
in the JSA11062 advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's
self-reported version number.");
  # https://supportportal.juniper.net/s/article/2020-10-Security-Bulletin-Junos-OS-MX-series-EX9200-Series-IPv6-DDoS-protection-does-not-work-as-expected-CVE-2020-1665
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f29c10f");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11062");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX92|MX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.2', 'fixed_ver':'17.2R3-S4', 'model':'^(EX92|MX)'},
  {'min_ver':'17.2X75', 'fixed_ver':'17.2X75-D102', 'model':'^(EX92|MX)', 'fixed_display':'17.2X75-D102, 17.2X75-D110'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S8', 'model':'^(EX92|MX)'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S11', 'model':'^(EX92|MX)'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S2', 'model':'^(EX92|MX)'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S7', 'model':'^(EX92|MX)', 'fixed_display':'18.2R2-S7, 18.2R3'},
  {'min_ver':'18.2R3', 'fixed_ver':'18.2R3-S3', 'model':'^(EX92|MX)'},
  {'min_ver':'18.2X75', 'fixed_ver':'18.2X75-D30', 'model':'^(EX92|MX)'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R2-S4', 'model':'^(EX92|MX)'},
  {'min_ver':'18.3R3', 'fixed_ver':'18.3R3-S2', 'model':'^(EX92|MX)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
