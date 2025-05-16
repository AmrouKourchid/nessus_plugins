#TRUSTED 2a39af7a696efa999febc5ba44ec418b6eae22f63df6bd2ddd8cb07a768f3503d7b5eebfdceefd9d5687c3d5c5f958327372b3cc6c8537fad4e18452b9fff8546619e6e9892f7b6705dd7da6316979e8fabac7bc673c2d8442f3e0cd3d89f05f2856f0f1272a2d93c91cfdd204849e92c9e0447eae89ad245d2c7d30f496f6fe55874b551edda4b31febb17fb727b506944290ef3b5e3b31a64964ba1020bf35c576ebf19dc35e279e67a7c01c04056120e86f816e905ef964f23a365f10b97b18b1c5b8b98181b5e91c3ea15afd4bf0c552085655dfc11c601415b8fe0a88c84e1fbd56783e940642b5d27602bfc20a368d1aed5093ebeea9e77d4ef06c2dc5137ef1c83595036abeb6a59b3e6a201909c3cd3959720291cae9a5c0f88e6957efea8bce4cdc4e61d97d04175d2fbc13b2fe57c547f41848a108866aa02ecea3cebc63d84e45e8876b3a38a3f192ed5fbe393c3816cee088540fe539d67771ef1f75726c98d18cac1bf9321564e3db308c183a7d1c5c2cda4064dcde6c3431adc30e5ff7bdd0500cfdb40cf919ece7655f2f5e1a9cf1c70a6b77b13211195d0e5b124ed970ace1c9b3396bb8584d0b55f6fd56563a1f55f2aa96e971a3a9fd2d64168fb9c24a7e9ab69bf6792f2825b69dcc689b1458e039db506949d7661daede6a0103410cd1170aa64f0b8003876fb7cc8cc866f4f3dfd38cf5a744faa71c
#TRUST-RSA-SHA256 847602bc96d697135af856d8430306d1eb11d98a0e93e5471673c855c8a748a11b2f08c6f934fbe7c75ee7561229a97a16519684ebbf10e9e631594cb8cad3c9bbd929d7c59b45f82642377a2d5377d529db1ce9575b1e53146bb2e06f2d0fbd864d6ef2836321927d231c9a5edeab848ea4f282765c05701c12b620eca20d026c551ee5f5126d2d4710d21a569bbb76305dcf75687d6d3ae2a2f186c3955807a127996d2538fdc781cc126ffabb70d8eb6397772b2c5d71c269eac4c0b3cc14ea0f812ff0a2d4708c63f9e1bdcbcf44ea3a6fd8d66f49e1ef6e5786c13e7645512f9f4c6c830a04c370ce488e2318b951f3aad55ee923f4958ab93623dbbf24f961a2a286457d6cfc885a5e276e4ae7be70aea1d9e8d7ecd73806884e64fb6942f83b7c1fc6ab41d67c4ead705bd8f1e42cfc1cf17f0b52a5887d3bc9294e4222973f0351c4c03383a7609ed5537695750316184b93892ffd85a96213973d63dac505399bad5bb8483ff1f8aa54531379d2fe0b2265ef055725893ecd926899599a32e8ce1c28bff97c7121bf440963ff9e005ebfa26e2fc675eeee5c8024bd8e457be6ebb6e1fc10b9979c1ab214eb4e511b271e8d7dd05d197b78990b755be8e9fec313a29842d565cd2c1b7392d3629f29d75c7c3de0454314cfdc4a11ed36c9249444f2775991316d0ac231b10c867cadd17c2367363abb042f9ef12aa0
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143382);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2020-1689");
  script_xref(name:"JSA", value:"JSA11086");
  script_xref(name:"IAVA", value:"2020-A-0467-S");

  script_name(english:"Juniper Junos OS EX4300-MP/EX4600/QFX5K Series DoS (JSA11086)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11086
advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2020-10-Security-Bulletin-Junos-OS-EX4300-MP-EX4600-QFX5K-Series-High-CPU-load-due-to-receipt-of-specific-layer-2-frames-when-deployed-in-a-Virtual-Chassis-configuration-CVE-2020-1689
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34483a1a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11086");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1689");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^EX4300")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S9', 'model':'^EX4300'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S11', 'model':'^EX4300'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S2', 'model':'^EX4300', 'fixed_display':'17.4R3-S2, 17.4R3-S3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S11', 'model':'^EX4300'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S5', 'model':'^EX4300'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R2-S4', 'model':'^EX4300'},
  {'min_ver':'18.3R3', 'fixed_ver':'18.3R3-S3', 'model':'^EX4300'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S5', 'model':'^EX4300'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S4', 'model':'^EX4300'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S2', 'model':'^EX4300'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S5', 'model':'^EX4300', 'fixed_display':'19.2R1-S5, 19.2R3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S4', 'model':'^EX4300', 'fixed_display':'19.3R2-S4, 19.3R3'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S3', 'model':'^EX4300', 'fixed_display':'19.4R1-S3, 19.4R2-S1, 19.4R3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R1-S3', 'model':'^EX4300', 'fixed_display':'20.1R1-S3, 20.1R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
