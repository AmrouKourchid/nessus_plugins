#TRUSTED abd79470c7f92c8cc39016182661d7730eac2cada9b02e90848c53606c5858d1d9290d2ce277ddbf5ff385f1d22c8c00a66173bc7af484b26fea355ebf5d31f9ce687435b60aa32772e30f8cd8ba26b8d0bae7b3e764a7a17aaa8f23104badabeb034fdc892caa95607a65e00949d467114335a2d9ba17885072a6398ca28ea75b68c43763f8cf161a044f785938d4d203fa42efbe64bb485dfeb5fa24e43baf02fcaf0e10545902a2a72786b7a3b9e62eea5940a56e25856a3868cdb16a0001580173f5a047b3f31675dd99ebda5895be49c9e31e4f1b30dad52b90c8c9f800e0804475db36e3fe1c646f65ebba56f3b4afafd86b66aaf573fb0e61d22979263d3d8c0de642497f4d7d8c8bc2e9a72be49383fddc9ef65af363691508521b9e7189d1aec21146721ab9ba698c41f88fda419f58e30d7b38cd14ad6f2d599c7e728eae04f61ac3b69490b1108d391c3bc83ebcee1df458a650f56217e0fc767453d77db877c2da869419c2f866206f4fa3dc25c047166af19b296d71b10371769d3f5473432bda536551e485713d2dc3064743cec65b1313bb26b50f6ab8241db1aa91c9c222ca57a1a2351c25e5d50008a1f1e7fbb638d28c744471e88a5f885016893f006e452e53bc7288627d680d18453486e15d1949e86d206c0eaa48544e3076d565163458aee54267df1d1270e7d9ec98dd1e89e22f8006badc49d3ed
#TRUST-RSA-SHA256 a08581a5adf08c6c1c3f95b87cb744aed10db94fab104231fbb8fd808120f88239429f9feba9ed58d725a9f62cf32b3aeebb8180f660e6153021271beaf72b35d2fe55e4a351c103f99328a51f42d4534138996f2086809fcb61f40131d458ad3327c432f75624824d15d80bd90afa4144e76ded964962d9c0cbaa573bc1010a5ec8d77e75cd3cf86a96208d30936ae356b85708a506eac62fcfeaa190b2e596b9ebbeaea92fcc18302ea8dcbf00551b80824bd1ad84295b586934e43d52fe5daf5eb77b173c696a6e9aced6a05c845cc34adb455509936f97fdd7f734b86ab27a1c9307de6c31f74c0041d8b86ba20063cfb2369b088201d364efac6ab183805cb5f602fa3ebb574c473760fd2787558e9f89e5e21e12b8138947161fe86d885cfa85e6d2b9eb86377e0301d378d676e3f856b236ee92f25fd15f8173dc940114fca77236d8005c62e7f358f65a2188a51f1103976f63100e94dbe0ab3def41f81c828b0da97be2befc698280e47774810c9ec03290510d0787d70dfee5d780cd423548bf7dd8d178c77f1e62fd392a0aeec30fb1369c26e4807aa566d70d487716b056639b3ddf1fbb0457ab4f2a76f1095f68717c370587f3349bfea79ae5fd22d04a44c0d0ea81fecf2d6bbea57236aaeffb178891d0884325af432bd01d27724e8132e6db0d1633ad56a17642e1223e5168dd933f1268cb1024f28b5b2e
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161217);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id("CVE-2022-22186");
  script_xref(name:"JSA", value:"JSA69494");
  script_xref(name:"IAVA", value:"2022-A-0162-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69494)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69494
advisory.

  - Due to an Improper Initialization vulnerability in Juniper Networks Junos OS on EX4650 devices, packets
    received on the management interface (em0) but not destined to the device, may be improperly forwarded to
    an egress interface, instead of being discarded. Such traffic being sent by a client may appear genuine,
    but is non-standard in nature and should be considered as potentially malicious. This issue affects:
    Juniper Networks Junos OS on EX4650 Series: All versions prior to 19.1R3-S8; 19.2 versions prior to
    19.2R3-S5; 19.3 versions prior to 19.3R3-S5; 19.4 versions prior to 19.4R3-S7; 20.1 versions prior to
    20.1R3-S3; 20.2 versions prior to 20.2R3-S4; 20.3 versions prior to 20.3R3-S3; 20.4 versions prior to
    20.4R3-S2; 21.1 versions prior to 21.1R3-S1; 21.2 versions prior to 21.2R3; 21.3 versions prior to 21.3R2;
    21.4 versions prior to 21.4R2; 22.1 versions prior to 22.1R1. (CVE-2022-22186)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2022-04-Security-Bulletin-Junos-OS-EX4650-Series-Certain-traffic-received-by-the-Junos-OS-device-on-the-management-interface-may-be-forwarded-to-egress-interfaces-instead-of-discarded-CVE-2022-22186
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff8efb3b");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69494");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22186");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^EX465")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var vuln_ranges = [
  {'min_ver':'0',    'fixed_ver':'19.1R3-S8', 'model':'^EX465'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S5', 'model':'^EX465'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S5', 'model':'^EX465'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S7', 'model':'^EX465'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S3', 'model':'^EX465'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S4', 'model':'^EX465'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S3', 'model':'^EX465'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S2', 'model':'^EX465'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S1', 'model':'^EX465'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3', 'model':'^EX465'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2', 'model':'^EX465'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2', 'model':'^EX465'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var report = get_report(ver:ver, fix:fix, model:model);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
