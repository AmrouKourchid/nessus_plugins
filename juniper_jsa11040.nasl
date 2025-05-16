#TRUSTED 63295c4902e3da3e7326fa215eeb66eb0ef07c31424a785f6dbe7278a44a9cf66e6214882f65c28dae61cf0e6044f47e13fafde57120e14f97e1c89a31ba32bf2a37d0e89786a840831f30140382acbb985dc01e709dcb98ce9e6c1b1f9896d6521b96bd5a2ca20f7f1111b071d83ca7186d5203dfc4f5abdd92330b181b87ab2fd947b8216a1f87468498e9ad3c841caacffd420f868b2dc4f4471aa28af43da85d3266dd453a86a9475954bf7e1dbc761ac432a0094fc6ba532f6518be625cfe3865f1f9892a2bfa476f2b78b53bf1c515e9cdf063daa73af0dfc334575dd582fdcb0ac0cc8cfad9781ce88367b526ae7a6b99ffd727a9dabc522d28094871690f895b8ed436eb58e426197d34ca166e5f38b7b365763164c40ccbd67c92b97bc5408365c79c62ec1eb11210f2fb0db69dd2fb6196a7c34b8b29d587c6ee861f8964e03ca552679c0cef58fb1a759273b1583a03da081f8aa9572bb91af0ad2632e8f29b5e024d34defca6aae2e88207c5f45c805227b784897e2455b5c2601dc1b7d6c48ea382232b9a242cd5f8d2299a58e0c263a58c3e59aaaa63058c94f25d5a689ff3759ca5e42af65d9cd8910dc64e98b3581adcc454926df218fd4b3a4a5eb1f17efb2d7bf8d7ff9b2140b8d4f83a4782b274cacafdb83ae31f2dfc58a14b30ce8ce0425d01249882d5782408437db9016a4eecf4f23b02c3c0af73
#TRUST-RSA-SHA256 174132837ab8b6e790150d6164db26e9f94fdf3a54ada928507f1e2d615328552329a375dfe51da8db115112d2c104e87f46c7e212a2f3533b1f8355e4a43473f9fc92d0282a0e1a233728ad840bc8f32994101674a0971cc94c06a067beb28cf0a623a2a9fa2acc3c800e95a07edc6f11f6c6b6c07f545221b65db52404dda7b66a4bfb84b325350d503d9e4a44554017b783e68d6d5946341eac9b487b8aac7dcbe08203c4e2bfb10813532f7b186f64a4c081b0f88895c9102673ef5cc5c5ef549f3687e97ece935d036ed8c7d20d15786a078f0e1a81c0c7b4ae5f396e2fd75fdca9be434cc212cf8617cded194d6290b8560cdf146a148df9cf9d0b333e299908d46e38c43e288d676c3a578393237d2ca2efe23d66c464ad640b2130f9b06b6861feb86989fef09c82dbced66c24218c2b5f852535ef99aeb66263cf0b99b0e13691d39e0d7b637fcd2b0cb2caeaede37d207ca3ea76f4eb3fac0c8f74b8fcd80b8af97c2fc75eaea78575b73fe90cb6d94bd305530c65527497ada3975e80fc32855593eb19f09a7e8cb85b2f8b2836adb997386f2a8bd234fc27e41ebed014601f2ddb15706f7be16f222ca235d12947f8961818c046b949dcb0247a27975ea12b142f97f0cc97d49b15ecdcec0cda047a0ced27051f1b0209599a03b827e156dd66afd3563ead42de6c7a0db163664dca8c6ae7871266624666e68a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138905);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2020-1653");
  script_xref(name:"JSA", value:"JSA11040");
  script_xref(name:"IAVA", value:"2020-A-0320-S");

  script_name(english:"Juniper Junos Kernel Crash (vmcore) or FPC Crash (JSA11040)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Junos OS installed on the remote host is affected by a denial of service
(DoS) vulnerability. On Juniper Networks Junos OS devices, a stream of TCP packets sent to the Routing Engine (RE) may
cause mbuf leak which can lead to Flexible PIC Concentrator (FPC) crash or the system to crash and restart (vmcore).
This issue can be trigged by IPv4 or IPv6 and it is caused only by TCP packets. This issue is not related to any
specific configuration and it affects Junos OS releases starting from 17.4R1. However, this issue does not affect Junos
OS releases prior to 18.2R1 when Nonstop active routing (NSR) is configured [edit routing-options nonstop-routing].
The number of mbufs is platform dependent. Once the device runs out of mbufs, the FPC crashes or the vmcore occurs and
the device might become inaccessible requiring a manual restart. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported versio
number.");
  # https://supportportal.juniper.net/s/article/2020-07-Security-Bulletin-Junos-OS-Kernel-crash-vmcore-or-FPC-crash-due-to-mbuf-leak-CVE-2020-1653
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b98f44fc");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11040");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S11'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S2'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S10'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S7'},
  {'min_ver':'18.2R3', 'fixed_ver':'18.2R3-S5'},
  {'min_ver':'18.2X75', 'fixed_ver':'18.2X75-D34', 'fixed_display':'18.2X75-D34, 18.2X75-D41, 18.2X75-D420.12, 18.2X75-D51, 18.2X75-D60'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R2-S4'},
  {'min_ver':'18.3R3', 'fixed_ver':'18.3R3-S2'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S7', 'fixed_display':'18.4R1-S7, 18.4R2-S4'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R3-S1'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S5', 'fixed_display':'19.1R1-S5, 19.1R2-S1, 19.1R3'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S5', 'fixed_display':'19.2R1-S5, 19.2R2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S3', 'fixed_display':'19.3R2-S3, 19.3R3'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S2', 'fixed_display':'19.4R1-S2, 19.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
