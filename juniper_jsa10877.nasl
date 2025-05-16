#TRUSTED 2889fb9de4a7cc05fad5fe9c8a0dd0da92edd5a6d079cd4f33e186aa9fcd8516335df678b726cd61d3e4d28d233ae1421fc587b4948d624c0badd83df694d6fb09096302188a687c82bea1a4977bafff67206c73ae0957f35d95a24b25824df7320e021517f209c00e30893b89f6c5c0db2c7ee20244f8fae12cc735c19519e255a8aac117f2eec14b4cdc4d058c16af5f10f05476b4e97491ce47322a985d466b3c5c0d6bed5a2da58b932fd597336724e7cf218c41cbe617367885c85760021c228fcb39545923d77d471296844f16098e456d0511aef38b79a6bd05fe3629121b1f6563255744871dc77342685082dff027f7950feaf23795791481db852164e37ed47daa14f30ad3f135aa87ecfc96892a570ebcc9d8d8306d7840ed870aababca65a467c28cd5cec0dc752a30e74606c923135d405c835bb22df5d6b2a31fccfa22e9e9d7f840b22d508f8250bfb209a02f827ed43e06effa5bb94a3397380da3b5abe9f01a245859b72275e8787b4dc64bead2c546d8d36a6e287d1a46122f5784649e83dc83714b9157381d44e861aa35516fa3429dc78320aefc06fcc8d2ac788947d9262254d0ec1a743df16f123ac350c4acecde0dd9697fbb361dc2df9b6562abda6bef5ab5c9978014c34791c8f77a2eaeacb86f9434809f0a9740548eb2c8b7ea9eb4c715b87f9da61b651ddbb4e9588a5ba1597788afb176a5
#TRUST-RSA-SHA256 42dff3fe5787e52ca861fd991b9b87066e7039859ecc2882513c4ea6f95fd8b7679eb68f554b30052357653bb1f5ddabd156c41ef22ba5cde7f4797c48a5a29938c397fbf6215fe973f6cb3337071046bc730f3e78c95a7210a559a40125703e7656ff629af30b2f18a861fd7eaa85aa290ba5f06f6d9c5101537e37bb009231c4b1b04ae7e01afc501b0021cf517f1ab0f5093bc32a898444f8dd10c18e70b7544107c967b937b9beb89c8d6944f0df45068fb309930ce264f7cdcce79addf31a6714d4e75d315daf36eb275d17fd4f121cf42af0d7563f5947296cecd8e339b00dcc47a3e27a34df4c882627e6ed5f0a0636c614bbffae1d3f15f03a3a68ecc93051f7a50ecbfa7211cba4b2bcbfaf97a64d8a3bd4c38616c1fa7034382a7fba99f683a49537fb9d98ad72453ca36d5a08ff271c0a3953dabf7a0586b5e31adff6a6b66d674722096168445e25486996e55fab2993025b33c2d0659c2424f6dae4b68d6136cf037c56f2c573f2a7f467b96fea2692252a620d75ee4be15facf41f5b2524a8f61d02804a4a551478733fb259bcbb383cb5ea28d34eaeeb8fb067f5789f0b7b9792d717523e9027767ba57f8dc3d6d1d75108c9bb8586892f925642e1d833c70f7853be030425e9df2a5d20d344c203ad07fd5413efbc640841f16695ab22b0cd5f601627fc11a3d42d0540d3a233e25a142b0ac43e3a125e6c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118231);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/24");

  script_cve_id("CVE-2018-0043");
  script_xref(name:"JSA", value:"JSA10877");

  script_name(english:"Juniper Junos RPD MPLS RCE (JSA10877)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a potential remote code execution vulnerability due to
how the routing protocol daemon handles MPLS packets. An attacker could
potentially crash the RDP service or execute code.");
  # https://supportportal.juniper.net/s/article/2018-10-Security-Bulletin-Junos-OS-RPD-daemon-crashes-upon-receipt-of-specific-MPLS-packet-CVE-2018-0043
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25daec47");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10877");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0043");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.1X46', 'fixed_ver':'12.1X46-D77', 'model':'^SRX'},
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S10'},
  {'min_ver':'12.3X48', 'fixed_ver':'12.3X48-D75', 'model':'^SRX'},
  {'min_ver':'14.1X53', 'fixed_ver':'14.1X53-D130', 'model':'^(EX|QF|QFX)', 'fixed_display':'14.1X53-D130, 14.1X53-D47'},
  {'min_ver':'15.1', 'fixed_ver':'15.1R4-S9 15.1R7'},
  {'min_ver':'15.1F6', 'fixed_ver':'15.1F6-S10'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D140', 'model':'^SRX'},
  {'min_ver':'15.1X53', 'fixed_ver':'15.1X53-D233', 'model':'^(EX23|EX34|NFX|QFX1|QFX511|QFX52)', 'fixed_display':'15.1X53-D233, 15.1X53-D471 15.1X53-D490, 15.1X53-D59, 15.1X53-D67'},
  {'min_ver':'16.1', 'fixed_ver':'16.1R3-S8 16.1R4-S8 16.1R5-S4 16.1R6-S4 16.1R7'},
  {'min_ver':'16.1X65', 'fixed_ver':'16.1X65-D48'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R1-S6 16.2R3'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R1-S7 17.1R2-S6 17.1R3'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R1-S6 17.2R2-S3 17.2R3'},
  {'min_ver':'17.2X75', 'fixed_ver':'17.2X75-D100 17.2X75-D42 17.2X75-D91'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R1-S4 17.3R2-S2 17.3R3'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R1-S3 17.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
