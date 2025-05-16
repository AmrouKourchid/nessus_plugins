#TRUSTED 5019f7e52a6031c5492545512a6230f159ae60708fb55af69b4f54df54fd3e1f767b4c6393ac929b995ec9a8ef82e2a85ebb3e069ae0cd3ac3e286d5a14b526ce031408854f65118b86e80dc407073d11a0bdad7ff6a7476e5718eb8ceb9a3005c674098149fca4851b203d0aaa9b0d664d4fd54448c10c11fbdf8769513cd19f8c3015f0608b97f52b8225472cf8234546fc9482443c0fcb64d8fa4a4b32ae447b6e40a922cdeb27a7e9b62be497ee0a9ac6b1944bf6703529c96d4db26ace6a5e2cfe0737437e334cc21271a972c78017a9c5670a86f2ec41d6df62f7610a81750385fe9ec5a61468ee7aa4cb05842edf9cc22ab3aaac82a99a2e2472f808ec3013c77d188e5a73a6b51b77d4a2d880caf210a9ea51e5185dc14cdbd2d0d54b1b0ec50947fbbff52434f4fc6201c7cd1fec1c04032a38fa4835415b844ab5c5b6cfc91d690fef600bb35a4108d666ce1887472a9b23fbbfb6903214c1da7786765e91fbb9a599e975fb1ae32778c1784a625d0738fbe0aec159ef03e369dc23f7d952c1423894edb94f9f77b1a57a58866b7394658b8a29fbd005e0f01c344f6b72c03de5bfda0fcc9b12fa7dca0cf64ed750f7dc6c86549236654f6590b06fd73ee8b432eb782628257b40869206d301caa1d8318a6b9e52a9a8d47dac4608d04a8b447b708c410c6703542de16877e99119747d09488d8eb162c24dfee35
#TRUST-RSA-SHA256 6987ad48d1ce59a4758b6055f6148c041385b743cbb9e82250232aef5ddd52902a8793b7dbd3c87a308e0630ee229ebc3c248c5838b50bc79812b05471371c1464cd0618dd40a79cda0f97bb9e6ee58d7b25aab5e62edfe7129ec1c724914e1abba1561d05b2c6bc6195fe150e3b7f787155b474b7dc032c0f1bbb2c067d2e46865dda2570d8313f0ec2075af6c140ac65943b5bf51fd2a5a9a48dfda1ad4e0c709a1f74e88eafa728d05673556de54dd1a7359b25273ec00b7619e8c589668294916c8d2b0b4d879958210e1acdc98e98e1df3a597bf6726abac07ba9df7412917a5ec97766734d16e234d441596a2abd0a9f72a9d65b3a738a5d806a7c5416c9323fcd145e2cd850d13af077a18a2fb73c8f25d7d5aa4beeb553e8e93418f27e36b6c315ff3973628618a6808342d29f41dfb5a2b580e133d6c5fc63a17fa47d388f6d4ad71c9370ae69a51c0489316e98c30f6e472098b04c46c664ac9f4e96a4cbcfe685219511749d8f52ce26da3d38ca4314d1a15eae59736e1c3798767861f780929e9789b28e1779240348276d3690097dc3195f0d7ca1810a10f7abd2ce2d709379a05afb5cb2846c63583e3adfb8b4ab28c617551f72f8257838d1ccc55d515b89c563831dcce519d5fb1c1b6e4c7d9e0d30db4e72750f2f68eeb8d19dfc5487cb749dbfaa32a98d18a3004894f01d0b94c2daa99d0310000e7853
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232736);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id("CVE-2024-39516");
  script_xref(name:"JSA", value:"JSA88100");
  script_xref(name:"IAVA", value:"2024-A-0650");

  script_name(english:"Juniper Junos OS DoS (JSA88100)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA88100
advisory.

  - An Out-of-Bounds Read vulnerability in the routing protocol daemon (rpd) of Juniper Networks Junos OS and
    Junos OS Evolved allows an unauthenticated network-based attacker sending a specifically malformed BGP
    packet to cause rpd to crash and restart, resulting in a Denial of Service (DoS). Continued receipt and
    processing of this packet will create a sustained Denial of Service (DoS) condition. (CVE-2024-39516)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Junos-OS-and-Junos-OS-Evolved-Receipt-of-a-specifically-malformed-BGP-packet-causes-RPD-crash-when-segment-routing-is-enabled-CVE-2024-39516
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73c57d63");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA88100");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/14");

  script_set_attribute(attribute:"plugin_type", value:"combined"); 
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'21.4R3-S8'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.4R3-S8-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S5'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S5-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S4'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-S4-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3-S3'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R3-S3-EVO'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2-S2'},
  {'min_ver':'23.2-EVO', 'fixed_ver':'23.2R2-S2-EVO'},
  {'min_ver':'23.4', 'fixed_ver':'23.4R2'},
  {'min_ver':'23.4-EVO', 'fixed_ver':'23.4R2-EVO'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  var conf1 = junos_check_config(buf:buf, pattern:"^set protocols bgp group.*family traffic-engineering unicast");
  var conf2 = junos_check_config(buf:buf, pattern:"^set protocols bgp .* traceoptions .* detail");

  if (!(conf1 || conf2))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
  override = FALSE;
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
