#TRUSTED 5641190eb330986627cf5003e7834a6038099f1cb67e9cc71024a59fa297a6691c16bfc7d556ce0fa742648a576b59398ac1df60b3e283802503bb338c69d1b41ea1424fb2a1c7e45d6609865def3ce908897043cdd9b0da00bd929b1637cac9040f9a27e19a0be5aecfe65cabbcaba6b9cd506e1997246ec011b1f00dc59d62b96d487d0d0efc6ab6b9051383474f71003d5cdfa97b1ad076071ea15d362d66673c0f8807d2772d1fe45265670bb4e22f01dbbbe3809f3a1916d33518d44ef5be5cab70acd412666af306910885b8f7a1e5855a221c4ef53e98a25c911ab00fe85793870cad04d98b6bd109318eb759c87443fed330f0f11b5ee2a81478beccf154d820a68e9ab3a371fa960ad6cab1e79410662d61420fb74b8e969899fe143a7469748b527916cb62f37f414cc5e3da0e58941a167ebbbf3c37b6b106915e86ecb10ead95153a419f696872cefe474fb9d8243397d6bdbc2b59b6472576e8623f1769e294173bae2166e745d8155d93d71eff841406e486720c6ae32de4f59e252b1cedaae0b4b1b99f14c821fc2040e0147a2aaa7ff4e01605a60a1deb144f3a5e3624827c5032caa47659483ba4044c9ea73a7f4df4790bbd3f22a831747e9e37f5c13442526903a7a67cecb74e5d791cb9eb664f8717cdfc6cbcdabb78d1180530ef02602660effa7989367e2bf3e122d85b293ecd657c3d9a327a82df
#TRUST-RSA-SHA256 95410fe1a64941c52edd2e584e06634f5f2663f003baf7ad2910d02ce317e291cd4f8a151b43cece68f02df019f4e29c0326e3690c7b68cee5926047c0d96ed583feff7390dff2cde52e8bf35655ea0d5f641e5de6f83a3ae3dacd43d960138de96951c82ccea530744ac2f6b8e5f22941da5717cda533e07bd1f973f6e675b3054450a874b97d6f072b1df0ada9769484d82b690fcb818b8551141e276ab26368360a3612d1baf73c7e001490e662f2194f4170fd0a45fbaf00ab8e475580869c8e6119a2fdfeb33ebedff7f3591c5dd6905caf5a9a202677da87d144c1bd688ccab2af9ab5491844b45e8feed3c57fcd385624e839a9bc10d3e1e37386df8270f48e6b311ee5a9561c8f643c99b88eb5f09b7cb423e166c9c440a0c1dd344fd52d50dbb6657b68603f2e3d7c6fbe5aa62071b34fbf9aad95ae849a0be32d694cd169a6b840e2716bb24193d6eab6880e5d440879c531f82f09a7708ee7f738e3ae4a924531f5b5da59fe16a384c640201f33c38a41efcef34d4260d6872c988a395f895dcb80f947dce303aef4fddb9fda502029f50a5333cc63aab93fb0c8a64c6137c41eb077177edcb11efe7eb75a1f57f7b46c60b01ac77b9325fedfdfc785ef2ba1177166b826d6487eff7c55ff9867c0d0fc30557f0683e123af4bd8d7a8dac71b5d64b94e9c43bc4b89e4a882ce775163d56804bf7b503e9b3f3258

##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161953);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id("CVE-2021-31385");
  script_xref(name:"JSA", value:"JSA11253");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11253)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in J-Web of Juniper 
Networks Junos OS allows any low-privileged authenticated attacker to elevate their privileges to root. 

Note: Nessus found J-Web enabled [set system services web-management http(s)] on this device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11253");
  script_set_attribute(attribute:"solution", value:
"Disable J-Web, or limit access to only trusted hosts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S19'},
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S10'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S9'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S6'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S7'},
  {'min_ver':'19.2R3', 'fixed_ver':'19.2R3-S3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S3'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S5'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2'},
  {'min_ver':'20.1R3', 'fixed_ver':'20.1R3-S1'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.4R2-S1', 'fixed_display':'20.4R2-S1, 20.4R3'},
  {'min_ver':'20.3', 'fixed_ver':'21.1R1-S1', 'fixed_display':'21.1R1-S1, 21.1R2'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set system services web-management http(s)?"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
