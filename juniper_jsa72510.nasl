#TRUSTED a10bc1fc82d526c15789cef3396d12d433e71a6800df2d499e8e3f8e02883e893933e794e06fc7651c4bdaaec53d48bc20bc0d2b3e6a3d31c9fe37036ecc1a32b0625a6cdd32ceb69087cf5deb506d051c7d8fc5aa07cc09f4838158067c6aa856ce9c5f85a770d3ca2f589f3a4b01f159386de7472e0e60cfbda04e0811696661cf1bc600924475474a67d9d667e996fb78feb08312885ebd1b3a8410f942c6fdc71c1f31156831a3e9acaecd103806ca4e8853414b3cd4fce6636faeb306bcbdccf52930ba9f1ee18c4488b1f22274be59a636eced9ab38f1354709753a79f046a02ab52ae52ae19ad41700821b1195530429becdc06f0a75c1e3fa5f1b722f7a1b41afdd52b2d54ba5752102b8a9d1f7e1c1bac0d501dc3062a3749ef434cc458a28892aedf934f49bd5e0597509fd1e13dea7960cfc84e293219a5ff434eab686986f494e1cfa819cbbdc969a7448ac14771d8077e21e71c464cc597a0ea10152316ff1c19c744905d9bbb30f5952d32eed98110a2c9de27c83933a7d31b076951adb09eb77e46d9ce5f643fe11707a7217f896e41ab0b8eb0755ecaacfc12ea4922b9c2d455a2cd857df82fddaab39dcddbecf1614b732c420982d5eb4ceff3cf01702b4ddacf5672392fe432ed8c76f50721bde0443e19963998d558bb528b2d1dfe00045fd49794d21dc2387f2de38bd052310e64c375b756dc2e9f30
#TRUST-RSA-SHA256 4a048ce15ef5de7d864a133f84be023ab78ec1f44f730fea5a2bf2e75688880b529fe7bee3234c95b92854b2a0d9844c1890f75eb3e475e89dfd69668394bf0e979fcb384987343d4aed26f2a99dff47468321b821a6eb67ddcd5f4844266e1bf575dcbac72647d9287385762cfc6d715a193257af3033cfe0d80aa4cc48c320a091c99f57ea985dff8e1354aaaca0aead34a7ace77147a80c956101b70518ff02f6f76afb9d5e66c2859648c70e7a94392008fafe10c6989491aafb212d792d42c570aa4e628b385324a7bb21110b8524ef65b5fef307aaf2fc3aebd8e547f1e30a33c35f02180cf1a5edc685549a58dfcbd516ded56198211e520aa756b3b70e070bf04defff5f58333e50e892a70c3ce52c32ff7fbd74f2dee2d9b47f36131d15d50b3ebc4c2faf63332e56d09ba8db2d0041b313d055142e17db958823b963a67f7c9c8261985552e2cb8e4b874952a34aa4677d75418005948f2a7b6358acb5ccb2318c9650a5cec24f19200a905d210988e476b8a0d909d917d3ee48439e67505941711a11c15ccff184f28c0f407f0547d119140b13c2998719fecba1cd7e71489c221ca4d2903409ad18b6aca65e0bb8bc160d9c13e018bc820ad1f949b3edd275a532ed089d576f8b245723101caf10e8f7128d9319f10f56c30d79e308a4481a896cb426efa1a93e1e39f3660cc4255dd1a1abeaabb553124b0563
#
# (C) Tenable Network Security, Inc.
#

#%NASL_MIN_LEVEL 80900

include('compat.inc');

if (description)
{
  script_id(180550);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/23");

  script_cve_id("CVE-2023-4481");
  script_xref(name:"JSA", value:"JSA72510");
  script_xref(name:"IAVA", value:"2023-A-0451");

  script_name(english:"Juniper Junos OS Vulnerability (JSA72510)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA72510
advisory. An Improper Input Validation vulnerability in the Routing Protocol Daemon (rpd) of Juniper Networks Junos OS 
and Junos OS Evolved allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS). When a BGP 
update message is received over an established BGP session, and that message contains a specific, optional transitive 
attribute, this session will be torn down with an update message error. This issue cannot propagate beyond an affected 
system as the processing error occurs as soon as the update is received. This issue is exploitable remotely as the 
respective attribute can propagate through unaffected systems and intermediate AS (if any). Continuous receipt of a BGP 
update containing this attribute will create a sustained Denial of Service (DoS) condition. Some customers have 
experienced these BGP session flaps which prompted Juniper SIRT to release this advisory out of cycle before fixed 
releases are widely available as there is an effective workaround. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2023-08-29-Out-of-Cycle-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-A-crafted-BGP-UPDATE-message-allows-a-remote-attacker-to-de-peer-reset-BGP-sessions-CVE-2023-4481
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?440316de");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA72510");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/06");

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
  {'min_ver':'0.0','fixed_ver':'18.4R3-S5'},
  {'min_ver':'0.0-EVO','fixed_ver':'21.2R3-S7-EVO'},
  {'min_ver':'20.3','fixed_ver':'20.3X75-D44'},
  {'min_ver':'20.4','fixed_ver':'20.4R3-S10'},
  {'min_ver':'21.2','fixed_ver':'21.2R3'},
  {'min_ver':'21.2R3-S1','fixed_ver':'21.2R3-S4'},
  {'min_ver':'21.2R3-S6','fixed_ver':'21.2R3-S7'},
  {'min_ver':'21.3','fixed_ver':'21.3R3-S5'},
  {'min_ver':'21.3-EVO','fixed_ver':'21.3R3-S5-EVO'},
  {'min_ver':'21.4','fixed_ver':'21.4R3-S2'},
  {'min_ver':'21.4R3-S4','fixed_ver':'21.4R3-S5'},
  {'min_ver':'21.4-EVO','fixed_ver':'21.4R3-S5-EVO'},
  {'min_ver':'22.1','fixed_ver':'22.1R3-S4'},
  {'min_ver':'22.1-EVO','fixed_ver':'22.1R3-S4-EVO'},
  {'min_ver':'22.2','fixed_ver':'22.2R3-S3'},
  {'min_ver':'22.2-EVO','fixed_ver':'22.2R3-S3-EVO'},
  {'min_ver':'22.3R2','fixed_ver':'22.3R2-S2'},
  {'min_ver':'22.3R3','fixed_ver':'22.3R3-S1'},
  {'min_ver':'22.3-EVO','fixed_ver':'22.3X50-EVO'},
  {'min_ver':'22.3X80-EVO','fixed_ver':'22.3X80-D39-EVO'},
  {'min_ver':'22.4','fixed_ver':'22.4R3'},
  {'min_ver':'22.4-EVO','fixed_ver':'22.4R3-EVO'},
  {'min_ver':'23.1','fixed_ver':'23.1R2'},
  {'min_ver':'23.1-EVO','fixed_ver':'23.1R2-EVO'},
  {'min_ver':'23.2R1','fixed_ver':'23.2R1-S1'},
  {'min_ver':'23.2R1-EVO','fixed_ver':'23.2R1-S1-EVO'},
  {'min_ver':'23.2-EVO','fixed_ver':'23.2R2-EVO'},
  {'min_ver':'23.4','fixed_ver':'23.4R1'},
  {'min_ver':'23.4-EVO','fixed_ver':'23.4R1-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  var pattern = "^set protocols bgp bgp-error-tolerance*";
  if (junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, "affected because the 'bgp-error-tolerance' feature is enabled");
  override = FALSE;
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
