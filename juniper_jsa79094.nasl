#TRUSTED 60006da9df542a2517c8505cc8fc99a5c266d129f01c94385856b89c55ad8a3375fa4275d6c57b29e045a2b27d08d64bd80dfe4a8e9481539eea3e6acc05dc4583bfe38c91765db586df4fb933e5ea70a594206dabc0b1c6e1c091539836faf94d478eca4859851788ae39cd37db5c85e64582d0810f831384c6119bad26fbee38190520a6cb564487cd4799ce206a9a19aec1abf02185fe5de5e1a60946b63fb78a5fa83b60fb42bdf617644a3fd9e3721a6d9ff4695acb83891e30fe394ed100be1de6d579016cc23d88396a6ae84912bb0d0e34ce545b8a935f777165cb1f0d38d6b876627fa8273505f945336f9e9ca1a61318095b2e56ca1a9ffa9e91c6ba89f04923ca54c03d2db6df54d536e8176c4cae2a0984716018b4e471dc4b7328e7eb9528f91c1d5c880eeb41e646ae4440becac449004671bd589c8d905cfc34559e28b634fda6936bfeea160e9b95426aeeb5800f81e4b82cb7f1f66a7c290233b627bd31fd049b3f352a2c09540b205bb8cfe0834dcf6bc1c008b3d74c960baacb4aedbfaec69d1d8c1753e2330bc7661ba0a4ffebbd094dab1603e6261431bacdd8eb7d09328e2fb374cc3866f71dc77e411639439fd0c1664863968250bd0139555de26069a187577ecac1e97b230d714a420a9ddf21a1aeb1b5a318c795c4b511a874f205d61c300a847d861f8d999b0596694bbded612fd0e6be5e38
#TRUST-RSA-SHA256 72ccb05423e0a6e956752583195276c67234c49809de0dc7d94c247771a4f7b8e84be1bbb94d2b0914439373f4b6a9433e805c0cf9e31d9871715adccd7b7accd12a75cc69011a50bb526a897e386ff64955daa95a71ddbb10b4fb9488fbeaaf0fcce82a1f3153cfb7dd1b3f256c554f88aceb5b513d9647a09b0752233ff4456a88632c6658d9c23f98b08e177a4e39018dc2660dab9a17ec6231821cfd389e8a4392482590c39019742a16ebde64b563602d10cac4a7e836c036f0daf8b3145cc4bb22f89fdc7ac69782cf0e55b4002c25d29c88495440ec17ed7a9fabda2413f9b1e6165703e7b1a5a378d3150aa40890893d1f51105842ee7c7979ad4a10e842eac6a17e24b757db0c549bdf2e18cd1163d6143a5ec5f23e4b49f3254bd97998248cc16cbbb5b5348622640c5b3c2c89194bee2948f7d21bb2b48241958982938f79951b6825ed5ff55e3e85cd24d64d6414f3c3705e98c33cea6545e35f65acf928f7339c502c34a91611b7714c128c269ec1bae2eb9e5ff0f4f8059d51f8ad582e0e8fca7e93189ae2cf4390c45b325e52be9cb41bd9f55f988bda1054d11c6ddebe0d491cbcb241408ef7fb2eccba8571c51ddf13f0997e121a3d806bf545a16f6f10a5b61c3ca848d261b387968e4514228017e4f9418378d0e9900392d6ed10704216557afd634c742e8c562ff0602d8f12397c4012449941dd7f33
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193874);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2024-30394");
  script_xref(name:"JSA", value:"JSA79094");
  script_xref(name:"IAVA", value:"2024-A-0232");

  script_name(english:"Juniper Junos OS Vulnerability (JSA79094)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA79094
advisory.

  - A Stack-based Buffer Overflow vulnerability in the Routing Protocol Daemon (rpd) component of Junos OS and
    Junos OS Evolved allows an unauthenticated, network-based attacker to cause an rpd crash, leading to
    Denial of Service (DoS). (CVE-2024-30394)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-04-Security-Bulletin-Junos-OS-A-specific-EVPN-type-5-route-causes-rpd-crash-CVE-2024-30394
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8a28d66");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA79094");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30394");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges;
if (ver =~ 'EVO$')
{
  vuln_ranges = [
    {'min_ver':'0.0-EVO', 'fixed_ver':'21.4R3-S5-EVO'},
    {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-S4-EVO'},
    {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S2-EVO'},
    {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-S1-EVO'},
    {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R3-EVO'},
    {'min_ver':'23.2-EVO', 'fixed_ver':'23.2R2-EVO'},
  ];
}
else
{
  vuln_ranges = [
    {'min_ver':'0.0', 'fixed_ver':'21.2R3-S7'},
    {'min_ver':'21.4', 'fixed_ver':'21.4R3-S5'},
    {'min_ver':'22.1', 'fixed_ver':'22.1R3-S4'},
    {'min_ver':'22.2', 'fixed_ver':'22.2R3-S2'},
    {'min_ver':'22.3', 'fixed_ver':'22.3R3-S1'},
    {'min_ver':'22.4', 'fixed_ver':'22.4R3'},
    {'min_ver':'23.2', 'fixed_ver':'23.2R2'},
  ];
}

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"protocols evpn", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'running a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) 
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
