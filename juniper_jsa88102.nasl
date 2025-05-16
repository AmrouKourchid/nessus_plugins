#TRUSTED 4365892e590c9f6f7b59e0c6be94c6d404a2f230d2e4608cb19aa24c867e8f3a93308637c5bb8bd228b96e562e86cfae70f7cc4eccac673eeaeeee39547cde8c81be8ab5a026a5dd0ba646e23628db296ae55f6a3dc683c296acf829b563e74df0e4bce1eb24cb74ce13a8a71ab1b7042f5b8d1803670740161e7ab7529492a543901fd81b2e6ffb49bdb1d9bc481cf22564383360326033937e33eca39447e6d0bd174f7974b33018fbb137b2de531dbae2ec04298475118b17316ad8b13950951946777601cda66e3a74703d945153086d8b217e0b2035a1909a7ce8b3d6f84601649954f7af6c865ef8727100a3a5a88d5355fcc5d2e868cda20e70bead711ca637861afd18f0a2eb70e9f316b6e2c50e285ea2cb74b64e4092587bedb0266c198b881eeda1128a943d4cd6d5039a6661408879b84ec6221fce4cb5ec1b50144b2f9bc23f46d268a74da9ab75c355a3bcf312057e2e1984473589e52e801222013fbd012c6875a902fb8b1610e9db04fcfe386519b2b6c8de91bac192dec0fcd3254452ed24a33be5bf4f0444e701092a5a080c068aeabbff3db3fe3382d49101614a3efa95d3c3a6388b3eeb69b56c9bcf16dd0a798de32fa29c0940f73b260eddfe9a7d5f2f38e58ab0493753739ff663e3f2e6fa4eb43055a8b17a5766fb17319a80685b6514357b48ab28d1c84d54869af1ec888e8d6dd6ed8442c394
#TRUST-RSA-SHA256 1772df1cd7452ff24aeb2d24da9df31d3445f7a143f079ae8024e207f8b64d723a8f493cb80eaf9a45c648f3696abc0be7bb1f75dee8552eab7edbb94d4995ad5a91ae9e2833df29ae2a8e86b96219a3d4ab5b8e237a40d670dffa5b646f02b336bc614e4d0957551ff405bed128916546899ee4770db2c7d51de974e49136e149c4e58a895bea61060e06a0a52d2895145cc02e0af6edafaeeb6a06521517e2b7d3d62ff167d30e69b0b68700b02915dfe924a3f3e7c62bae78f2b3a9800fc4502c29433a47bce3f1630ca48f646e2efc66bd895a5753230417e28858acd28f348065d352756c3d57c99750cf70416fcafba57bfb09d4ce1a76c54f0e32085d72198ca448e5bae6084edd5b0ebb18cd8f2193df57681befd0b1cded9d8170bbcb93a71ff2b74e23621f6edc980b9c6734e605ba71b1a659c968f8567b55f29ae42b341f041279b3c5344ae5252fd8f1cf33e8c7a978d0540d80e5401241c6d7cf8eea0cc51498cd7fc6a8ab68b9853b8c7eff3fca2dba2cf2f3e9ab028a15ba348f070d59a2e73f8bc6b153b4475f610448a74694614af5b793d35ad6140ab2cbe296a72e7b81fe2576f53fe4bb6b517ce9e14354ff5a533584ba825a9f71fa9f4412b09edce9b6fd761d78e1b919378a23407d9791aeb83948003ec13c45f0c42d01b762888bd349aa9d5ca7e3640f3a7b82278a60c22c9b34186e863dd5d3
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209273);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id("CVE-2024-39525");
  script_xref(name:"JSA", value:"JSA88102");
  script_xref(name:"IAVA", value:"2024-A-0650");

  script_name(english:"Juniper Junos OS DoS (JSA88102)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA88102
advisory.

  - An Improper Handling of Exceptional Conditions vulnerability in the routing protocol daemon (rpd) of
    Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated network-based attacker sending a
    specific BGP packet to cause rpd to crash and restart, resulting in a Denial of Service (DoS). Continued
    receipt and processing of this packet will create a sustained Denial of Service (DoS) condition.
    (CVE-2024-39525)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-When-BGP-nexthop-traceoptions-is-enabled-receipt-of-specially-crafted-BGP-packet-causes-RPD-crash-CVE-2024-39525
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63aa98ec");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA88102");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39525");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/18");

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

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'21.2R3-S8'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.2R3-S8-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S8'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S8-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S4'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S4-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S4'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-S4-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3-S3'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R3-S3-EVO'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2-S1'},
  {'min_ver':'23.2-EVO', 'fixed_ver':'23.2R2-S1-EVO'},
  {'min_ver':'23.4', 'fixed_ver':'23.4R2'},
  {'min_ver':'23.4-EVO', 'fixed_ver':'23.4R2-EVO'}
];

# BGP must be enabled
override = TRUE;
var buf = junos_command_kb_item(cmd:'show bgp neighbor');
if (buf)
{
  override = FALSE;
  if (preg(string:buf, pattern:"BGP.* is not running", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because BGP is not enabled");

# A BGP peering session is established.
# EX. Peer: 192.168.40.4+179 AS 17   Local: 192.168.6.5+56466 AS 17   
#     Type: Internal    State: Established    Flags: Sync
#     Last State: OpenConfirm   Last Event: RecvKeepAlive

  if (!preg(string:buf, pattern:"Peer:.*State: Established", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because BGP peering session is not established");
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
