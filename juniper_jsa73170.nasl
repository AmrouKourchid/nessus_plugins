#TRUSTED 629ef8d8440f872e084ad58567c5cf3e27bead0cd0e5200efc76700c09f887746cc806a3fce8a0861f9b1a5b9d41881e9033075009e17d7b0c83f00e3c6553230a8056e9f5b9868c647dfa03baae1101a5a876b725c4fece891f156f708f7751273a8cf9220dfc499c18231ec489fa8f032cd2f9baf81475d45b0d2f5a999fb786a4534c78e935cff2a04e4bb241ba264a7eccb4053bcab23abafb41033ff9a50033d0a7cd12bda1a9726266ee4390f7b51f8ed241aa9fbf84ce965d3042b4066400671d4f89c34baa3ed6035517e520034c64a0a3c36c3de0c0995024d8d2bc6396b1b4309654c26fbd44c984fc1ef5af6b2e0900b67b662f0e0279cac0e7ec0478c301075c3e8af9e111cec13be109bb18e1bd100ecee28d6d09ff2c1efa7415cce38ee1d1ff0e0d2a362286541b4dd2d66bb2976738a20392e467b04c9cd60f8692a66710b20cdf131cef02d7a32e9b687a8dc0d690b7a8675077ecc25593cf729d46948d6791c07524f2f3d2e078c841bac59b08043872bad5dfdf975488c4d2f12da025e70b30077c0654b9dfcdbc6db5038c6463cffd81149370bdf7fc08120f356e9328617a7b1aed499258a17250989909ae0fc40ade2bf9042f771f90a7041aed33d017abc4a756cfaec773087572ae04befc65fcdbcabd39877bdc469a19f57ab3333764598fd93c0ce54bd79ead628e3dbb459cefe76fa619ecbb
#TRUST-RSA-SHA256 34d849de0058fcc2e1f84f2ab9e94c7f05e8c08f07d47c1b22771c1e4a097aa079604ae21f35178d4c29e129cfb03960f9808c2887e7d869bb1d04c1fab1c107dce42fbc14b26bba8b183d776a26ae26a81a26c7c39112b837dedbd0490a215fac4f8f885e4e10dbf128e0b748f227a21df79c94c58042db27f865b4f58e39bc79997da6b59040f84a689fa22fb6bae3173486ef27e70d44d02f6709e5e34eaf2fa795ba3546a01335f3c2d287006c0942d474c3f8a2030a8c46c057084201e5676a1a4ad0faab1db28cc905af30f1882a40e450545d16a8a0f11ba2ca1636f0cbe4eaf8c369b5875af21812c69bf30d09c440c050f8dec20574cb8c7b4353bfbca502389a0520e9c197d1041cd971878f737a537e0c87b87931ec4f832cd19d70b745905f7c9193ff490c46eee90e6e53cf148b010e3d2e24b965166809a86d7fca578ff33d196dc921a5c4454aad0d168c4d69b63d515b328a2c0f5425d565c062f1a9e64e3cd0708ada1bc36f042343c6d5686290c14fb2065cf3a639386bcc124bd22ef35f8531cc40aa24385754b139142b8593d46ddf417ff349c575c81ec6e1c628aa35bfec9de8233834ee3566706e6d5170dd87ec2dca95a51168229187084a053f1712bd1faec3c4c604ea24cc004da826f02ba4f0d2e0ea78c97dcf463d77384975f086420b98189bdd07955c8a4ea6c06d686bf4783b498a38c2
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183961);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/27");

  script_cve_id("CVE-2023-44204");
  script_xref(name:"JSA", value:"JSA73170");
  script_xref(name:"IAVA", value:"2023-A-0565");

  script_name(english:"Juniper Junos OS Vulnerability (JSA73170)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA73170
advisory.

  - An Improper Validation of Syntactic Correctness of Input vulnerability in Routing Protocol Daemon (rpd)
    Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated, network based attacker to cause
    a Denial of Service (DoS). (CVE-2023-44204)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://supportportal.juniper.net/JSA73170");
  # https://supportportal.juniper.net/s/article/2023-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-The-rpd-will-crash-upon-receiving-a-malformed-BGP-UPDATE-message-CVE-2023-44204
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5832e7c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA73170");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S4'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S5-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S3'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S3-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S2'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S3-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2', 'fixed_display':'22.3R2-S2, 22.3R3'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S1', 'fixed_display':'22.4R2-S1, 22.4R3'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3-EVO'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R1', 'fixed_display':'23.2R1, 23.2R2'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2-EVO'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set protocols bgp"))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

