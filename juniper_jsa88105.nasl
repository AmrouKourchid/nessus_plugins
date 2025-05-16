#TRUSTED 32d9d4ea80c9fcbf9bb1d97074e1908b0c4f16a0bf8bda0b56cde2eeba0bef2330ab6c287d9c8bbc409499ba6a30dc6ad9e07b3f86ecfba6dc00484c467ae339b86c4a28fc453964017168a23dd49ac208a93304e64ea47312413d94d43d04b935672451e0c09a11ec82491d61c69c68b061ec08816d89e6bfad63a032884b4171e5a8a3322761530a78c930c9f986a304fa8fbb7cf6cc48d1f087ed26719e6aae59d57d33c738172c6bf27002a54e75db92d9c4b9340a0314517ac22c279bac1f23b978ef0436eafec80a3fc6f4ba6f4e29dbb3970850c44cbb9bf2fe04688de034931b838a32476c8ad5fcc6808f942d855c3bd80137bd5060612a92fe20d0b9e78a96df9724d150a6ec3e70e5fff2528b84f9b2cd79004e4f00d140516412f9853753b5fc5fa8846525b58f29111474570ff2cda0c4784315fa81b7aac7748ae504f8be2ed4d64dc5a5d790718a64da29592fda810a35981e5496bc0eb5e7723632b700ef2b112960327b0f94d49c253aba9faaf1143082e321ea4d9cc5ae7a71ab71f547c71370b62a06db8f22e4016aee46bfa03fadeb83410ace9e2ee788f01efe3fa324e2c2f859a510eb8ad3a8107a09f0ea28c89b26ad4df22b78fcd3dc2e2b486b99240edea10e54a0e744c5fd946034196d7916651bbd22369910750217f492f487bc17c098c16ae3180e0d4aa02223ab8650d3126592b0c4157f
#TRUST-RSA-SHA256 77df0d8b32e8a0611dbd3f6eaca5e078bf2e464a4b6e537c0fd3b5176814aef392d7ca0a93ebbd23f4fb70cfc7bea02158b5d581e3c8b11ccce81fce59b0e5bd43f006f1cb060c2ec85fec9853950809dc74a92b2727f47377985a64f55fdf42cdddf5f2ec746e354e6c27a79213c572c44c07092cf4b83761ff00dc550572cf6589dd5c9e413292ec84b3eccd1e5be33a43e7b861823ee48660e017f82cbd366b8a394ee9f4014c2418a54bdf458787edd36474d0d17f5e1d8d0d00119e286abc4ead49ecb0becdc19e0538c7bf9d29043c35a66271fa82b7a49e90769c1d9ebf5cf08045c29143d1119e38c693728e768418627701d58f124b158911c0f0109ab4a3974298a35a8f5575e7712eefe562a22ba0792c704d9851f87afd9a749cfa148357617ba8bc178d74d1ca8be1037fd7f437e9fc0df97f0086e3041d5fea3f42a75165e4188b80444f6919e73b91ae728a4404c1838654f65a002489f025491d2129c301a325d95ebe830bf9c980802244ecf472175f1b9cc1c260961523a8aa085a93b9026aa1b6f6e8f09f5fd0e61a26b57f7de5daec5b054a8ef6530f6b53c660dbf53f88bbd61e4dff1ac1b3afa89818136691eba0892a1fc4f73f5a909b15c1decd974c40fa96408cbacdf5a6e65a8d1fec561c90b49ff81e99cb997f514c1292a3351c82ac742bd79651171025f190199e6f50c5671b60a9e14ffb
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210407);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id("CVE-2024-39534");
  script_xref(name:"JSA", value:"JSA88105");
  script_xref(name:"IAVA", value:"2024-A-0650");

  script_name(english:"Juniper Junos OS Vulnerability (JSA88105)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA88105
advisory.

  - An Incorrect Comparison vulnerability in the local address verification API of Juniper Networks Junos OS
    Evolved allows an unauthenticated network-adjacent attacker to create sessions or send traffic to the
    device using the network and broadcast address of the subnet assigned to an interface. This is unintended
    and unexpected behavior and can allow an attacker to bypass certain compensating controls, such as
    stateless firewall filters. (CVE-2024-39534)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-10-Security-Bulletin-Junos-OS-Evolved-Connections-to-the-network-and-broadcast-address-accepted-CVE-2024-39534
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3104ff1");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA88105");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39534");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/06");

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

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.4R3-S8-EVO'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S4-EVO'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-S4-EVO'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R3-S3-EVO'},
  {'min_ver':'23.2-EVO', 'fixed_ver':'23.2R2-S1-EVO'},
  {'min_ver':'23.4-EVO', 'fixed_ver':'23.4R1-S2-EVO', 'fixed_display':'23.4R1-S2-EVO, 23.4R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
