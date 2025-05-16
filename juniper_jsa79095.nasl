#TRUSTED 6603eb58994f950090333aca01237ae2e690826aeec713b1becaa3ddaf54fec372296084d256d6fc64cc5915bfdd83f4921de46e8205ef18806f6b6da6e77c9742e10b91b6e89987f29bad30daf93d1939db190fe5fbc25c0dbf11ab624ab5f23359a85f8232c1eaae47fde5433be229d5777d4a3be6722fe9e8701905756927eab7e6baa8fa31f939607a38c1adb7c283fa0610edc0bd08a23e9a546b0251efbc7cc9eb6fd076178d52b7196fbbaa50e28fbcca904fcfb53051c3097098671f5c62c540a2dd3c9620a3636637db0213d3be889729dc85a94befdb51b0d5a59e601c32bb64c599c9d0802a38acf305639a839dc1e9f308dd4ae2ebb932425a76a6c7b11e4386d692a59c3ef65b0bbb1cf6d33164e255457b40f53c4e9de55eadec5c658b02f97ef01034e309af106552e156f2afc1c9e38ec784c6b068e1346d7653182543e68f74ce2164b4f44a1bc2c0cf010497b9d18d557a60202ae30c91b8e648757896c2f60cf4ef788709ca64f7c76009edd9e17c81b5fdc9334e28177d4197a70cc185b05ed85dbc33b6238e1b7a46dd5a62734a70e92d83d095cb0c773b2c4ec3a3ea7cb3cbca2c49403402cc68dc07dd733870dbcaf4c270152ee12b5b452ba5ce3cc7fb969c3614eb5002ef6ba7f845cdf6e86f561b2173f2b45782d9b151ce6fc7307880e36965ec36ca149c6e372b2b7c3052d9a6f084cc3bf6
#TRUST-RSA-SHA256 71d8d5c9c64fbfed189fbad6e0d19f44382e5b18395dbd98b4f0995de13008e4e9043a689d9c4e29a9a9b727b816340a3ecf09bed5582fbe5cfd54b01f6999a235b77ff8147b775648cd2184d693cfd48e667c887216518768a8ed70f0e662eacb3ad13d2911708915f7ba8c2d3c79a43603ae52a32d3260464de47b3a81b796f36d1a2c236eb04892d76dca1449a5a67e3822f91c402a4ee16d31c7a496338bcd2eab929c5c3181463539ca00bc9b38800cf68032aac0119d2db89f19fe027525175ca630f1a0c70e87c7592bbc61d0f5f0a26af86f47dfcacf3cbae44a07ca5ff99593baf280d9110426060d5583aa4bc12d8cd5390ca8e74086a2737a6789ba48154d42f7d4bad1ed62870bdf0b8d3fa495b7799496a2135974e9b5bdc389ebe81943d1206c5dd1789dbcafdb4467f3be864b5b55615d5f9edc850ea6f75146cc4d5217dad7bd3547781f96da4e87bf7ae7b8f661a6ddb2f7d15f0b1911bb707ac86f2e0081079ccbb077c5b6f811e87a1d558ea140566afe99ced2f7effe66b77781ef375d35e962fc3d5720220fdbe20dec722dc44ea7f4b5ac498e686dce298cfa63764e4116a91b3861a5b35a396c601f28781e967a2c27d5e0836120430c56caf7e487e796b0e827fe9fe4673bb2b9dd47642ebb4718ad13dbcb3ab0950d2cc43eda044fa8272bedf0c58e7eb0e36551c1b34aed0f1bafd436409b40
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200181);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2024-30395");
  script_xref(name:"JSA", value:"JSA79095");
  script_xref(name:"IAVA", value:"2024-A-0232");

  script_name(english:"Juniper Junos OS Vulnerability (JSA79095)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA79095
advisory.

  - An Improper Validation of Specified Type of Input vulnerability in Routing Protocol Daemon (RPD) of Junos
    OS and Junos OS Evolved allows an unauthenticated, network-based attacker to cause Denial of Service
    (DoS). If a BGP update is received over an established BGP session which contains a tunnel encapsulation
    attribute with a specifically malformed TLV, rpd will crash and restart. This issue affects: Junos OS: *
    all versions before 21.2R3-S7, * from 21.3 before 21.3R3-S5, * from 21.4 before 21.4R3-S5, * from 22.1
    before 22.1R3-S5, * from 22.2 before 22.2R3-S3, * from 22.3 before 22.3R3-S2, * from 22.4 before 22.4R3, *
    from 23.2 before 23.2R1-S2, 23.2R2. Junos OS Evolved: * all versions before 21.2R3-S7-EVO, * from 21.3-EVO
    before 21.3R3-S5-EVO, * from 21.4-EVO before 21.4R3-S5-EVO, * from 22.2-EVO before 22.2R3-S3-EVO, * from
    22.3-EVO before 22.3R3-S2-EVO, * from 22.4-EVO before 22.4R3-EVO, * from 23.2-EVO before 23.2R1-S2-EVO,
    23.2R2-EVO. This is a related but separate issue than the one described in JSA75739 (CVE-2024-30395)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-04-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-A-malformed-BGP-tunnel-encapsulation-attribute-will-lead-to-an-rpd-crash-CVE-2024-30395
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87d4d939");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA79095");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30395");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/07");

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
  {'min_ver':'0.0', 'fixed_ver':'21.2R3-S7'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.2R3-S7-EVO'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-S5-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S5'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S5-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S5'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S3'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S3-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S2'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-S2-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R3-EVO'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R1-S2', 'fixed_display':'23.2R1-S2, 23.2R2'},
  {'min_ver':'23.2-EVO', 'fixed_ver':'23.2R1-S2-EVO', 'fixed_display':'23.2R1-S2-EVO, 23.2R2-EVO'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set protocols bgp group.*neighbor", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
