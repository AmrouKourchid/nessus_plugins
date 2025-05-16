#TRUSTED 53533f19b24e272a3b9002b49883565c29c100b90a64d36d51e43fcf1f312f39919b9a6df1fa754348842b46c5c9d69ab8052ee0e87b61e4d5ca2d31e6fe6940ead938b4668444908ad90c18e85cb626728251dcde6182287016b485098293fad40f24de0ac3f15efdeca4cf0ef066b4d485ce8217ba1515fd7508975cf6e7675687111bd39ab7c5dfd4bbff7b1d8b22073f5eea7cebaf64541f0953bf7579a02ad450e3994fe8b6c71771f8802f0e1f60f1ed7c9f6f77b815b530cb898efdf20ab963828a570d50b829f2a765f6922d3afd6806699b6cd3716eb451df5fe8c453c55c2fc7e6baa0cd820d5d39723a0f8aadebc1fb2099dce95e328bb2261343a9d4b703516f4ea778a171819cebc12dede7e9333d90e2f400e787f982a1927ae228d457ad59e1b83e9892acf58cb34e5809b3f3c840a90f2182606f67ca105dce5e58ae147d8a6f3f174fdb971c0cc0aa70e168c580419788016e7a287f3cea6c99173be866c474467ff540fb6ea5410576e93044ce8755cb36634b114d03c9bf92ac463c6d24bd89866f9ac72ddb8d520f1318801bd5b3d19260fd7f51adb70efa3bd4663381fb83ff5382aeda4cabfa4e2c4599fec35e590a8f07e1339af5b881be5b1bdaf846daec48f2835ebaf8088a86e84fcedb15946d4ade2eecee1d75a89b4705f0012d9806d600d61dc3031af9e6872d154d59302bb147d25ee0ac
#TRUST-RSA-SHA256 80ee16e4bd73ebc8e325a791dff3c6c18df2265560bb866106ce48af896882a52359d71c261cac0bdab4a81f26d87eaba55e7426746c1fba7a2e9007f845fe875efb0e83750717795d85087c74ac3781a07070dd200a05477f7dac66a0b242ebd344fd020659295edeee083f14a8bc5ec0816e2a46fec1dbe42aedf5bdb5edfe144366089bc7e5e38f97162a2d0fda4d6bef3ae93da59725c4bb7156e93b64eb67ca9379f651bdc669ae6cd142e314d8ff431021fccfdff9caec836b4996e17d111fa2f9f531eb0e0c6024201ecb185d0bb48113a141d3d79162be47cae59130c21681a5d84608a328912f2b9a94c5535ec8e0649eb06642138dfdcaa833fe4c3c215664f510a0ea586bfb8e74504a3b4a13b1d8690c57ff24586a8ee5c4667aa2b9ec6f613e09b12c2178b56defa1e40ec1ef21f4c4dc36d16ed39fb5081f44f7c878f0b04e071687a3f99b0c480b207b022d8d1bde6841a1d9033842564816b130f97ad0bd030055422292161ea16f0a975d8fae8030a016aa76e47ec626ec434e7ebeda0b2b4ffd8206afdb676ca085914da72342e9f14e12b62841755290a8602fecf959600dd7bd44c0024a6e6887ed6c68fc3e2933f728d27ebc11490be8fdd7594a7f4e22900de18291005544d243c60a78803a6dd0460e5bd9790b93a31cc62af51c5b270f40f89e3b955f9b9065686793fdeac65e035adcfdbcd416
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148682);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2021-0235");
  script_xref(name:"JSA", value:"JSA11130");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11130)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11130
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://supportportal.juniper.net/s/article/2021-04-Security-Bulletin-Junos-OS-SRX1500-4100-4200-4600-5000-Series-with-SPC2-SPC3-vSRX-Series-In-a-multi-tenant-environment-a-tenant-host-administrator-may-configure-logical-firewall-isolation-affecting-other-tenant-networks-CVE-2021-0235
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5fa9851a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11130");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000|vSRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.3', 'fixed_ver':'18.3R1', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000)'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000)'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000)'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S6', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000)'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S2', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000)'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S2', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000)'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S4', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000)'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S2', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000)'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000|vSRX)', 'fixed_display':'20.1R2, 20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S1', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000|vSRX)', 'fixed_display':'20.2R2-S1, 20.2R3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1-S2', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000|vSRX)', 'fixed_display':'20.3R1-S2, 20.3R2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R1', 'model':'^(SRX1500|SRX4100|SRX4200|SRX4600|SRX5000|vSRX)', 'fixed_display':'20.4R1, 20.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
