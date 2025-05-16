#TRUSTED 498885955c7bdf131b70f5b531effe4db9bd08c482931b3a18392e17b444655321f1bfb53e6d814b3aa8214a53191c9437e34637466272c58ce48e4e9c1f13876b37849373791cf75d9a00fb6100c0bda4d73692e2aadb14de42c02442f2ec0b6b541d61c294f3113bdeb11030166a8addc7570f2f97ef9a82c427959f30f2061a0eb99e464afcb7844bc12cbc8fa9f34c37fcb92fcb16345c518085311358872bd87c7017f2261b515c93ab7584cedfee4261116a3b584315d9b839115513ca94ec10308bd725d21477302ca1d081fd38e84b9180d14a89765db3f5553e43308c1b1567ff0593c7a28982bff15d8496cfc31e0c8e585fe617aac8e715248b39460c6252cd7ea28c23f6f8dd796031b4b38b74e5a59ca1b4f03424f0f9458cb2ef6a8e65ed31ebdeb82a8a7b4e1280586ca84a87f25a0569d3c36957149ab8bd1f13c2e6f183bf2ff60224f5774fb1a8de47780ba809f81a17d1c056aad8ce73e3e1d007b045088013ebf400a4eca0f6e470e07fd161d070dc81609b18b6bb854e789ec08d8e33d1e16230e191324566234400e0c59573f1c2896ebaaead85f2e7532449643da44671299ee804c6f384c27854b70728a2cf925547e9085dd4b16682a74e9ba5112513dbe6cf4debfe6d22ada7eb0283e189e4077dd7ede11a35fb2b71b4a1408c4fb61481c79cb19585829404beeb96e2474799e501d1c06770
#TRUST-RSA-SHA256 ad08bb994e0b75de431c62ccc345a7ffc471de7b75c224f554e84f0760487d75bf791d504ba8e3bb8e158492a21585bcab6e19dc1930a16cc96fdf5cc7a8e19164c4d298e99102362a3915a9e39b27c514e75d68293496042084c4b1b25f09225c4595d8a8751b81d179cf59a24bfca8902222409c951391bc30cbd487923fa45e70070693de4307be65cd0d1838d1d232f5090695b43d43a5dd61bec1a9879faee0eb8a4f0ad93a8d7cc12ea183916af058f4ab765d89fb87d938b8473748e580bb3f5cfd5bbfd56246f08114a28d9b02728e1e957c63f90242fad5f86671501cc753b360e04cb400e0d9d5a483a11a6e5ae2d44a31441a0c50b5fe184a76c0f60e8b264ed693ac1a1c014efd6c02aa317ddb0ea1fd88dbefb958ac90db11e0ee1396e842ea1e8c4b60782a20a81ed0267f896831ed9548969f625957d955e2f2541632ac33a2c66de8a6e4a4814b4f6364ba827c06836aa8a89feba6edd5ea9494f4c73041ce2426283b3ffd36cfb7f0914fb0898a450af85913f517bc7e0662d68329b9d075c509aaffa1e5282afbadd4ad0820c90635e9301ba364297e32d661391869fe14e442288bce337d0b989ca5c98d20ba66693abf8000e6474332d22487631b82f3531653857662296ac94802df5935c138c3d60a150f7e0e938d2f2938397de5dfb2c0861ac658baada999140610ee8a1a938d1ddeabb72d6e3a
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183962);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2023-44185");
  script_xref(name:"JSA", value:"JSA73146");
  script_xref(name:"IAVA", value:"2023-A-0565");

  script_name(english:"Juniper Junos OS Vulnerability (JSA73146)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA73146
advisory.

  - An Improper Input Validation vulnerability in the routing protocol daemon (rpd) of Juniper Networks allows
    an attacker to cause a Denial of Service (DoS) to the device upon receiving and processing a specific
    malformed ISO VPN BGP UPDATE packet. (CVE-2023-44185)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA73146");
  # https://supportportal.juniper.net/s/article/2023-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-In-a-BGP-scenario-RPD-crashes-upon-receiving-and-processing-a-specific-malformed-ISO-VPN--BGP-UPDATE-packet-CVE-2023-44185
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f962cd9");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA73146");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44185");

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

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S6'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'20.4R3-S6-EVO'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S5'},
  {'min_ver':'21.1-EVO', 'fixed_ver':'21.1R1-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S4'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S3'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-S3-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S3'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S3-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2-S2', 'fixed_display':'22.1R2-S2, 22.1R3'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R2-S1', 'fixed_display':'22.2R2-S1, 22.2R3'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R2-S1-EVO'},
  {'min_ver':'22.2R3', 'fixed_ver':'22.2R3-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R1-S2', 'fixed_display':'22.3R1-S2, 22.3R2'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R1-S2-EVO', 'fixed_display':'22.3R1-S2-EVO, 22.3R2-EVO'}
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
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);

