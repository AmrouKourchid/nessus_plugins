#TRUSTED 4e5f775f584e8dedb7dfc81c38737596f618dff9c347ee801d91873773afa1e35a7510810d8ba85f273e2d33c2c46524be33a8f850f2a729431846301f6867bdd8677fdcb37dd230590ab7988d17a8fd4ade4dde4e41a482cd56c1e3393e3ac135130008651a55a5e51668956986c094a16711b45e67ad8e088e7e8a3aaa58ecb2eb710c10df9087ac38fe8d208d9248090d9107ebda1a6775f9c59367a7a176d8f7e421085875d7f7cc4bde0d7e4ddf99b65ba4a2538517286fcdfdead050cc30886ada7b64ebe4cd119151e24500ed10cd877ef599d2ad87f2d6a2f4f99bf96880b55b12e5b2ae8f21e57e4d59e403e2e847f5168da93efc9f7618733a83f1f79cb149427378151fdcc315784c4087aa6a4ac9cfaac0a21ec9579125c7e05bc741012e43323a4f5025aedbecfca199941f16dd35847eef2d31eb6f9487af1edc0312357738ef2f85db735119e16a278ccddc90d48cfb817cb1b3c0666975046871724c3c50a3be224e99ba23a6eddefb26ecd42467bbeac7a89bac46e6a19030a6243639ef62748e853fc2c4502bc1931638270a1812a9e70ee45e8d2dab915edb754d0fed508c1686be2444c7ed3da234759c631d9a8c2da8dfe2d8fdd690fe1e4cf3577515b53586ae2a6ccc7ed8e5d12a37af71ab8a3bfbafab872335da9399bdbc812786c23d1d4a47f5a1b535acff8c3404a8f2ec072113e8d681a3d9
#TRUST-RSA-SHA256 114425b7039de11787a88627f2a27251c4cbb3729b4b649c7646b0101872c4816f2c544cda6797db83c12fba42f6475a4f6efffaf96f780785eb626902768cc11ab125986547ee856604140b74e77037a4a7082b8d9a5da3fbc30cf18a05d064b83cea8c027f6ad3e98b6680a1f555633e1d42c06772c4a1ebe877bf43bf81dc7d478ec6c8131e768aae850b84a4d4cd984af2d9e490b68db9d663e13e5bb6e7f28656341a208941ddcf24a04f63ae39652c30ba3a1dea2da6ef20cf2042eea8dce6c59bffff3aae51f3dae394e9a13422a8980c0f2c470342464c48b7bc47c642cc290fe6e88a9364e585102073a039bcdc633942fee1936771f7cadfd225a15dcda61c37f57e057c1f82255e6a98400168d8ae214f2c34186044d013cf6232b1620eec99c2510cffb8b907023d999d8e30fa89103c9811ee9ce3337b51c6638e4a0ca5c6f217044ebe70e01713a98ccb8f460fc500891ffb83c8fb8eb6d9ae4f60e9e1f28e3102a16b94b50d22a423a3517438b02fc26ff0c50133d417aaca2a9982c80201ba9b7840cb9475233f001f348fe3f22be9e908a3a69617d6dc6c47738a3d2a54b11dc361b4da8fd8909b662178f1231f3325f9f285dfa004d1a769d0edc44d9b5bbcc5c807d6cfbb561ace2ebfedf3e2dc6bf840c33c425705a36d67d3e9722f443be5d91a3f60644b7c26b4142d946bb772a9bde2c9769b9b13
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195169);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2024-30386");
  script_xref(name:"JSA", value:"JSA79184");
  script_xref(name:"IAVA", value:"2024-A-0232");

  script_name(english:"Juniper Junos OS Vulnerability (JSA79184)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA79184
advisory.

  - A Use-After-Free vulnerability in the Layer 2 Address Learning Daemon (l2ald) of Juniper Networks Junos OS
    and Junos OS Evolved allows an unauthenticated, adjacent attacker to cause l2ald to crash leading to a
    Denial-of-Service (DoS). (CVE-2024-30386)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-04-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-In-a-EVPN-VXLAN-scenario-state-changes-on-adjacent-systems-can-cause-an-l2ald-process-crash-CVE-2024-30386
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6d626db");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA79184");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30386");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/08");

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
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S8'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'20.4R3-S8-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S6'},
  {'min_ver':'21.2-EVO', 'fixed_ver':'21.2R3-S6-EVO'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-S5-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S4'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S4-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S3'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-S3-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S1'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S1-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
# https://www.juniper.net/documentation/us/en/software/junos/evpn-vxlan/topics/task/evpn-routing-instance-vlan-based-configuring.html
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set routing-instances .* vxlan vni [0-9]+"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
