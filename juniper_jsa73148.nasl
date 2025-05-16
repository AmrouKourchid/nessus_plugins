#TRUSTED 916bac879cab423561a53700f88d878ac507e26465bbfd83dafe2eb745449ca5723b940ed4686f400efb0bcdf829529f7586f64712adfa6fe30da4aa51071d93cd6e796c42227d42bdb9732ee7906b4ba08484201d8b4e52cd24a81ada6780da809c04f3caa46c63eaf7a77cf25d9f4d054cdd0f74b97ce55ce103c0966c7c531372e86e997e536f8ef46393557e3d0a4235be64ebfa08cf2ae3f7aec8de5815554c2e86608ee8990194676a75b065039de8b2346d2fed4b71a26116ff27c8f62636e57123d3dcfd6cb0839ec19390d8ab36d4a7388b441dfacf4045cd18df02a67ae2b0fb42523efcd2574e772ed7a1fc8e023c14315c2dfe10e89cec355327f6603fec130d8ab2c4bd39c99c5c7aa9aa640f51b56e1944c388d1ba06e608e42605ec7bbd02adcaf707f9581c7d20bec11c3b5c878a150879e2a93847e1a3bc84400e0aa838cb43d1bab4ddfeab47754692201cf76530c0b8059ab468ec32a0205dc69130dadf7455117308189ea57f562015ae7a22654991b696352207f604832e0f6f2a9fe3ceb99f66179e6ade3c7f85fd192d649187eb3a6efca1fda16e1a14de878e8c12f44b6a9099513503f34758d42158ca644dc7035991d7a3216457fedbdb40fb2ae43129fcf30edf86f2464eb69ef72ee16d7de63f36574a550c9c6dcbb4a74f9c1bc7ec21b9bb0a50bc0e0149c2b26d7a86a73ceb84a9bf7af5
#TRUST-RSA-SHA256 23c16e3532da618464f1c5152456e7438802cb0cde47044879d8a3c18c8c2779dd19dab624bfab63d3803836662f27b4d8d8d5f5e8d5818b4fe543b160cb85ddb10f0b99a29b04f78e1949c6d12c71d94d4d83ea4614b3d2372cea9b40bab773ea13f74d28069a17d4caa2d501857c1bc8a58a4b74697f89f57f70e6dcc1691dee80c46a7fe41885d0b8fb7b685b2ddc093ed9d02c67aac9e1adf8c221c7dafc7a9f7262143154c62b6fd53636d348dce4047a651729d8e91d5dc22c4228c80a7a768de600b4ae0cb574d6fa810f6950c6a2dd609efe2284ae0c80c85b1511bd8cf074e3377745d562d8643afd654d814ea084b26c40d722e56a05af56278fd9bb9753f1196636a6d96dfae3b609b78df66e5147d2b88815fd36eafd55fc3d3b0818d8c0e4d74efcce90ca59df761da367bdf434e27e84e4eb0ddf7224528f637d4975fc07fefc7db10c0b445be4b157483ec8e2f1f2ee0cdff224ab04ba9f7f07ca9a4015829bf827659a34c9146bacbb3013492ae1bf1c14e37f7f93d9243449ad92ca28cbf5ca76f9400cc392ad40c9fff9a127ab5c481a380efec4bce97dc817d625fde8a017a4ec25ea5c71d844cd97708964aa3746284270a6bcd07a8e87f3e85cbf2610fa8a4b745a5e9136fbb12fa4cd0b776b02d2be96df4fc55cca93491dfe0686c5da5658f259bc454792b0c9330401753684ee8f2575ba3e82e6
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184167);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2023-44183");
  script_xref(name:"JSA", value:"JSA73148");
  script_xref(name:"IAVA", value:"2023-A-0565");

  script_name(english:"Juniper Junos OS Vulnerability (JSA73148)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA73148
advisory.

  - An Improper Input Validation vulnerability in the VxLAN packet forwarding engine (PFE) of Juniper Networks
    Junos OS on QFX5000 Series, EX4600 Series devices allows an unauthenticated, adjacent attacker, sending
    two or more genuine packets in the same VxLAN topology to possibly cause a DMA memory leak to occur under
    various specific operational conditions. The scenario described here is the worst-case scenario. There are
    other scenarios that require operator action to occur. (CVE-2023-44183)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA73148");
  # https://www.juniper.net/documentation/us/en/software/junos/multicast-l2/topics/topic-map/redundant-trunk-groups.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6842cf2");
  # https://www.juniper.net/documentation/us/en/software/junos/evpn-vxlan/topics/topic-map/sdn-vxlan.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f7abb60");
  # https://supportportal.juniper.net/s/article/2023-10-Security-Bulletin-Junos-OS-QFX5000-Series-EX4600-Series-In-a-VxLAN-scenario-an-adjacent-attacker-within-the-VxLAN-sending-genuine-packets-may-cause-a-DMA-memory-leak-to-occur-CVE-2023-44183
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?746f39fa");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA73148");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX46|QFX5)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.4', 'fixed_ver':'18.4R2', 'model':'^(EX46|QFX5)'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R1', 'model':'^(EX46|QFX5)'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5', 'model':'^(EX46|QFX5)'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S4', 'model':'^(EX46|QFX5)'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S3', 'model':'^(EX46|QFX5)'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S1', 'model':'^(EX46|QFX5)'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2', 'model':'^(EX46|QFX5)', 'fixed_display':'22.3R2-S2, 22.3R3'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2', 'model':'^(EX46|QFX5)'}
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
