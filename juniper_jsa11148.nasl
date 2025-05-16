#TRUSTED 9513377777c0723fe77413673c89b06decf6a425f697891c54773f67c9a414bcffa778997afc76a230837d824255c65866890c08ae5eb40d2c042e6007efbf560509c4f95ceb6ba10f581e2b4581e26b1d411ee71a14eece02a9fd429a3ca020b7dd1697c53655444de349639d2a0cce82e252bee6e019ab4c3c42854796c77785aef9736b295113d42357419bc4faf57301f661f5b5b9d2d542e8db07f53448c2020e67c126d9a773f504b6f1b30e1c972e2df8eeccaa70a5d51d56bce395b78391197e6e5000890a7b91e25dc332d8964f9628c73a7bd499bcd013e698b359ee7ad2ff8f606aa3155580300783849afd20dca995af607122438d4fa5270132f0e14250253b77d7e9034ebe5dfe6bb2357c0d659da5894fdd2b127f68eed3bc61d719a2480dbffe6af6f299123bb365b6cc5d12aab5faa7d030ab8f055e1db1583b30faefa781126baf4956967e2700021d8f6152a3d7b7e1c722e4cacd34fd07c0adf5295ad71174a403ecf781f6c7debaf48aec58ea4aae8860d843ef98f449dd4333fc316d161304e32d702aaa9aada7edd301b646f038fa798b201c356c00fc9ccfb43eaa2cae509fb0c95a28c8146a74578cf6e9db71cd31202aaf13cb989976f37833873984290f2c585f1f5000fb402e7b22d6fbfdf33df3637c829a8ac7bed727b37150e441e4ec403b5a252ffcd05803a3479a1732189130ea05f8
#TRUST-RSA-SHA256 57fe7cc9d8b2af31ea706b853ddce0efdba5676115417f3450f67e334d4a65c4e1b7e8011e8bb095311537c7d3218bcff299030a0bb46e549e92a8c2009e3ed3c28a916384706bbd7d71f35f138e15dae607ffce316618c2cc519060efbbe6ba89e3c67516188b0b7150d08bb21c06173bf21dd58dc510dd4adb51b47b14cf9f3b979738f99cea5ae4d0eb504a7efb7da3a7744c0f0e5e6742aa5fb5204dcd1a0db6eefb340378f9921ef784f974946e684ee7560b72466174f9461dc02d139d186e462a6d93e826a35e06b8978f780840bb17ab678a5043d37a8e2a67436212150488cea798492d0cfd29232a9273afb55604d3aed75ee6012c4e223bc637a8fb64b12361deb496986eaad7e1bd6c724bd4eb8027c71139df743d2a007770c2bf09a74ea38cdf2e25ff3f302068d23cd245730457816b940ff246a3b198fe6f4ea5ab38fe78507ac1fbb64096e0e7c2c9bd64550ea4d26960531328d96765dcbfe099ab316442cce4ac3641aa446435358db2eadb75993bd452fde68e835ac6a16cfd9707586c6835c98f06153b008e2ac2db06d9da27f0e45fc72bd6f775dfc60aa4d23d801055a94967f7b4938ffec73d66deec21f9b4585df11f6270718f74d7a82e7e87c4ff6c25d20944100f44ec114dfdc1c2dd928330321b2021d60d3abbb1ba978cb31e85cc70b6e367491c44b480abba269c0946960903e8b4968d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149366);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/24");

  script_cve_id("CVE-2021-0257");
  script_xref(name:"JSA", value:"JSA11148");

  script_name(english:"Juniper Junos DoS (JSA11148)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced in 
the JSA11148 advisory. On Juniper Networks MX Series and EX9200 Series platforms with Trio-based MPCs (Modular Port
Concentrators) where Integrated Routing and Bridging (IRB) interfaces are configured and mapped to a VPLS instance or
a Bridge-Domain, certain Layer 2 network events at Customer Edge (CE) devices may cause memory leaks in the MPC of
Provider Edge (PE) devices which can cause an out of memory condition and MPC restart. When this issue occurs, there will
be temporary traffic interruption until the MPC is restored.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://supportportal.juniper.net/s/article/2021-04-Security-Bulletin-Junos-OS-MX-Series-EX9200-Series-Trio-based-MPCs-memory-leak-in-VPLS-with-integrated-routing-and-bridging-IRB-interface-CVE-2021-0257
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd4735b8");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11148");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/10");

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
if (model !~ "^(EX92|MX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S10', 'model':'^(EX92|MX)'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R3-S3', 'model':'^(EX92|MX)'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S7', 'model':'^(EX92|MX)'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4', 'model':'^(EX92|MX)'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S6', 'model':'^(EX92|MX)'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S2', 'model':'^(EX92|MX)'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S1', 'model':'^(EX92|MX)'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S2', 'model':'^(EX92|MX)', 'fixed_display':'19.4R2-S2, 19.4R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R1-S3', 'model':'^(EX92|MX)', 'fixed_display':'20.2R1-S3, 20.2R2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1-S1', 'model':'^(EX92|MX)', 'fixed_display':'20.3R1-S1, 20.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
