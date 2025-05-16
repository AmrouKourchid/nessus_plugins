#TRUSTED 708f3313498a785981d4c57c4f83dd84bdbaa06b332af8f73e0cb33891dc45b9fee67e0eb79ef481c5a4f8f658f3e9d9fa7b8dc0d1e90986d6eb6fbb12e70624a54125809180bb8b04e4c923a16ecabb68e10e886cba48e52f058835e76a0e6dd549b280a9742cbe5c8cf39a57e376c4b8c99f916818dbf5d8943c81ee077c549464182b324dfac16af8ce44adec3bccb6ec8897fcdaf27d806cab9e5e333f17a01d7e73384e2a2f15191eddd3036eb98d2adf8f1b8c45ff7b7bd68017c14134c0a6756de03fdf07522bf7d6abffc283faba2a2de4eb36ed35e5b83225eec311d790da595ec5eabad82be0f4d2dbc1668539c84ca52ca7634796e6f0f31e901b4ce5309f337d06996fa8863b11e8f96026e264333408d82d3633f1d2f4a8e304e420b080d2902387b73a3edd732ee66a89b5d9349b5eb4d25c6348e9cfd97f131a288141826d86d24141377f041ce4c7f10a940e8ca815b9500a643ecba640f472b3da5a56ebea6ecd46360dee9468adf3c0ac8e08e7f96f41c4e5fb6b2e1fcacdf40fcbb970867735ea766066999612226c3a4fbc15567b1c216ffee5a9253374f6fd523c18820695ecf50070fa126919036f7b48a404eaa5f06ed55f674213aa52df022cc16e3b0cf9096ff88fd0814b6eef75e28ab21a568a62b674eafa7868d91c3c4a6862c206630169835f97d8eaf4a3005263a6ab528bcb3a8aa9cff0
#TRUST-RSA-SHA256 2b72eb9f2dc7f161faebab4940f7e47420e46b95a533db035d52f2b727b411cf4ac7df8039d819e052c59b166554aaf52764fbe09dfb5736378a4d822fe49e462f6a4cb167509fd1932d998d154c33501256a9fee6586590cbd3ca2d0d3fce5d805c33e89f722e097b2abf1f3be136c4afdabacc882830068c7252607e234aae2491aabfa421ebdf63333179dd54acb0e9c2ec31b04c4c268ffd0741ef1cf1729712212685c249cf6e32fb20b01c8ef1ee41d62f133ba229cf808c46dab41780db14f3f9f6e6be1c1a93563d34b109c8ca158277131c28a8017d6f81491e3656b33523934e1f613e2cc944f13dd48342e98cffbb9b84f717ef97c3dcc633c58c4d3dcc60baa92065394a2130c656e6b573ebeb35d07372889bc8f0be4ea0f4e49be390c4f9bdff09a37532b351911e1b3010d4f303837f4c8a23e40ebc0a4b8a225b71eeb8e5ee2f5f4ee66afe3635ea7e6039c25bc861eb84dfa75a62912ff027a5e0f6478160ce5ca7f65841c161cc297c397317119100c1b38e0a3e58871fe2faaff2cdf73ff3b1602e2acaf1008a815678164631c586dabaa6fbf34a9f85ae4c97c8ee07438caa1ba6dbb326c58a23238064091881933828a540d08aef3deab6f087048268c570ede42dfd6046ba82958ba5ad463e5a77d74559bf1799349dbf6e3e8e26369ad1468a18565dcda9e7d905a9f53d847655b7bf5ee87753be
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130504);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/24");

  script_cve_id("CVE-2019-0066");
  script_xref(name:"JSA", value:"JSA10965");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: NG-mVPN rpd DoS (JSA10965)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by an unexpected status
return value weakness in the Next-Generation Multicast VPN (NG-mVPN) which can result in a denial of service (DoS)
condition. An unauthenticated, remote attacker can exploit this issue, by repeatedly sending crafted, malformed IPv4
packets to a victim device, including when these packets are forwarded directly through a device, provided that the
malformed packet is not first de-encapsulated from an encapsulated format by a receiving device. This allows an
attacker to cause the system to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2019-10-Security-Bulletin-Junos-OS-A-malformed-IPv4-packet-received-by-Junos-in-an-NG-mVPN-scenario-may-cause-the-routing-protocol-daemon-rpd-process-to-core-CVE-2019-0066
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c12b569");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10965");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0066");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1', 'fixed_ver':'15.1F6-S12'},
  {'min_ver':'15.1R7', 'fixed_ver':'15.1R7-S2'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D150', 'model':'^SRX'},
  {'min_ver':'16.1', 'fixed_ver':'16.1R3-S10'},
  {'min_ver':'16.1R4', 'fixed_ver':'16.1R4-S12'},
  {'min_ver':'16.1R6', 'fixed_ver':'16.1R6-S6'},
  {'min_ver':'16.1R7', 'fixed_ver':'16.1R7-S2'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R2-S7'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R2-S9', 'fixed_display':'17.1R2-S9, 17.1R3'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R1-S7', 'fixed_display':'17.2R1-S7, 17.2R2-S6, 17.2R3'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R2-S4', 'fixed_display':'17.3R2-S4, 17.3R3'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
