#TRUSTED a95a35b2b453361c5bbc7effe44908fec5a7d08c41a764ab816f3308a363113a637e2babf6cdd27d143014ab93c4ba899adac074128b04e9a65bf50bb89d0131f7db3cd9405c2a97d2aae9796dd4d6fc17fd73dfe48283a042dbaa1c38bf1a3a93b515e2ad1b2fec580d3d5a0a1e767e8820ae97416214b6b7be3fc4fd7afe1bcfbcd789963f0724b50f42aa6a798b9ac79f0661f7fcdc2896112144c8affeea8ce21876069db24213c0019844e4111ec74fa9aa9adb3bfd7ae999a82d97abccacfdc68413bad4dbda5c9a13256e2c6ef328a3ebfd4b22b92e739858b2bcbc77b4ea7707b7e9b292357e78a14cd08303392a5dade9526bbf0309bf291f5ed7fb0a5cf7cb91f8b30d6ef580fce5217b1276428256790a1c0c3848e0e2d193c02ca7ab3cb10ba037bed53057423e0141df09479556637c42a09c67731de502e7036ee4c20e12d467e72539a7807006c69f33eff410a0ee39e3dee303064e9dd4b8b9980c699cba683fb2f5d07089321a63d92cb607dea754084a5b1ea6de43f71ab1ccfcbb2efe7677f5f741811e35d7f49fb20dbabeda6f08f836ad8d59e8d38d84bfb04af4e49342a58d410f6ce53aac1b2c47251fe8e16857e5f707a3a19c8b1feaedc225361c1bebe674ec51e3b98d361aee203d0427107bafeedec5d2a9073db17515f98153137b92c9553eaee9a4e0d1e6e0b255fb20811b78a670293005
#TRUST-RSA-SHA256 8b6928b4d02c86f9b2167bcf93695b49777614c149eeee6b1d0489e533ad48297566c812f7e1a7c9a012e41f170a6218ec612e2e91e3b0aefc0b51fc44aae4a73383d873b0aabe0d123bf196b0edba03408b350bb8a5483e386aa5be3de69db3af1f785961c8a406072c4c2264d25a16ffea12475f91571ed167295e7b9c0ef0ccb196aa9cdfdf802917f5a945ade86deb1fa4268038b9e5366e0dab4a7f231f654bdc562b9dcd3999bd6604b9dc28693a7938edcdb3a566964ed8af54c17436fa2b4933522ff242bb6b99d717a425ee7e2b73989f61ed6b8b5ab8f36f2210457aa0ae0922c56f194bd599f3b6a2fa8b731ec75d3ed3d9b592547fdd658f36d4c5d8eea0036bb2a2529f17c18802f5d34d07693ec8e24e8835e8c494334bcb85b03d9cc92f4b3c0aff6a8179c2ef90ab1c5df515e4c126582b58718aea9f0757224da8b446df30aaf255385d55b5650cadd51a1240a0a01bb75a064d77435044cbe69d1847ebca96bf8ae8c2610cfa802b5e7ac8fe199ae02014ebea53f897a6b7d63b2cc0a2b98950270e4d3f6090f0c906535bb81eeba1d41f58ea65e71787dde8e3940e3e07c165b97315ba92a288bf03ad62e30c81d75e23f5e2e80f57b298b58f73a8e72dabf5bc153a054de6bd4816c98a4169271cb1c61157b1fe5cbf2a7da2a9e5fd0f715d612dfcd5c6de4b0a7d219891236d752548cc316be883a6
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166332);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id("CVE-2022-22199");
  script_xref(name:"JSA", value:"JSA69898");
  script_xref(name:"IAVA", value:"2022-A-0421-S");

  script_name(english:"Juniper Junos OS DoS (JSA69898)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a DoS vulnerability as referenced in the JSA69898
advisory due to the Improper Handling of an Unexpected Data Type in the processing of EVPN routes on Juniper Networks
Junos OS and Junos OS Evolved. An attacker in direct control of a BGP client connected to a route reflector, or via a
machine in the middle (MITM) attack, can send a specific EVPN route contained within a BGP Update, triggering a routing
protocol daemon (RPD) crash, leading to a Denial of Service (DoS) condition. Continued receipt and processing of these
specific EVPN routes could create a sustained Denial of Service (DoS) condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://www.juniper.net/documentation/us/en/software/junos/evpn-vxlan/topics/ref/statement/evpn-edit-routing-instances-protocols.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dfd1b7b");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-RPD-core-upon-receipt-of-a-specific-EVPN-route-by-a-BGP-route-reflector-in-an-EVPN-environment-CVE-2022-22199
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63c352a3");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69898");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22199");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges;
if (ver =~ 'EVO$')
{
  vuln_ranges = [
    {'min_ver':'21.3R1', 'fixed_ver':'21.4R3-EVO'},
    {'min_ver':'22.1', 'fixed_ver':'22.1R1-S2-EVO', 'fixed_display':'22.1R1-S2-EVO, 22.1R3'},
    {'min_ver':'22.2', 'fixed_ver':'22.2R2-EVO', 'fixed_display':'22.2R2-EVO'},
  ];
}
else
{
  vuln_ranges = [
    {'min_ver':'21.3R1', 'fixed_ver':'21.3R3-S2'},
    {'min_ver':'21.4', 'fixed_ver':'21.4R2-S2', 'fixed_display':'21.4R2-S2, 21.4R3'},
    {'min_ver':'22.1', 'fixed_ver':'22.1R1-S2', 'fixed_display':'22.1R1-S2, 22.1R3'},
    {'min_ver':'22.2', 'fixed_ver':'22.2R2'},
  ];
}

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"protocols evpn", multiline:TRUE)
  || !preg(string:buf, pattern:"leave-sync-route-oldstyle", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'running a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
