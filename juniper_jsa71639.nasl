#TRUSTED 709aa4a2eb9dc90ad25e4f784d2ebaf5f7115f50f66028fae5b735a4bf6bdd754c48c7162f8abfaf5ab699bb1831272e2d1dab27d263387d0225c884aaddc0e2ad907965812c23149f36e1d1a1336bb8f56c5fc5fd1ebd0767a074ac8cf5149af6426f9d9d4c49485bf439ce5264260040831e001e713a4503da1bba6720e65e66bb5b95575fb568ae51b3db64e507a61605601344a64bad4facf3a7083485c9c30a1c4d433c16fd782f71c608ac29082e7479512c33621c6d39fae69282390f78fcb639f19e4cb7fcc7e25bf824a7113676eadb07c8b8c9158ddf2f214e29dd40a72072b42e240ea2ffb67db0df1d4c6f95f1190ed5510361da6aa958d8d9f931f11998173994ac97cd0ef56de0fd772af6a19ceaf3a80f8128a0cd0c8d4cfa227bf960cabeba1fe4d65fbc274230d3e6f5a6ad84762d4d2bad032651c9715b30240216870ba414f17504ef1cb66b0c1e4953e5ada79e1a37a62ec26357d0d4d2d7487130e4a85fae74038277626acca43dcc3cb615b0a43498ef532ca11e3673358bb204213d04b255ca39e42b92bc1eebb497c821f6be5cef4e5b0b0d46a77666d2c08dc6dfb96f584198c0689f49ff0955000f2c10213791c085506712bfda8cc3224bd026109373a98e0eb7ba03ed247d0a040e6e43afb5ea1bae42e0152ca2dd7f0d5b5c2efe5733af6d278179ac1fde729c4457ee300ef86b2559744d
#TRUST-RSA-SHA256 72679762468742269d4c44568a945a7fde7f3536ef17b356d0fc089c146815a8491eb7375a12b0f46c8011d062704ff8d11be301825b6ce6450c3b5339cbd9274f524f4c511f6c1303efbb44a7c108ab4923daa48d18a6e144565c169403621025b617c71ca542b4af5b441d84a09c2a49b89149b1192ab13295d8ad43861e6fa7e70821b6f27df6a6b7b5d64e0eb43762faf907602b50a57aa4c53b338e85393b8068ffa3161d5d3eee0b0804424118dbed606e1bb61993c1d058e004c9b08e7533f9e9649ef389c77c60547ff0fe6fcae000f793743630d116b9e0a321f3d2845870a1f6ce11449291fb28a2e2285374e6f745ba804a6a9aaf72f4e9fcd9174405e099c35e7f7c78cecd6d80bdc6fae515996479f4d3182db9fa6ce19a49886b272e0d06da1683bcefedd8e17c80d380c94ed4dbd73c9e54084962ae6a6b5cb42de2b0ca9d27064c4bde35030f867f6ffd8a455e6f80eb47a0e7957c2108c11d3af381815e3b1504fe2764b6246932a50a39babd32671bc7f8a79ddfa0533ff3bd89f5c8fe3f039f6cf425c12c861d90082f3819e2f59303a52ab922fdc23d2a2a313aab29ef38c56b1b853eae25b9c2afb8ca59f550b8f09d9c92d54a58e0c803d8ea8fe9f851ec03589864af8083baf6f416e371b89eaa40afb1315e98d02eb1ffc5639fc18851f095759a4eed4b2535c2d0604df7504db48b09f51e5744
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179871);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/15");

  script_cve_id("CVE-2023-36832");
  script_xref(name:"JSA", value:"JSA71639");

  script_name(english:"Juniper Junos OS Vulnerability (JSA71639)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA71639
advisory.

  - An Improper Handling of Exceptional Conditions vulnerability in packet processing of Juniper Networks
    Junos OS on MX Series allows an unauthenticated network-based attacker to send specific packets to an
    Aggregated Multiservices (AMS) interface on the device, causing the packet forwarding engine (PFE) to
    crash, resulting in a Denial of Service (DoS). Continued receipt and processing of this packet will create
    a sustained Denial of Service (DoS) condition. (CVE-2023-36832)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA71639");
  # https://supportportal.juniper.net/s/article/2023-07-Security-Bulletin-Junos-OS-MX-Series-PFE-crash-upon-receipt-of-specific-packet-destined-to-an-AMS-interface-CVE-2023-36832
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?283c064d");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA71639");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36832");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var model = get_kb_item_or_exit('Host/Juniper/model');
var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
check_model(model:model, flags:MX_SERIES, exit_on_fail:TRUE);

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'19.1R3-S10', 'model':'^MX'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S7', 'model':'^MX'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S8', 'model':'^MX'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S12', 'model':'^MX'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S8', 'model':'^MX'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S7', 'model':'^MX'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S5', 'model':'^MX'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S5', 'model':'^MX'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S4', 'model':'^MX'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S3', 'model':'^MX'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S2', 'model':'^MX'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3', 'model':'^MX'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S1', 'model':'^MX', 'fixed_display':'22.3R2-S1, 22.3R3'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R1-S2', 'model':'^MX', 'fixed_display':'22.4R1-S2, 22.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
