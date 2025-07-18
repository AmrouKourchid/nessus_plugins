#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166075);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2022-22226");
  script_xref(name:"JSA", value:"JSA69876");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69876)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69876
advisory.

  - In VxLAN scenarios on EX4300-MP, EX4600, QFX5000 Series devices an Uncontrolled Memory Allocation
    vulnerability in the Packet Forwarding Engine (PFE) of Juniper Networks Junos OS allows an unauthenticated
    adjacently located attacker sending specific packets to cause a Denial of Service (DoS) condition by
    crashing one or more PFE's when they are received and processed by the device. (CVE-2022-22226)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.juniper.net/documentation/us/en/software/junos/ovsdb-vxlan/evpn-vxlan/topics/ref/statement/vxlan.html#id-vxlan__d281e31
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56c91bd5");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-EX4300-MP-EX4600-QFX5000-Series-In-VxLAN-scenarios-specific-packets-processed-cause-a-memory-leak-leading-to-a-PFE-crash-CVE-2022-22226
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75c64715");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69876");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22226");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^EX4300")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.1', 'fixed_ver':'17.1R1', 'model':'^EX4300'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S13', 'model':'^EX4300'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S5', 'model':'^EX4300'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S13', 'model':'^EX4300'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S8', 'model':'^EX4300'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5', 'model':'^EX4300'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S8', 'model':'^EX4300', 'fixed_display':'18.4R1-S8, 18.4R2-S6'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R3-S6', 'model':'^EX4300'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S4', 'model':'^EX4300'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S7', 'model':'^EX4300'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S1', 'model':'^EX4300'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6', 'model':'^EX4300'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S1', 'model':'^EX4300'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S4', 'model':'^EX4300', 'fixed_display':'19.4R1-S4, 19.4R2-S4'},
  {'min_ver':'19.4R2', 'fixed_ver':'19.4R3-S1', 'model':'^EX4300'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2', 'model':'^EX4300'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S3', 'model':'^EX4300', 'fixed_display':'20.2R2-S3, 20.2R3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2', 'model':'^EX4300'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
