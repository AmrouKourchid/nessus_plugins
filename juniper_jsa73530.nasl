#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182927);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/21");

  script_cve_id("CVE-2023-22392");
  script_xref(name:"JSA", value:"JSA73530");
  script_xref(name:"IAVA", value:"2023-A-0565");

  script_name(english:"Juniper Junos OS Vulnerability (JSA73530)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA73530
advisory.

  - A Missing Release of Memory after Effective Lifetime vulnerability in the Packet Forwarding Engine (PFE)
    of Juniper Networks Junos OS allows an adjacent, unauthenticated attacker to cause a Denial of Service
    (DoS). (CVE-2023-22392)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://supportportal.juniper.net/JSA73530");
  # https://supportportal.juniper.net/s/article/2023-10-Security-Bulletin-Junos-OS-PTX-Series-and-QFX10000-Series-Received-flow-routes-which-aren-t-installed-as-the-hardware-doesn-t-support-them-lead-to-an-FPC-heap-memory-leak-CVE-2023-22392
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a8f4430");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA73530");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(FPCs|LC110x|PTX1000|PTX10002|PTX10004|PTX10008|PTX10016|PTX3000|PTX5000|QFX10000|with)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S5', 'model':'^(FPCs|LC110x|PTX1000|PTX10002|PTX10004|PTX10008|PTX10016|PTX3000|PTX5000|QFX10000|with)', 'fixed_display':'20.4R3-S5, 20.4R3-S8'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R1', 'model':'^(FPCs|LC110x|PTX1000|PTX10002|PTX10004|PTX10008|PTX10016|PTX3000|PTX5000|QFX10000|with)', 'fixed_display':'21.1R1, 21.1R3-S4'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S2', 'model':'^(FPCs|LC110x|PTX1000|PTX10002|PTX10004|PTX10008|PTX10016|PTX3000|PTX5000|QFX10000|with)', 'fixed_display':'21.2R3-S2, 21.2R3-S6'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3', 'model':'^(FPCs|LC110x|PTX1000|PTX10002|PTX10004|PTX10008|PTX10016|PTX3000|PTX5000|QFX10000|with)', 'fixed_display':'21.3R3, 21.3R3-S5'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2-S2', 'model':'^(FPCs|LC110x|PTX1000|PTX10002|PTX10004|PTX10008|PTX10016|PTX3000|PTX5000|QFX10000|with)', 'fixed_display':'21.4R2-S2, 21.4R3, 21.4R3-S4'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R1-S2', 'model':'^(FPCs|LC110x|PTX1000|PTX10002|PTX10004|PTX10008|PTX10016|PTX3000|PTX5000|QFX10000|with)', 'fixed_display':'22.1R1-S2, 22.1R2, 22.1R3-S3'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S1', 'model':'^(FPCs|LC110x|PTX1000|PTX10002|PTX10004|PTX10008|PTX10016|PTX3000|PTX5000|QFX10000|with)'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2', 'model':'^(FPCs|LC110x|PTX1000|PTX10002|PTX10004|PTX10008|PTX10016|PTX3000|PTX5000|QFX10000|with)', 'fixed_display':'22.3R2-S2, 22.3R3'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2', 'model':'^(FPCs|LC110x|PTX1000|PTX10002|PTX10004|PTX10008|PTX10016|PTX3000|PTX5000|QFX10000|with)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
