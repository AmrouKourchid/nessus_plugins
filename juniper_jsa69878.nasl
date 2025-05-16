#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178640);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2022-22227");
  script_xref(name:"JSA", value:"JSA69878");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69878)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69878
advisory.

  - An Improper Check for Unusual or Exceptional Conditions vulnerability in the Packet Forwarding Engine
    (PFE) of Juniper Networks Junos OS Evolved on ACX7000 Series allows an unauthenticated network-based
    attacker to cause a partial Denial of Service (DoS). On receipt of specific IPv6 transit traffic, Junos OS
    Evolved on ACX7100-48L, ACX7100-32C and ACX7509 sends this traffic to the Routing Engine (RE) instead of
    forwarding it, leading to increased CPU utilization of the RE and a partial DoS. This issue only affects
    systems configured with IPv6. This issue does not affect ACX7024 which is supported from 22.3R1-EVO
    onwards where the fix has already been incorporated as indicated in the solution section. This issue
    affects Juniper Networks Junos OS Evolved on ACX7100-48L, ACX7100-32C, ACX7509: 21.1-EVO versions prior to
    21.1R3-S2-EVO; 21.2-EVO versions prior to 21.2R3-S2-EVO; 21.3-EVO versions prior to 21.3R3-EVO; 21.4-EVO
    versions prior to 21.4R1-S1-EVO, 21.4R2-EVO. This issue does not affect Juniper Networks Junos OS Evolved
    versions prior to 21.1R1-EVO. (CVE-2022-22227)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-Evolved-ACX7000-Series-Specific-IPv6-transit-traffic-gets-exceptioned-to-the-routing-engine-which-will-cause-increased-CPU-utilization-CVE-2022-22227
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edf58abe");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69878");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22227");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (model !~ "^ACX7100")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.1-EVO', 'fixed_ver':'21.1R3-S2-EVO', 'model':'^ACX7100'},
  {'min_ver':'21.2-EVO', 'fixed_ver':'21.2R3-S2-EVO', 'model':'^ACX7100'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-EVO', 'model':'^ACX7100'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R1-S1-EVO', 'model':'^ACX7100', 'fixed_display':'21.4R1-S1-EVO, 21.4R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
