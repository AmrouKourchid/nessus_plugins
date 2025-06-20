#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156684);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2022-22170", "CVE-2022-22171");
  script_xref(name:"JSA", value:"JSA11277");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA11277)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA11277 advisory.

  - An Improper Check for Unusual or Exceptional Conditions vulnerability in the Packet Forwarding Engine
    (PFE) of Juniper Networks Junos OS allows an unauthenticated networked attacker to cause a Denial of
    Service (DoS) by sending specific packets over VXLAN which cause the PFE to reset. This issue affects:
    Juniper Networks Junos OS 19.4 versions prior to 19.4R3-S7; 20.1 versions prior to 20.1R3-S3; 20.2
    versions prior to 20.2R3-S3; 20.3 versions prior to 20.3R3-S2; 20.4 versions prior to 20.4R3-S1; 21.1
    versions prior to 21.1R3; 21.2 versions prior to 21.2R2; 21.3 versions prior to 21.3R1-S1, 21.3R2. This
    issue does not affect versions of Junos OS prior to 19.4R1. (CVE-2022-22171)

  - A Missing Release of Resource after Effective Lifetime vulnerability in the Packet Forwarding Engine (PFE)
    of Juniper Networks Junos OS allows an unauthenticated networked attacker to cause a Denial of Service
    (DoS) by sending specific packets over VXLAN which cause heap memory to leak and on exhaustion the PFE to
    reset. The heap memory utilization can be monitored with the command: user@host> show chassis fpc This
    issue affects: Juniper Networks Junos OS 19.4 versions prior to 19.4R2-S6, 19.4R3-S6; 20.1 versions prior
    to 20.1R3-S2; 20.2 versions prior to 20.2R3-S3; 20.3 versions prior to 20.3R3-S1; 20.4 versions prior to
    20.4R3; 21.1 versions prior to 21.1R3; 21.2 versions prior to 21.2R2. This issue does not affect versions
    of Junos OS prior to 19.4R1. (CVE-2022-22170)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2022-01-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Specific-packets-over-VXLAN-cause-memory-leak-and-or-FPC-reset-CVE-2022-22170-CVE-2022-22171
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16d107e8");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11277");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22171");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S7'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S1'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R1-S1', 'fixed_display':'21.3R1-S1, 21.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
