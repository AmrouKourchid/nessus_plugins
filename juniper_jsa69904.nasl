#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166077);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2022-22247");
  script_xref(name:"JSA", value:"JSA69904");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69904)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69904
advisory.

  - An Improper Input Validation vulnerability in ingress TCP segment processing of Juniper Networks Junos OS
    Evolved allows a network-based unauthenticated attacker to send a crafted TCP segment to the device,
    triggering a kernel panic, leading to a Denial of Service (DoS) condition. Continued receipt and
    processing of this TCP segment could create a sustained Denial of Service (DoS) condition.
    (CVE-2022-22247)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-Evolved-Kernel-processing-of-unvalidated-TCP-segments-could-lead-to-a-Denial-of-Service-DoS-CVE-2022-22247
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fecf2fea");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69904");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22247");

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
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
