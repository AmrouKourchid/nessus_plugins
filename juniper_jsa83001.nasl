#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202129);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/10");

  script_cve_id("CVE-2024-39541");
  script_xref(name:"JSA", value:"JSA83001");

  script_name(english:"Juniper Junos OS Vulnerability (JSA83001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA83001
advisory.

  - An Improper Handling of Exceptional Conditions vulnerability in the Routing Protocol Daemon (rpd) of
    Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated, adjacent attacker to cause a
    Denial-of-Service (DoS). (CVE-2024-39541)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-07-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Inconsistent-information-in-the-TE-database-can-lead-to-an-rpd-crash-CVE-2024-39541
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6becb64");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA83001");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39541");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'22.4', 'fixed_ver':'22.4R3-S1'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2'},
  {'min_ver':'23.4', 'fixed_ver':'23.4R1-S1', 'fixed_display':'23.4R1-S1, 23.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
