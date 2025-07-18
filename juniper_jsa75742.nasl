#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193491);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2024-21601");
  script_xref(name:"JSA", value:"JSA75742");

  script_name(english:"Juniper Junos OS Vulnerability (JSA75742)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA75742
advisory.

  - A Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
    vulnerability in the Flow-processing Daemon (flowd) of Juniper Networks Junos OS on SRX Series allows an
    unauthenticated, network-based attacker to cause a Denial-of-Service (Dos). On SRX Series devices when two
    different threads try to simultaneously process a queue which is used for TCP events flowd will crash. One
    of these threads can not be triggered externally, so the exploitation of this race condition is outside
    the attackers direct control. Continued exploitation of this issue will lead to a sustained DoS. This
    issue affects Juniper Networks Junos OS: * 21.2 versions earlier than 21.2R3-S5; * 21.3 versions earlier
    than 21.3R3-S5; * 21.4 versions earlier than 21.4R3-S4; * 22.1 versions earlier than 22.1R3-S3; * 22.2
    versions earlier than 22.2R3-S1; * 22.3 versions earlier than 22.3R2-S2, 22.3R3; * 22.4 versions earlier
    than 22.4R2-S1, 22.4R3. This issue does not affect Juniper Networks Junos OS versions earlier than 21.2R1.
    (CVE-2024-21601)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-01-Security-Bulletin-Junos-OS-SRX-Series-Due-to-an-error-in-processing-TCP-events-flowd-will-crash-CVE-2024-21601
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cfdafbfa");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA75742");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21601");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

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
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S5'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S4'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S3'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S1'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2', 'fixed_display':'22.3R2-S2, 22.3R3'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S1', 'fixed_display':'22.4R2-S1, 22.4R3'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
