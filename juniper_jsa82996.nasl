#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202113);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2024-39536");
  script_xref(name:"JSA", value:"JSA82996");

  script_name(english:"Juniper Junos OS Vulnerability (JSA82996)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA82996
advisory.

  - A Missing Release of Memory after Effective Lifetime vulnerability in the Periodic Packet Management
    Daemon (ppmd) of Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated adjacent
    attacker to cause a Denial-of-Service (DoS). (CVE-2024-39536)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2024-39536");
  # https://supportportal.juniper.net/s/article/2024-07-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Flaps-of-BFD-sessions-with-authentication-cause-a-ppmd-memory-leak-CVE-2024-39536
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14f13161");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA82996");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39536");

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
  {'min_ver':'0.0', 'fixed_ver':'21.2R3-S8'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.2R3-S8-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S7'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S7-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S4'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S4'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S4-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S2', 'fixed_display':'22.4R2-S2, 22.4R3'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R3-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
