#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166078);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id("CVE-2022-22225");
  script_xref(name:"JSA", value:"JSA69875");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69875)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69875
advisory.

  - A Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in the Routing Protocol Daemon (rpd) of
    Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated attacker with an established BGP
    session to cause a Denial of Service (DoS). (CVE-2022-22225)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-In-a-BGP-multipath-scenario-when-one-of-the-contributing-routes-is-flapping-often-and-rapidly-rpd-may-crash-CVE-2022-22225
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d72af8bd");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69875");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22225");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0-EVO', 'fixed_ver':'20.4R3-S4-EVO'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S6'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S4'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S3'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S4'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3'},
  {'min_ver':'21.1-EVO', 'fixed_ver':'21.1R1-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2'},
  {'min_ver':'21.2-EVO', 'fixed_ver':'21.2R2-EVO'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
