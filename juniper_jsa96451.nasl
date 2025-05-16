#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234109);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2025-21597");
  script_xref(name:"JSA", value:"JSA96451");
  script_xref(name:"IAVA", value:"2025-A-0261");

  script_name(english:"Juniper Junos OS Vulnerability (JSA96451)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA96451
advisory.

  - An Improper Check for Unusual or Exceptional Conditions vulnerability in routing protocol daemon (rpd) of
    Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated, logically adjacent BGP peer to
    cause Denial of Service (DoS). On all Junos OS and Junos OS Evolved platforms, when BGP rib-sharding and
    update-threading are configured, and a BGP peer flap is done with specific timing, rpd crashes and
    restarts. Continuous peer flapping at specific time intervals will result in a sustained Denial of Service
    (DoS) condition. This issue affects eBGP and iBGP, in both IPv4 and IPv6 implementations. This issue
    requires a remote attacker to have at least one established BGP session. The issue can occur with or
    without logical-systems enabled. This issue affects: Junos OS: * All versions before 20.4R3-S8, * 21.2
    versions before 21.2R3-S6, * 21.3 versions before 21.3R3-S5, * 21.4 versions before 21.4R3-S4, * 22.1
    versions before 22.1R3-S3, * 22.2 versions before 22.2R3-S1, * 22.3 versions before 22.3R3, * 22.4
    versions before 22.4R3. Junos OS Evolved: * All versions before 21.2R3-S6-EVO, * 21.3-EVO versions before
    21.3R3-S5-EVO, * 21.4-EVO versions before 21.4R3-S4-EVO, * 22.1-EVO versions before 22.1R3-S3-EVO, *
    22.2-EVO versions before :22.2R3-S1-EVO, * 22.3-EVO versions before 22.3R3-EVO, * 22.4-EVO versions before
    22.4R3-EVO. (CVE-2025-21597)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2025-04-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-When-BGP-rib-sharding-and-update-threading-are-configured-and-a-peer-flaps-an-rpd-core-is-observed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ab2a939");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA96451");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/R:A");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21597");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S8'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.2R3-S6-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S6'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-S5-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S4'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S4-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S3'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-S3-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S1'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R3-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
