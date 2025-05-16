#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193494);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2024-21614");
  script_xref(name:"JSA", value:"JSA75755");

  script_name(english:"Juniper Junos OS Vulnerability (JSA75755)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA75755
advisory.

  - An Improper Check for Unusual or Exceptional Conditions vulnerability in Routing Protocol Daemon (RPD) of
    Juniper Networks Junos OS and Junos OS Evolved allows a network-based, unauthenticated attacker to cause
    rpd to crash, leading to Denial of Service (DoS). On all Junos OS and Junos OS Evolved platforms, when
    NETCONF and gRPC are enabled, and a specific query is executed via Dynamic Rendering (DREND), rpd will
    crash and restart. Continuous execution of this specific query will cause a sustained Denial of Service
    (DoS) condition. This issue affects: Juniper Networks Junos OS * 22.2 versions earlier than 22.2R2-S2,
    22.2R3; * 22.3 versions earlier than 22.3R2, 22.3R3. Juniper Networks Junos OS Evolved * 22.2 versions
    earlier than 22.2R2-S2-EVO, 22.2R3-EVO; * 22.3 versions earlier than 22.3R2-EVO, 22.3R3-EVO. This issue
    does not affect Juniper Networks: Junos OS versions earlier than 22.2R1; Junos OS Evolved versions earlier
    than 22.2R1-EVO. (CVE-2024-21614)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-01-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-A-specific-query-via-DREND-causes-rpd-crash-CVE-2024-21614
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97a91160");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA75755");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21614");

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
  {'min_ver':'22.2', 'fixed_ver':'22.2R2-S2', 'fixed_display':'22.2R2-S2, 22.2R3'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R2-S2-EVO'},
  {'min_ver':'22.2R3', 'fixed_ver':'22.2R3-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2', 'fixed_display':'22.3R2, 22.3R3'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-EVO'},
  {'min_ver':'22.3R3', 'fixed_ver':'22.3R3-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
