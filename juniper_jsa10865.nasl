#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178668);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/20");

  script_cve_id("CVE-2018-0031");
  script_xref(name:"JSA", value:"JSA10865");

  script_name(english:"Juniper Junos OS Vulnerability (JSA10865)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA10865
advisory.

  - Receipt of specially crafted UDP/IP packets over MPLS may be able to bypass a stateless firewall filter.
    The crafted UDP packets must be encapsulated and meet a very specific packet format to be classified in a
    way that bypasses IP firewall filter rules. The packets themselves do not cause a service interruption
    (e.g. RPD crash), but receipt of a high rate of UDP packets may be able to contribute to a denial of
    service attack. This issue only affects processing of transit UDP/IP packets over MPLS, received on an
    interface with MPLS enabled. TCP packet processing and non-MPLS encapsulated UDP packet processing are
    unaffected by this issue. Affected releases are Juniper Networks Junos OS: 12.1X46 versions prior to
    12.1X46-D76; 12.3 versions prior to 12.3R12-S10; 12.3X48 versions prior to 12.3X48-D66, 12.3X48-D70;
    14.1X53 versions prior to 14.1X53-D47; 15.1 versions prior to 15.1F6-S10, 15.1R4-S9, 15.1R6-S6, 15.1R7;
    15.1X49 versions prior to 15.1X49-D131, 15.1X49-D140; 15.1X53 versions prior to 15.1X53-D59 on
    EX2300/EX3400; 15.1X53 versions prior to 15.1X53-D67 on QFX10K; 15.1X53 versions prior to 15.1X53-D233 on
    QFX5200/QFX5110; 15.1X53 versions prior to 15.1X53-D471, 15.1X53-D490 on NFX; 16.1 versions prior to
    16.1R3-S8, 16.1R4-S9, 16.1R5-S4, 16.1R6-S3, 16.1R7; 16.2 versions prior to 16.2R1-S6, 16.2R2-S5, 16.2R3;
    17.1 versions prior to 17.1R1-S7, 17.1R2-S7, 17.1R3; 17.2 versions prior to 17.2R1-S6, 17.2R2-S4, 17.2R3;
    17.2X75 versions prior to 17.2X75-D100; 17.3 versions prior to 17.3R1-S4, 17.3R2-S2, 17.3R3; 17.4 versions
    prior to 17.4R1-S3, 17.4R2; 18.1 versions prior to 18.1R2; 18.2X75 versions prior to 18.2X75-D5.
    (CVE-2018-0031)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2018-07-Security-Bulletin-Junos-OS-Receipt-of-specially-crafted-UDP-packets-over-MPLS-may-bypass-stateless-IP-firewall-rules-CVE-2018-0031
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c453ff02");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10865");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0031");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.1X46', 'fixed_ver':'12.1X46-D76'},
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S10'},
  {'min_ver':'12.3X48', 'fixed_ver':'12.3X48-D66', 'fixed_display':'12.3X48-D66, 12.3X48-D70'},
  {'min_ver':'14.1X53', 'fixed_ver':'14.1X53-D47'},
  {'min_ver':'15.1', 'fixed_ver':'15.1F6-S10', 'fixed_display':'15.1F6-S10, 15.1R7'},
  {'min_ver':'15.1R6', 'fixed_ver':'15.1R4-S9', 'fixed_display':'15.1R4-S9, 15.1R6-S6'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D131', 'fixed_display':'15.1X49-D131, 15.1X49-D140'},
  {'min_ver':'15.1X53', 'fixed_ver':'15.1X53-D233', 'model':'^(EX2300|EX3400|NFX|QFX10K|QFX5110|QFX5200)', 'fixed_display':'15.1X53-D233, 15.1X53-D471, 15.1X53-D490, 15.1X53-D59, 15.1X53-D67'},
  {'min_ver':'16.1', 'fixed_ver':'16.1R3-S8', 'fixed_display':'16.1R3-S8, 16.1R7'},
  {'min_ver':'16.1R4', 'fixed_ver':'16.1R4-S9'},
  {'min_ver':'16.1R5', 'fixed_ver':'16.1R5-S4'},
  {'min_ver':'16.1R6', 'fixed_ver':'16.1R6-S3'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R1-S6', 'fixed_display':'16.2R1-S6, 16.2R2-S5, 16.2R3'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R1-S7', 'fixed_display':'17.1R1-S7, 17.1R2-S7, 17.1R3'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R1-S6', 'fixed_display':'17.2R1-S6, 17.2R2-S4, 17.2R3'},
  {'min_ver':'17.2X75', 'fixed_ver':'17.2X75-D100', 'fixed_display':'17.2X75-D100, 17.2X75-D110'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R1-S4', 'fixed_display':'17.3R1-S4, 17.3R2-S2, 17.3R3'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R1-S3', 'fixed_display':'17.4R1-S3, 17.4R2'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R2'},
  {'min_ver':'18.2X75', 'fixed_ver':'18.2X75-D5'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
