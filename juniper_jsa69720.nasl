#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178646);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2003-0001", "CVE-2022-22216");
  script_xref(name:"JSA", value:"JSA69720");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA69720)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA69720 advisory.

  - Multiple ethernet Network Interface Card (NIC) device drivers do not pad frames with null bytes, which
    allows remote attackers to obtain information from previous packets or kernel memory by using malformed
    packets, as demonstrated by Etherleak. (CVE-2003-0001)

  - An Exposure of Sensitive Information to an Unauthorized Actor vulnerability in the PFE of Juniper Networks
    Junos OS on PTX Series and QFX10k Series allows an adjacent unauthenticated attacker to gain access to
    sensitive information. PTX1000 and PTX10000 Series, and QFX10000 Series and PTX5000 Series devices
    sometimes do not reliably pad Ethernet packets, and thus some packets can contain fragments of system
    memory or data from previous packets. This issue is also known as 'Etherleak' and often detected as
    CVE-2003-0001. This issue affects: Juniper Networks Junos OS on PTX1000 and PTX10000 Series: All versions
    prior to 18.4R3-S11; 19.1 versions prior to 19.1R2-S3, 19.1R3-S7; 19.2 versions prior to 19.2R1-S8,
    19.2R3-S4; 19.3 versions prior to 19.3R3-S4; 19.4 versions prior to 19.4R2-S5, 19.4R3-S6; 20.1 versions
    prior to 20.1R3-S2; 20.2 versions prior to 20.2R3-S3; 20.3 versions prior to 20.3R3-S2; 20.4 versions
    prior to 20.4R3-S4; 21.1 versions prior to 21.1R2-S1, 21.1R3; 21.2 versions prior to 21.2R1-S1, 21.2R2.
    Juniper Networks Junos OS on QFX10000 Series and PTX5000 Series: All versions prior to 18.3R3-S6; 18.4
    versions prior to 18.4R2-S9, 18.4R3-S10; 19.1 versions prior to 19.1R2-S3, 19.1R3-S7; 19.2 versions prior
    to 19.2R1-S8, 19.2R3-S4; 19.3 versions prior to 19.3R3-S4; 19.4 versions prior to 19.4R2-S6, 19.4R3-S6;
    20.1 versions prior to 20.1R3-S2; 20.2 versions prior to 20.2R3-S3; 20.3 versions prior to 20.3R3-S1; 20.4
    versions prior to 20.4R3-S1; 21.1 versions prior to 21.1R2-S1, 21.1R3; 21.2 versions prior to 21.2R2.
    (CVE-2022-22216)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2022-07-Security-Bulletin-Junos-OS-PTX-Series-and-QFX10000-Series-Etherleak-memory-disclosure-in-Ethernet-padding-data-CVE-2022-22216
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ef23eae");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69720");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-0001");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-22216");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
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
if (model !~ "^(PTX1|PTX1000|PTX5000|QFX1)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'18.3R3-S6', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)', 'fixed_display':'18.3R3-S6, 18.4R3-S11'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S9', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S10', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2-S3', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S7', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S4', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S4', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S5', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)', 'fixed_display':'19.4R2-S5, 19.4R2-S6'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S6', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S2', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S1', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)', 'fixed_display':'20.3R3-S1, 20.3R3-S2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S1', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)', 'fixed_display':'20.4R3-S1, 20.4R3-S4'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2-S1', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)', 'fixed_display':'21.1R2-S1, 21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R1-S1', 'model':'^(PTX1|PTX1000|PTX5000|QFX1)', 'fixed_display':'21.2R1-S1, 21.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
