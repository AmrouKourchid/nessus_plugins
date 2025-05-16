#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178674);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/20");

  script_cve_id("CVE-2018-0034");
  script_xref(name:"JSA", value:"JSA10868");

  script_name(english:"Juniper Junos OS Vulnerability (JSA10868)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA10868
advisory.

  - A Denial of Service vulnerability exists in the Juniper Networks Junos OS JDHCPD daemon which allows an
    attacker to core the JDHCPD daemon by sending a crafted IPv6 packet to the system. This issue is limited
    to systems which receives IPv6 DHCP packets on a system configured for DHCP processing using the JDHCPD
    daemon. This issue does not affect IPv4 DHCP packet processing. Affected releases are Juniper Networks
    Junos OS: 12.3 versions prior to 12.3R12-S10 on EX Series; 12.3X48 versions prior to 12.3X48-D70 on SRX
    Series; 14.1X53 versions prior to 14.1X53-D47 on EX2200/VC, EX3200, EX3300/VC, EX4200, EX4300, EX4550/VC,
    EX4600, EX6200, EX8200/VC (XRE), QFX3500, QFX3600, QFX5100; 14.1X53 versions prior to 14.1X53-D130 on
    QFabric; 15.1 versions prior to 15.1R4-S9, 15.1R6-S6, 15.1R7; 15.1X49 versions prior to 15.1X49-D140 on
    SRX Series; 15.1X53 versions prior to 15.1X53-D67 on QFX10000 Series; 15.1X53 versions prior to
    15.1X53-D233 on QFX5110, QFX5200; 15.1X53 versions prior to 15.1X53-D471 on NFX 150, NFX 250; 16.1
    versions prior to 16.1R3-S9, 16.1R4-S8, 16.1R5-S4, 16.1R6-S3, 16.1R7; 16.2 versions prior to 16.2R2-S5,
    16.2R3; 17.1 versions prior to 17.1R1-S7, 17.1R2-S7, 17.1R3; 17.2 versions prior to 17.2R1-S6, 17.2R2-S4,
    17.2R3; 17.3 versions prior to 17.3R1-S4, 17.3R2-S2, 17.3R3; 17.4 versions prior to 17.4R1-S3, 17.4R2.
    (CVE-2018-0034)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2018-07-Security-Bulletin-Junos-OS-A-malicious-crafted-IPv6-DHCP-packet-may-cause-the-JDHCPD-daemon-to-core-CVE-2018-0034
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a7b9fec");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10868");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0034");
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

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^EX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S10', 'model':'^EX'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
