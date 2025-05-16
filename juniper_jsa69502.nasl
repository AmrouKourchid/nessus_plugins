#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178641);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2022-22191");
  script_xref(name:"JSA", value:"JSA69502");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69502)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69502
advisory.

  - A Denial of Service (DoS) vulnerability in the processing of a flood of specific ARP traffic in Juniper
    Networks Junos OS on the EX4300 switch, sent from the local broadcast domain, may allow an unauthenticated
    network-adjacent attacker to trigger a PFEMAN watchdog timeout, causing the Packet Forwarding Engine (PFE)
    to crash and restart. After the restart, transit traffic will be temporarily interrupted until the PFE is
    reprogrammed. In a virtual chassis (VC), the impacted Flexible PIC Concentrator (FPC) may split from the
    VC temporarily, and join back into the VC once the PFE restarts. Continued receipt and processing of these
    packets will create a sustained Denial of Service (DoS) condition. This issue affects Juniper Networks
    Junos OS on the EX4300: All versions prior to 15.1R7-S12; 18.4 versions prior to 18.4R2-S10, 18.4R3-S11;
    19.1 versions prior to 19.1R3-S8; 19.2 versions prior to 19.2R1-S9, 19.2R3-S4; 19.3 versions prior to
    19.3R3-S5; 19.4 versions prior to 19.4R2-S6, 19.4R3-S7; 20.1 versions prior to 20.1R3-S3; 20.2 versions
    prior to 20.2R3-S3; 20.3 versions prior to 20.3R3-S2; 20.4 versions prior to 20.4R3-S1; 21.1 versions
    prior to 21.1R3; 21.2 versions prior to 21.2R2-S1, 21.2R3; 21.3 versions prior to 21.3R1-S2, 21.3R2.
    (CVE-2022-22191)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2022-04-Security-Bulletin-Junos-OS-EX4300-PFE-Denial-of-Service-DoS-upon-receipt-of-a-flood-of-specific-ARP-traffic-CVE-2022-22191
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34abb95f");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69502");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22191");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
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
if (model !~ "^EX4300")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'15.1R7-S12', 'model':'^EX4300'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S10', 'model':'^EX4300'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S11', 'model':'^EX4300'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S8', 'model':'^EX4300'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S9', 'model':'^EX4300'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S4', 'model':'^EX4300'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S5', 'model':'^EX4300'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S6', 'model':'^EX4300'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S7', 'model':'^EX4300'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S3', 'model':'^EX4300'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3', 'model':'^EX4300'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S2', 'model':'^EX4300'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S1', 'model':'^EX4300'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3', 'model':'^EX4300'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2-S1', 'model':'^EX4300', 'fixed_display':'21.2R2-S1, 21.2R3'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R1-S2', 'model':'^EX4300', 'fixed_display':'21.3R1-S2, 21.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
