#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178186);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/24");

  script_cve_id("CVE-2023-36850");
  script_xref(name:"JSA", value:"JSA71661");
  script_xref(name:"IAVA", value:"2023-A-0357-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA71661)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA71661
advisory.

  - An Improper Validation of Specified Index, Position, or Offset in Input vulnerability in the Connectivity
    Fault Management(CFM) module of Juniper Networks Junos OS on MX Series(except MPC10, MPC11 and LC9600)
    allows an adjacent attacker on the local broadcast domain to cause a Denial of Service(DoS).
    (CVE-2023-36850)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA71661");
  # https://supportportal.juniper.net/s/article/2023-07-Security-Bulletin-Junos-OS-MX-Series-An-MPC-will-crash-upon-receipt-of-a-malformed-CFM-packet-CVE-2023-36850
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7bfcf52");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA71661");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (model !~ "^MX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S7', 'model':'^MX'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S8', 'model':'^MX'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S12', 'model':'^MX'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R1', 'model':'^MX'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S7', 'model':'^MX'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1', 'model':'^MX'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S7', 'model':'^MX'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S5', 'model':'^MX'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S4', 'model':'^MX'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S4', 'model':'^MX'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S3', 'model':'^MX'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S2', 'model':'^MX'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3', 'model':'^MX'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2', 'model':'^MX', 'fixed_display':'22.3R2, 22.3R3'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2', 'model':'^MX'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
