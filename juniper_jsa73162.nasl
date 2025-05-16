#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182928);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id("CVE-2023-44195", "CVE-2023-44196");
  script_xref(name:"JSA", value:"JSA73162");
  script_xref(name:"IAVA", value:"2023-A-0565");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA73162)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA73162 advisory.

  - An Improper Check for Unusual or Exceptional Conditions in the Packet Forwarding Engine (pfe) of Juniper
    Networks Junos OS Evolved on PTX10003 Series allows an unauthenticated adjacent attacker to cause an
    impact to the integrity of the system. (CVE-2023-44195, CVE-2023-44196)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://supportportal.juniper.net/JSA73152");
  # https://supportportal.juniper.net/s/article/2023-10-Security-Bulletin-Junos-OS-Evolved-PTX10003-Series-Packets-which-are-not-destined-to-the-router-can-reach-the-RE-CVE-2023-44196
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6b85fa3");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA73162");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^PTX1")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0-EVO', 'fixed_ver':'20.4R3-S8-EVO', 'model':'^PTX1'},
  {'min_ver':'21.1-EVO', 'fixed_ver':'21.1R1-EVO', 'model':'^PTX1'},
  {'min_ver':'21.2-EVO', 'fixed_ver':'21.2R3-S6-EVO', 'model':'^PTX1'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R1-EVO', 'model':'^PTX1'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S3-EVO', 'model':'^PTX1'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-S4-EVO', 'model':'^PTX1'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S3-EVO', 'model':'^PTX1'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R2-S2-EVO', 'model':'^PTX1'},
  {'min_ver':'22.3R3-EVO', 'fixed_ver':'22.3R3-EVO', 'model':'^PTX1'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R2-EVO', 'model':'^PTX1'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
