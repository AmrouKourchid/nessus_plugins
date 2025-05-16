#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193495);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2024-21603");
  script_xref(name:"JSA", value:"JSA75744");

  script_name(english:"Juniper Junos OS Vulnerability (JSA75744)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA75744
advisory.

  - An Improper Check for Unusual or Exceptional Conditions vulnerability in the kernel of Juniper Network
    Junos OS on MX Series allows a network based attacker with low privileges to cause a denial of service. If
    a scaled configuration for Source class usage (SCU) / destination class usage (DCU) (more than 10 route
    classes) is present and the SCU/DCU statistics are gathered by executing specific SNMP requests or CLI
    commands, a 'vmcore' for the RE kernel will be seen which leads to a device restart. Continued
    exploitation of this issue will lead to a sustained DoS. This issue only affects MX Series devices with
    MPC10, MPC11 or LC9600, and MX304. No other MX Series devices are affected. This issue affects Juniper
    Networks Junos OS: * All versions earlier than 20.4R3-S9; * 21.2 versions earlier than 21.2R3-S6; * 21.3
    versions earlier than 21.3R3-S5; * 21.4 versions earlier than 21.4R3; * 22.1 versions earlier than 22.1R3;
    * 22.2 versions earlier than 22.2R2; * 22.3 versions earlier than 22.3R2. (CVE-2024-21603)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-01-Security-Bulletin-Junos-OS-MX-Series-Gathering-statistics-in-a-scaled-SCU-DCU-configuration-will-lead-to-a-device-crash-CVE-2024-21603
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8935708c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA75744");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21603");

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
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(LC9600|MPC10|MPC11|MX|MX304|or|with)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S9', 'model':'^(LC9600|MPC10|MPC11|MX|MX304|or|with)'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S6', 'model':'^(LC9600|MPC10|MPC11|MX|MX304|or|with)'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5', 'model':'^(LC9600|MPC10|MPC11|MX|MX304|or|with)'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3', 'model':'^(LC9600|MPC10|MPC11|MX|MX304|or|with)'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3', 'model':'^(LC9600|MPC10|MPC11|MX|MX304|or|with)'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R2', 'model':'^(LC9600|MPC10|MPC11|MX|MX304|or|with)'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2', 'model':'^(LC9600|MPC10|MPC11|MX|MX304|or|with)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
