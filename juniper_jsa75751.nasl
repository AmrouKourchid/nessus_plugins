#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197078);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/16");

  script_cve_id("CVE-2024-21610");
  script_xref(name:"JSA", value:"JSA75751");
  script_xref(name:"IAVA", value:"2024-A-0232");

  script_name(english:"Juniper Junos OS Vulnerability (JSA75751)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA75751
advisory.

  - An Improper Handling of Exceptional Conditions vulnerability in the Class of Service daemon (cosd) of
    Juniper Networks Junos OS on MX Series allows an authenticated, network-based attacker with low privileges
    to cause a limited Denial of Service (DoS). In a scaled subscriber scenario when specific low privileged
    commands, received over NETCONF, SSH or telnet, are handled by cosd on behalf of mgd, the respective child
    management daemon (mgd) processes will get stuck. In case of (Netconf over) SSH this leads to stuck SSH
    sessions, so that when the connection-limit for SSH is reached new sessions can't be established anymore.
    A similar behavior will be seen for telnet etc. (CVE-2024-21610)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://supportportal.juniper.net/JSA75751");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA75751");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21610");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (model !~ "^MX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S9', 'model':'^MX'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S7', 'model':'^MX'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5', 'model':'^MX'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S5', 'model':'^MX'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S4', 'model':'^MX'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S3', 'model':'^MX'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S2', 'model':'^MX'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3', 'model':'^MX'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R1-S2', 'model':'^MX', 'fixed_display':'23.2R1-S2, 23.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
