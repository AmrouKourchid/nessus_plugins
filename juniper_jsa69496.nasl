#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178642);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/21");

  script_cve_id("CVE-2020-7461");
  script_xref(name:"JSA", value:"JSA69496");
  script_xref(name:"CEA-ID", value:"CEA-2021-0023");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69496)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69496
advisory.

  - In FreeBSD 12.1-STABLE before r365010, 11.4-STABLE before r365011, 12.1-RELEASE before p9, 11.4-RELEASE
    before p3, and 11.3-RELEASE before p13, dhclient(8) fails to handle certain malformed input related to
    handling of DHCP option 119 resulting a heap overflow. The heap overflow could in principle be exploited
    to achieve remote code execution. The affected process runs with reduced privileges in a Capsicum sandbox,
    limiting the immediate impact of an exploit. (CVE-2020-7461)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.freebsd.org/security/advisories/FreeBSD-SA-20:26.dhclient.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?681e9636");
  # https://supportportal.juniper.net/s/article/2022-04-Security-Bulletin-Junos-OS-vSRX-3-0-model-FreeBSD-SA-20-26-dhclient-heap-overflow-CVE-2020-7461
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be4dc047");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69496");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7461");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/07");
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
if (model !~ "^(3|vSRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S10', 'model':'^(3|vSRX)'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S10', 'model':'^(3|vSRX)'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S7', 'model':'^(3|vSRX)'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8', 'model':'^(3|vSRX)'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S4', 'model':'^(3|vSRX)'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S4', 'model':'^(3|vSRX)'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S6', 'model':'^(3|vSRX)'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S6', 'model':'^(3|vSRX)'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S3', 'model':'^(3|vSRX)'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3', 'model':'^(3|vSRX)'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S3', 'model':'^(3|vSRX)'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3', 'model':'^(3|vSRX)'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2', 'model':'^(3|vSRX)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
