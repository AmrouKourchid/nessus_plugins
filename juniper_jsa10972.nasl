#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130520);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2019-0050");
  script_xref(name:"JSA", value:"JSA10972");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: srxpfe DoS (JSA10972)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a vulnerability in the
srxpfe process. An unauthenticated, remote attacker can exploit this issue, by sending a large amount of traffic to an
affected SRX1500 device, causing it to fail to forward traffic.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2019-10-Security-Bulletin-Junos-OS-SRX1500-Denial-of-service-due-to-crash-of-srxpfe-process-under-heavy-traffic-conditions-CVE-2019-0050
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7179bd3a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10972");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0050");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^SRX1500")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D170', 'model':'^SRX1500'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S7', 'model':'^SRX1500'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S8', 'model':'^SRX1500', 'fixed_display':'17.4R2-S8, 17.4R3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S8', 'model':'^SRX1500'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3', 'model':'^SRX1500'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R2', 'model':'^SRX1500'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2', 'model':'^SRX1500'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
