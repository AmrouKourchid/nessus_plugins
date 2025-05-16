#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124195);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2019-0038");
  script_bugtraq_id(107873);

  script_name(english:"Juniper Junos SRX crafted packets destined to fxp0 denial of service (JSA10927)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a denial of service
vulnerability in the management interface due to buffer space exhaustion. An unauthenticated, adjacent attacker can
exploit this issue, via crafted packets destined to the management interface (fxp0) to cause the service to stop
responding.");
  # https://supportportal.juniper.net/s/article/2019-04-Security-Bulletin-SRX-Series-Crafted-packets-destined-to-fxp0-management-interface-on-SRX340-SRX345-devices-can-lead-to-DoS-CVE-2019-0038
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?068d2973");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10927");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0038");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
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
if (model !~ "^(SRX340|SRX345)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D160', 'model':'^(SRX340|SRX345)'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S3', 'model':'^(SRX340|SRX345)', 'fixed_display':'17.4R2-S3, 17.4R3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S1', 'model':'^(SRX340|SRX345)'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2', 'model':'^(SRX340|SRX345)'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R1-S2', 'model':'^(SRX340|SRX345)', 'fixed_display':'18.3R1-S2, 18.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
