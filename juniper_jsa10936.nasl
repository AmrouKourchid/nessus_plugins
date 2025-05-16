#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124760);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2019-0044");
  script_bugtraq_id(107872);

  script_name(english:"Juniper JSA10936");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is 12.1X46 
prior to 12.1X46-D82, 12.3X48 prior to 12.3X48-D80 or 15.1X49 prior to
15.1X49-D160. It is, therefore, affected by a vulnerability as referenced
in the JSA10936 advisory. 
Note that Nessus has not tested for this issue but has instead relied 
only on the application's self-reported version number.");
  # https://supportportal.juniper.net/s/article/2019-04-Security-Bulletin-Junos-OS-SRX5000-series-Kernel-crash-vmcore-upon-receipt-of-a-specific-packet-on-fxp0-interface-CVE-2019-0044
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77f76506");
  # https://supportportal.juniper.net/s/article/2019-04-Security-Bulletin-Junos-OS-SRX5000-series-Kernel-crash-vmcore-upon-receipt-of-a-specific-packet-on-fxp0-interface-CVE-2019-0044
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77f76506");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10936");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0044");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");

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
if (model !~ "^SRX5")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.1X46', 'fixed_ver':'12.1X46-D82', 'model':'^SRX5'},
  {'min_ver':'12.3X48', 'fixed_ver':'12.3X48-D80', 'model':'^SRX5'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D160', 'model':'^SRX5'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
