#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(122241);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2019-0005");
  script_xref(name:"JSA", value:"JSA10905");

  script_name(english:"Junos OS: Stateless firewall filter ignores IPv6 extension headers (JSA10905)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a vulnerability which may allow IPv6 
packets that should have been blocked to be forwarded.");
  # https://supportportal.juniper.net/s/article/2019-01-Security-Bulletin-Junos-OS-EX-and-QFX-series-Stateless-firewall-filter-ignores-IPv6-next-header-configuration-CVE-2019-0005
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc1e9681");
  # https://supportportal.juniper.net/s/article/2019-01-Security-Bulletin-Junos-OS-EX-and-QFX-series-Stateless-firewall-filter-ignores-IPv6-next-header-configuration-CVE-2019-0005
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc1e9681");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10905");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0005");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/15");

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
if (model !~ "^(EX23|EX2300|EX34|EX3400|EX4600|QFX3|QFX5|QFX511|QFX52)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'14.1X53', 'fixed_ver':'14.1X53-D47', 'model':'^(EX23|EX2300|EX34|EX3400|EX4600|QFX3|QFX5|QFX511|QFX52)'},
  {'min_ver':'15.1', 'fixed_ver':'15.1R7', 'model':'^(EX23|EX2300|EX34|EX3400|EX4600|QFX3|QFX5|QFX511|QFX52)'},
  {'min_ver':'15.1X53', 'fixed_ver':'15.1X53-D234', 'model':'^(EX23|EX34|QFX511|QFX52)', 'fixed_display':'15.1X53-D234, 15.1X53-D591'},
  {'min_ver':'16.1', 'fixed_ver':'16.1R7', 'model':'^(EX23|EX2300|EX34|EX3400|EX4600|QFX3|QFX5|QFX511|QFX52)'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R2-S10', 'model':'^(EX23|EX2300|EX34|EX3400|EX4600|QFX3|QFX5|QFX511|QFX52)', 'fixed_display':'17.1R2-S10, 17.1R3'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R3', 'model':'^(EX23|EX2300|EX34|EX3400|EX4600|QFX3|QFX5|QFX511|QFX52)'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3', 'model':'^(EX23|EX2300|EX34|EX3400|EX4600|QFX3|QFX5|QFX511|QFX52)'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2', 'model':'^(EX23|EX2300|EX34|EX3400|EX4600|QFX3|QFX5|QFX511|QFX52)'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R2', 'model':'^(EX23|EX2300|EX34|EX3400|EX4600|QFX3|QFX5|QFX511|QFX52)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
