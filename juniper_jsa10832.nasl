#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(106389);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2018-0004");
  script_xref(name:"JSA", value:"JSA10832");

  script_name(english:"Juniper Junos Kernel Register and Schedule Software Interrupt Handler Subsystem CPU Consumption Remote DoS (JSA10832)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability.");
  # https://supportportal.juniper.net/s/article/2018-01-Security-Bulletin-Junos-OS-Kernel-Denial-of-Service-Vulnerability-CVE-2018-0004
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4289a306");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10832");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0004");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.1X46', 'fixed_ver':'12.1X46-D50'},
  {'min_ver':'12.3R', 'fixed_ver':'12.3R12-S7'},
  {'min_ver':'12.3X48', 'fixed_ver':'12.3X48-D30'},
  {'min_ver':'14.1', 'fixed_ver':'14.1R8-S4', 'fixed_display':'14.1R8-S4, 14.1R9'},
  {'min_ver':'14.1X53', 'fixed_ver':'14.1X53-D30', 'fixed_display':'14.1X53-D30, 14.1X53-D34'},
  {'min_ver':'14.2', 'fixed_ver':'14.2R8'},
  {'min_ver':'15.1', 'fixed_ver':'15.1F6', 'fixed_display':'15.1F6, 15.1R3'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D40'},
  {'min_ver':'15.1X53', 'fixed_ver':'15.1X53-D31', 'fixed_display':'15.1X53-D31, 15.1X53-D33, 15.1X53-D60'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
