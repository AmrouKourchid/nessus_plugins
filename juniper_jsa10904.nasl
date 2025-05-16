#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125546);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/24");

  script_cve_id("CVE-2015-1283");

  script_name(english:"Juniper JSA10904");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is 12.3 prior
to 12.3R12-S12, 12.3X48 prior to 12.3X48-D76, 14.1X53 prior to 14.1X53-D48,
15.1 prior to 15.1R5, 15.1X49 prior to 15.1X49-D151, 15.1 prior to 15.1F6-S12
or 16.1 prior to 16.1R2. It is, therefore, affected by a denial of service 
(DoS) vulnerability. An unauthenticated, remote attacker can exploit this 
issue, via a crafted XML data input, to cause the system to stop responding
and potentially with other possible unspecified impacts as referenced in the
JSA10904 advisory. 
Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.freebsd.org/security/advisories/FreeBSD-SA-15:20.expat.asc");
  # https://supportportal.juniper.net/s/article/2019-01-Security-Bulletin-Junos-OS-FreeBSD-SA-15-20-expat-Multiple-integer-overflows-in-expat-libbsdxml-XML-parser-CVE-2015-1283
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12d7a337");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10904");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1283");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/29");

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


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S12'},
  {'min_ver':'12.3X48', 'fixed_ver':'12.3X48-D76', 'model':'^SRX', 'fixed_display':'12.3X48-D76, 12.3X48-D80'},
  {'min_ver':'14.1X53', 'fixed_ver':'14.1X53-D48', 'model':'^(EX2200|EX3200|EX3300|EX4200|EX4300|EX4550|EX4600|EX6200|EX8200|QFX3500|QFX3600|QFX5100)'},
  {'min_ver':'15.1', 'fixed_ver':'15.1R5'},
  {'min_ver':'15.1F', 'fixed_ver':'15.1F6-S12'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D151', 'model':'^SRX', 'fixed_display':'15.1X49-D151, 15.1X49-D160'},
  {'min_ver':'16.1', 'fixed_ver':'16.1R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
