#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126925);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/24");

  script_cve_id("CVE-2018-0045");

  script_name(english:"Juniper JSA10879");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of the tested product installed on the remote host is 
prior to the fixed version in the advisory. It is, therefore, affected
by a denial of service vulnerability that exists in RPD daemon. An 
unauthenticated, remote attacker can exploit this issue, by continuously
sending a specific Draft-Rosen MVPN control packet, to repeatedly crash
the RPD process causing a prolonged denial of service as referenced in
the JSA10879 advisory. 
Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://supportportal.juniper.net/s/article/2018-10-Security-Bulletin-Junos-OS-RPD-daemon-crashes-due-to-receipt-of-specific-Draft-Rosen-MVPN-control-packet-in-Draft-Rosen-MVPN-configuration-CVE-2018-0045
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e224e68");
  # https://supportportal.juniper.net/s/article/2018-10-Security-Bulletin-Junos-OS-RPD-daemon-crashes-due-to-receipt-of-specific-Draft-Rosen-MVPN-control-packet-in-Draft-Rosen-MVPN-configuration-CVE-2018-0045
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e224e68");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10879");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0045");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/23");

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
  {'min_ver':'12.1X46', 'fixed_ver':'12.1X46-D77', 'model':'^SRX'},
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S10'},
  {'min_ver':'12.3X48', 'fixed_ver':'12.3X48-D70', 'model':'^SRX'},
  {'min_ver':'15.1', 'fixed_ver':'15.1R4-S9', 'fixed_display':'15.1R4-S9, 15.1R7'},
  {'min_ver':'15.1R6', 'fixed_ver':'15.1R6-S6'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D140', 'model':'^SRX'},
  {'min_ver':'15.1X53', 'fixed_ver':'15.1X53-D233', 'model':'^(EX23|EX34|NFX|QFX1|QFX511|QFX52)', 'fixed_display':'15.1X53-D233, 15.1X53-D471, 15.1X53-D490, 15.1X53-D59, 15.1X53-D67'},
  {'min_ver':'16.1', 'fixed_ver':'16.1R4-S9', 'fixed_display':'16.1R4-S9, 16.1R7'},
  {'min_ver':'16.1R5', 'fixed_ver':'16.1R5-S4'},
  {'min_ver':'16.1R6', 'fixed_ver':'16.1R6-S3'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R1-S6', 'fixed_display':'16.2R1-S6, 16.2R2-S6, 16.2R3'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R1-S7', 'fixed_display':'17.1R1-S7, 17.1R2-S7, 17.1R3'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R2-S4', 'fixed_display':'17.2R2-S4, 17.2R3'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R2-S2', 'fixed_display':'17.3R2-S2, 17.3R3'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R1-S3', 'fixed_display':'17.4R1-S3, 17.4R2'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
