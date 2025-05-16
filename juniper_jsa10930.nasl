#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124327);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2019-0008");

  script_name(english:"Juniper JSA10930");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to
tested version. It is, therefore, affected by a stack based overflow 
vulnerability in the Junos OS Packet Forwarding Engine manager (FXPC)
process on QFX5000 series. A remote attacker can exploit it which can
lead to a remote code execution  as referenced in the JSA10930 advisory.
Note that Nessus has not tested for this issue but has instead relied only
 on the application's self-reported version number.");
  # https://supportportal.juniper.net/s/article/2019-04-Security-Bulletin-QFX5000-Series-EX4300-EX4600-A-stack-buffer-overflow-vulnerability-in-Packet-Forwarding-Engine-manager-FXPC-process-CVE-2019-0008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad993bfb");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10930");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

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
  {'min_ver':'14.1X53', 'fixed_ver':'14.1X53-D51'},
  {'min_ver':'15.1X53', 'fixed_ver':'15.1X53-D235'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R3'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R3'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S2'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S1', 'fixed_display':'17.4R2-S1, 17.4R3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S1'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2'},
  {'min_ver':'18.2X75', 'fixed_ver':'18.2X75-D30'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
