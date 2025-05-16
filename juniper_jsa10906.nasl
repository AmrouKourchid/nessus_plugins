#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121066);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2019-0006");
  script_xref(name:"JSA", value:"JSA10906");

  script_name(english:"Juniper Junos Packet Forwarding Engine Potential RCE (JSA10906)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a potential remote code execution vulnerability due to
how the Packet Forwarding Engine manager (FXPC) handles HTTP packets.
An attacker could potentially crash the fxpc daemon or execute code.");
  # https://supportportal.juniper.net/s/article/2019-01-Security-Bulletin-Junos-OS-EX-QFX-and-MX-series-Packet-Forwarding-Engine-manager-FXPC-process-crashes-due-to-a-crafted-HTTP-packet-in-a-Virtual-Chassis-configuration-CVE-2019-0006
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe1931e7");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10906");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0006");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/10");

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
if (model !~ "^(Chassis|EX|MX|Platforms|QFX|Virtual)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'14.1X53', 'fixed_ver':'14.1X53-D47', 'model':'^(Chassis|EX|Platforms|QFX|Virtual)'},
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S3', 'model':'^(Chassis|EX|MX|Platforms|QFX|Virtual)'},
  {'min_ver':'15.1X53', 'fixed_ver':'15.1X53-D50', 'model':'^(Chassis|EX|Platforms|QFX|Virtual)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
