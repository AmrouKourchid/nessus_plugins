#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178670);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2018-0032");
  script_xref(name:"JSA", value:"JSA10866");

  script_name(english:"Juniper Junos OS Vulnerability (JSA10866)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA10866
advisory.

  - The receipt of a crafted BGP UPDATE can lead to a routing process daemon (RPD) crash and restart. Repeated
    receipt of the same crafted BGP UPDATE can result in an extended denial of service condition for the
    device. This issue only affects the specific versions of Junos OS listed within this advisory. Earlier
    releases are unaffected by this vulnerability. This crafted BGP UPDATE does not propagate to other BGP
    peers. Affected releases are Juniper Networks Junos OS: 16.1X65 versions prior to 16.1X65-D47; 17.2X75
    versions prior to 17.2X75-D91, 17.2X75-D110; 17.3 versions prior to 17.3R1-S4, 17.3R2; 17.4 versions prior
    to 17.4R1-S3, 17.4R2. (CVE-2018-0032)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2018-07-Security-Bulletin-Junos-OS-RPD-crash-when-receiving-a-crafted-BGP-UPDATE-CVE-2018-0032
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04e176a8");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10866");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0032");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'16.1X65', 'fixed_ver':'16.1X65-D47'},
  {'min_ver':'17.2X75', 'fixed_ver':'17.2X75-D110', 'fixed_display':'17.2X75-D110, 17.2X75-D91'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R1-S4', 'fixed_display':'17.3R1-S4, 17.3R2'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R1-S3', 'fixed_display':'17.4R1-S3, 17.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
