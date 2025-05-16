#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139032);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2020-1648");
  script_xref(name:"JSA", value:"JSA11035");

  script_name(english:"Junos OS: RPD crash when processing a specific BGP packet (JSA11035)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service (DoS) vulnerability. Processing
a specific BGP packet can lead to a routing process daemon (RPD) crash and restart. This issue can occur even before the
BGP session with the peer is established. Repeated receipt of this specific BGP packet can result in an extended DoS
condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2020-07-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-RPD-crash-when-processing-a-specific-BGP-packet-CVE-2020-1648
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64ae2374");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11035");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1648");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.2X75', 'fixed_ver':'18.2X75-D53', 'fixed_display':'18.2X75-D53, 18.2X75-D60.2, 18.2X75-D65.1, 18.2X75-D70'},
  {'min_ver':'18.2X75-D50.8', 'fixed_ver':'18.2X75-D52.8'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1'},
  {'min_ver':'19.4-EVO', 'fixed_ver':'19.4R2-S2-EVO'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R1-S2', 'fixed_display':'20.1R1-S2, 20.1R2'},
  {'min_ver':'20.1-EVO', 'fixed_ver':'20.1R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
