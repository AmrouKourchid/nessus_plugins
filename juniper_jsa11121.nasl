#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178663);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2021-0226");
  script_xref(name:"JSA", value:"JSA11121");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11121)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11121
advisory.

  - On Juniper Networks Junos OS Evolved devices, receipt of a specific IPv6 packet may cause an established
    IPv6 BGP session to terminate, creating a Denial of Service (DoS) condition. Continued receipt and
    processing of this packet will create a sustained Denial of Service (DoS) condition. This issue does not
    affect IPv4 BGP sessions. This issue affects IBGP or EBGP peer sessions with IPv6. This issue affects:
    Juniper Networks Junos OS Evolved: 19.4 versions prior to 19.4R2-S3-EVO; 20.1 versions prior to
    20.1R2-S3-EVO; 20.2 versions prior to 20.2R2-S1-EVO; 20.3 versions prior to 20.3R2-EVO. This issue does
    not affect Juniper Networks Junos OS releases. (CVE-2021-0226)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2021-04-Security-Bulletin-Junos-OS-Evolved-The-IPv6-BGP-session-will-flap-due-to-receipt-of-a-specific-IPv6-packet
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34e63856");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11121");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0226");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
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
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S3-EVO'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S3-EVO'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S1-EVO'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
