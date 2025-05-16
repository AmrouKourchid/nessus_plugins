#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189374);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/01");

  script_cve_id("CVE-2024-21617");
  script_xref(name:"JSA", value:"JSA75758");

  script_name(english:"Juniper Junos OS Vulnerability (JSA75758)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA75758
advisory.

  - An Incomplete Cleanup vulnerability in Nonstop active routing (NSR) component of Juniper Networks Junos OS
    allows an adjacent, unauthenticated attacker to cause memory leak leading to Denial of Service (DoS). On
    all Junos OS platforms, when NSR is enabled, a BGP flap will cause memory leak. A manual reboot of the
    system will restore the services. Note: NSR is not supported on the SRX Series and is therefore not
    affected by this vulnerability. The memory usage can be monitored using the below commands. user@host>
    show chassis routing-engine no-forwarding user@host> show system memory | no-more This issue affects:
    Juniper Networks Junos OS * 21.2 versions earlier than 21.2R3-S5; * 21.3 versions earlier than 21.3R3-S4;
    * 21.4 versions earlier than 21.4R3-S4; * 22.1 versions earlier than 22.1R3-S2; * 22.2 versions earlier
    than 22.2R3-S2; * 22.3 versions earlier than 22.3R2-S1, 22.3R3; * 22.4 versions earlier than 22.4R1-S2,
    22.4R2. This issue does not affect Junos OS versions earlier than 20.4R3-S7. (CVE-2024-21617)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-01-Security-Bulletin-Junos-OS-BGP-flap-on-NSR-enabled-devices-causes-memory-leak-CVE-2024-21617
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7baa371");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA75758");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21617");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S5'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S4'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S4'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S2'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S2'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S1', 'fixed_display':'22.3R2-S1, 22.3R3'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R1-S2', 'fixed_display':'22.4R1-S2, 22.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
