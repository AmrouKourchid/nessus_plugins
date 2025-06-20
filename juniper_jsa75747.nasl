#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193496);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2024-21606");
  script_xref(name:"JSA", value:"JSA75747");

  script_name(english:"Juniper Junos OS Vulnerability (JSA75747)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA75747
advisory.

  - A Double Free vulnerability in the flow processing daemon (flowd) of Juniper Networks Junos OS on SRX
    Series allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). In a remote
    access VPN scenario, if a tcp-encap-profile is configured and a sequence of specific packets is
    received, a flowd crash and restart will be observed. This issue affects Juniper Networks Junos OS on SRX
    Series: * All versions earlier than 20.4R3-S8; * 21.2 versions earlier than 21.2R3-S6; * 21.3 versions
    earlier than 21.3R3-S5; * 21.4 versions earlier than 21.4R3-S5; * 22.1 versions earlier than 22.1R3-S3; *
    22.2 versions earlier than 22.2R3-S3; * 22.3 versions earlier than 22.3R3-S1; * 22.4 versions earlier than
    22.4R2-S2, 22.4R3. (CVE-2024-21606)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-01-Security-Bulletin-Junos-OS-SRX-Series-flowd-will-crash-when-tcp-encap-is-enabled-and-specific-packets-are-received-CVE-2024-21606
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?543a6301");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA75747");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^SRX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S8', 'model':'^SRX'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S6', 'model':'^SRX'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5', 'model':'^SRX'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S5', 'model':'^SRX'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S3', 'model':'^SRX'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S3', 'model':'^SRX'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S1', 'model':'^SRX'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S2', 'model':'^SRX', 'fixed_display':'22.4R2-S2, 22.4R3'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
