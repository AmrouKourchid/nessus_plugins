#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151631);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2017-1087");
  script_xref(name:"JSA", value:"JSA11177");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11177)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11177
advisory.

  - An Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability, where
    named paths are globally scoped, meaning a process located in one jail can read and modify the content of
    POSIX shared memory objects created by a process in another jail or the host system of Juniper Networks
    Junos OS. As a result, a malicious user that has access to a jailed system is able to abuse shared memory
    by injecting malicious content in the shared memory region. This memory region might be executed by
    applications trusting the shared memory. This issue could lead to a Denial of Service (DoS) or local
    privilege escalation. (CVE-2017-1087)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2021-07-Security-Bulletin-Junos-OS-FreeBSD-SA-17-09-shm-POSIX-shm-allows-jails-to-access-global-namespace-CVE-2017-1087
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c260516f");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11177");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1087");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S9'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S11'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
