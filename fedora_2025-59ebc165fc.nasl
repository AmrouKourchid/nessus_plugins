#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2025-59ebc165fc
#

include('compat.inc');

if (description)
{
  script_id(235106);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/03");

  script_cve_id("CVE-2025-21605");
  script_xref(name:"FEDORA", value:"2025-59ebc165fc");

  script_name(english:"Fedora 40 : valkey (2025-59ebc165fc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2025-59ebc165fc advisory.

    **Valkey 8.0.3**  -  Released Wed 23 Apr 2025

    Upgrade urgency SECURITY: This release includes security fixes we recommend you
    apply as soon as possible.

    Bug fixes

    * Optimize RDB load performance and fix cluster mode resizing on replica side (#1199)
    * Fix memory leak in forgotten node ping ext code path (#1574)
    * Fix cluster info sent stats for message with light header (#1563)
    * Fix module LatencyAddSample still work when latency-monitor-threshold is 0 (#1541)
    * Fix potential crash in radix tree recompression of huge keys (#1722)
    * Fix error SSL routines::bad length when connTLSWrite is called second time with smaller buffer (#1737)
    * Fix temp file leak druing replication error handling (#1721)
    * Fix ACL LOAD crash on replica since the primary client don't has a user (#1842)
    * Fix RANDOMKEY infinite loop during CLIENT PAUSE (#1850)
    * fix: add samples to stream object consumer trees (#1825)
    * Fix cluster slot stats assertion during promotion of replica (#1950)
    * Fix panic in primary when blocking shutdown after previous block with timeout (#1948)
    * Ignore stale gossip packets that arrive out of order (#1777)
    * Fix incorrect lag reported in XINFO GROUPS (#1952)
    * Avoid shard id update of replica if not matching with primary shard id (#573)

    Security fixes

    * **CVE-2025-21605** Limit output buffer for unauthenticated clients (#1993)

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-59ebc165fc");
  script_set_attribute(attribute:"solution", value:
"Update the affected valkey package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21605");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:valkey");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'valkey-8.0.3-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'valkey');
}
