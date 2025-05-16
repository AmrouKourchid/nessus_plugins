#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0131-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(234644);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/21");

  script_cve_id("CVE-2024-51744");

  script_name(english:"openSUSE 15 Security Update : coredns (openSUSE-SU-2025:0131-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2025:0131-1 advisory.

    - Update to version 1.12.1:
      * core: Increase CNAME lookup limit from 7 to 10 (#7153)
      * plugin/kubernetes: Fix handling of pods having DeletionTimestamp set
      * plugin/kubernetes: Revert 'only create PTR records for endpoints with
        hostname defined'
      * plugin/forward: added option failfast_all_unhealthy_upstreams to return
        servfail if all upstreams are down
      * bump dependencies, fixing boo#1239294 and boo#1239728

    - Update to version 1.12.0:
      * New multisocket plugin - allows CoreDNS to listen on multiple sockets
      * bump deps

    - Update to version 1.11.4:
      * forward plugin: new option next, to try alternate upstreams when receiving
        specified response codes upstreams on (functions like the external plugin
        alternate)
      * dnssec plugin: new option to load keys from AWS Secrets Manager
      * rewrite plugin: new option to revert EDNS0 option rewrites in responses

    - Update to version 1.11.3+git129.387f34d:
      * fix CVE-2024-51744 (bsc#1232991)
        build(deps): bump github.com/golang-jwt/jwt/v4 from 4.5.0 to 4.5.1 (#6955)
      * core: set cache-control max-age as integer, not float (#6764)
      * Issue-6671: Fixed the order of plugins. (#6729)
      * `root`: explicit mark `dnssec` support (#6753)
      * feat: dnssec load keys from AWS Secrets Manager (#6618)
      * fuzzing: fix broken oss-fuzz build (#6880)
      * Replace k8s.io/utils/strings/slices by Go stdlib slices (#6863)
      * Update .go-version to 1.23.2 (#6920)
      * plugin/rewrite: Add 'revert' parameter for EDNS0 options (#6893)
      * Added OpenSSF Scorecard Badge (#6738)
      * fix(cwd): Restored backwards compatibility of Current Workdir (#6731)
      * fix: plugin/auto: call OnShutdown() for each zone at its own OnShutdown() (#6705)
      * feature: log queue and buffer memory size configuration (#6591)
      * plugin/bind: add zone for link-local IPv6 instead of skipping (#6547)
      * only create PTR records for endpoints with hostname defined (#6898)
      * fix: reverter should execute the reversion in reversed order (#6872)
      * plugin/etcd: fix etcd connection leakage when reload (#6646)
      * kubernetes: Add useragent (#6484)
      * Update build (#6836)
      * Update grpc library use (#6826)
      * Bump go version from 1.21.11 to 1.21.12 (#6800)
      * Upgrade antonmedv/expr to expr-lang/expr (#6814)
      * hosts: add hostsfile as label for coredns_hosts_entries (#6801)
      * fix TestCorefile1 panic for nil handling (#6802)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239728");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EUVFYQAJREBRWHGVJH4PINWMTHG2NH7G/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cf715df");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-51744");
  script_set_attribute(attribute:"solution", value:
"Update the affected coredns and / or coredns-extras packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-51744");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coredns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coredns-extras");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'coredns-1.12.1-bp156.4.6.5', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'coredns-extras-1.12.1-bp156.4.6.5', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'coredns / coredns-extras');
}
