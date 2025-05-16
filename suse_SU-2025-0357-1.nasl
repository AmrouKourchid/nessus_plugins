#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0357-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(215181);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/10");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0357-1");

  script_name(english:"openSUSE 15 Security Update : etcd (SUSE-SU-2025:0357-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2025:0357-1 advisory.

    Security
    Update to version 3.5.18:

      * Ensure all goroutines created by StartEtcd to exit before
        closing the errc
      * mvcc: restore tombstone index if it's first revision
      * Bump go toolchain to 1.22.11
      * Avoid deadlock in etcd.Close when stopping during bootstrapping
      * etcdutl/etcdutl: use datadir package to build wal/snapdir
      * Remove duplicated <-s.ReadyNotify()
      * Do not wait for ready notify if the server is stopping
      * Fix mixVersion test case: ensure a snapshot to be sent out
      * *: support custom content check offline in v2store
      * Print warning message for deprecated flags if set
      * fix runtime error: comparing uncomparable type
      * add tls min/max version to grpc proxy

    - Fixing a configuration data loss bug:
      Fillup really really wants that the template and the target file
      actually follow the sysconfig format. The current config and the
      current template do not fulfill this requirement.
      Move the current /etc/sysconfig/etcd to /etc/default/etcd and
      install a new sysconfig file which only adds the ETCD_OPTIONS
      option, which is actually used by the unit file.
      This also makes it a bit cleaner to move etcd to use
      --config-file in the long run.

    - Update etcd configuration file based on
      https://github.com/etcd-io/etcd/blob/v3.5.17/etcd.conf.yml.sample

    Update to version 3.5.17:

      * fix(defrag): close temp file in case of error
      * Bump go toolchain to 1.22.9
      * fix(defrag): handle defragdb failure
      * fix(defrag): handle no space left error
      * [3.5] Fix risk of a partial write txn being applied
      * [serverWatchStream] terminate recvLoop on sws.close()

    Update to version 3.5.16:

      * Bump go toolchain to 1.22.7
      * Introduce compaction sleep interval flag
      * Fix passing default grpc call options in Kubernetes client
      * Skip leadership check if the etcd instance is active processing
        heartbeats
      * Introduce Kubernetes KV interface to etcd client

    Update to version 3.5.15:

      * Differentiate the warning message for rejected client and peer
      * connections
      * Suppress noisy basic auth token deletion log
      * Support multiple values for allowed client and peer TLS
        identities(#18015)
      * print error log when validation on conf change failed

    Update to version 3.5.14:

      * etcdutl: Fix snapshot restore memory alloc issue
      * server: Implement WithMmapSize option for backend config
      * gRPC health server sets serving status to NOT_SERVING on defrag
      * server/mvcc: introduce compactBeforeSetFinishedCompact
        failpoint
      * Update the compaction log when bootstrap and update compact's
        signature
      * add experimental-snapshot-catchup-entries flag.
      * Fix retry requests when receiving ErrGPRCNotSupportedForLearner

    Update to version 3.5.13:

      * Fix progress notification for watch that doesn't get any events
      * pkg/types: Support Unix sockets in NewURLS
      * added arguments to the grpc-proxy: dial-keepalive-time,
        dial-keepalive-timeout, permit-without-stream
      * server: fix comment to match function name
      * Make CGO_ENABLED configurable for etcd 3.5
      * etcdserver: drain leaky goroutines before test completed

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1095184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183703");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-February/020281.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36eafd8d");
  script_set_attribute(attribute:"solution", value:
"Update the affected etcd and / or etcdctl packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^SUSE") audit(AUDIT_OS_NOT, "openSUSE");
var os_ver = pregmatch(pattern: "^(SUSE[\d.]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'openSUSE 15', 'openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE (' + os_ver + ')', cpu);

var pkgs = [
    {'reference':'etcd-3.5.18-150000.7.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'etcdctl-3.5.18-150000.7.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'etcd / etcdctl');
}
