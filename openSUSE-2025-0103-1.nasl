#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0103-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(233307);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/25");

  script_cve_id("CVE-2022-27664", "CVE-2025-22868");

  script_name(english:"openSUSE 15 Security Update : cadvisor (openSUSE-SU-2025:0103-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2025:0103-1 advisory.

    - update to 0.52.1:

      * Make resctrl optional/pluggable

    - update to 0.52.0:

      * bump containerd related deps: api v1.8.0; errdefs v1.0.0; ttrpc v1.2.6
      * chore: Update Prometheus libraries
      * bump runc to v1.2.4
      * Add Pressure Stall Information Metrics
      * Switch to opencontainers/cgroups repository (includes update
        from golang 1.22 to 1.24)
      * Bump to newer opencontainers/image-spec @ v1.1.1

    - update to 0.49.2:

      * Cp fix test
      * Revert 'reduce_logs_for_kubelet_use_crio'

     - CVE-2025-22868: golang.org/x/oauth2/jws: Unexpected memory consumption during token parsing in
    golang.org/x/oauth2  (boo#1239291)

    - Update to version 0.49.1:

      * build docker - add --provenance=false flag
      * Remove s390x support
      * Disable libipmctl in build
      * Ugrade base image to 1.22 and alpine 3.18
      * fix type of C.malloc in cgo
      * Bump runc to v1.1.12
      * Bump to bullseye
      * Remove section about canary image
      * Add note about WebUI auth
      * Remove mentions of accelerator from the docs
      * reduce_logs_for_kubelet_use_crio
      * upgrade actions/checkout and actions/setup-go and actions/upload-artifact
      * build(deps): bump golang.org/x/crypto from 0.14.0 to 0.17.0 in /cmd
      * add cadvisor and crio upstream changes
      * Avoid using container/podman in manager.go
      * container: skip checking for files in non-existent directories.
      * Adjust the log level of Initialize Plugins
      * add ignored device
      * fix: variable naming
      * build(deps): bump golang.org/x/net from 0.10.0 to 0.17.0 in /cmd
      * manager: require higher verbosity level for container info misses
      * Information should be logged on increased verbosity only
      * Running do mod tidy
      * Running go mod tidy
      * Running go mod tidy
      * container/libcontainer: Improve limits file parsing perf
      * container/libcontainer: Add limit parsing benchmark
      * build(deps): bump github.com/cyphar/filepath-securejoin in /cmd
      * build(deps): bump github.com/cyphar/filepath-securejoin
      * Set verbosity after flag definition
      * fix: error message typo
      * vendor: bump runc to 1.1.9
      * Switch to use busybox from registry.k8s.io
      * Bump golang ci lint to v1.54.1
      * Bump github.com/docker/docker in /cmd
      * Bump github.com/docker/docker
      * Bump github.com/docker/distribution in /cmd
      * Bump github.com/docker/distribution
      * Update genproto dependency to isolated submodule
      * remove the check for the existence of NFS files, which will cause unnecessary requests.
      * reduce inotify watch
      * fix performance degradation of NFS
      * fix: fix type issue
      * fix: fix cgo memory leak
      * ft: export memory kernel usage
      * sysinfo: Ignore 'hidden' sysfs device entries
      * Increasing required verbosity level
      * Patch to fix issue 2341
      * podman support: Enable Podman support.
      * podman support: Create Podman handler.
      * podman support: Changes in Docker handler.
      * unit test: machine_swap_bytes
      * Add documentation for machine_swap_bytes metric
      * Add a machine_swap_bytes metric
      * fix: add space trimming for label allowlist
      * Upgrade to blang/semver/v4 v4.0.0
      * docs(deploy/k8s): remote build for kustomize
      * Update dependencies
      * Change filepaths to detect online CPUs
      * Update actions/checkout to v3
      * Fix flags typo
      * Updating location of kubernetes/pause image
      * Using t.TempDir() in tests
      * Unit test: MachineInfo Clone() method
      * Bugfix: MachineInfo Clone() - clone SwapCapacity
      * Optimize network metrics collection
      * Removing calls to deprecates io/ioutil package
      * Updating minimum Go version to 1.19
      * Request the pid of another container if current pid is not longer valid
      * Restructure
      * Add CRI-O client timeout setting
      * Set containerd grpc.MaxCallRecvMsgSize to 16MB
      * Fix asset build
      * feat(logging): add verbosity to non-NUMA node warning
      * add nerdctl to ignoredDevices
      * nvm: Change the 'no NVM devices' log.
      * nvm: Fix typo.
      * Fix CVE-2022-27664 (#3248)
      * resctrl: Reduce size and mode files check (#3264)
      * readme: Update Creatone contributor info. (#3265)
      * Fix comment to refer to correct client
      * build: bump golang to 1.20
      * ci: Update golang ci-lint to v1.51.2
      * build: Update shebang to python3
      * Revert 'dockerfile: Fix typo in go build tags.'
      * Decreasing verbosity level for 'Cannot read vendor id correctly, set empty'
      * dockerfile: Fix typo in go build tags.
      * deps: Move from cloud.google.com/go/compute -> cloud.google.com/go
      * use memory.min for reservation memory instead of high
      * Mark GOPATH as git safe.directory to fix CI build
      * switch to gomodule/redigo from garyburd/redigo
      * update go.mod/sum both in root and cmd/
      * Drop accelerator metrics and nvidia integration
      * Add s390x support for docker image
      * typo in MachineInfo spec for SwapCapacity
      * add support for swap in machine/info

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239291");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4JTZ2DTLVURMW7SOEALLXE6GW75RG2MM/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?584acb55");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-27664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22868");
  script_set_attribute(attribute:"solution", value:
"Update the affected cadvisor package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cadvisor");
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
    {'reference':'cadvisor-0.52.1-bp156.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cadvisor');
}
