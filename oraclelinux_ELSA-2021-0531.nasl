##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-0531.
##

include('compat.inc');

if (description)
{
  script_id(146640);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2020-14370");

  script_name(english:"Oracle Linux 8 : container-tools:ol8 (ELSA-2021-0531)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2021-0531 advisory.

    buildah
    [1.16.7-4.0.1]
    - Handling redirect from the docker registry [Orabug: 29874238] (Nikita Gerasimov)

    [1.16.7-4]
    - update to the latest content of https://github.com/containers/buildah/tree/release-1.16
      (https://github.com/containers/buildah/commit/aaed66b)
    - Related: #1888571

    [1.16.7-3]
    - revert back to buildah-1.16 for the quarterly release
    - Related: #1888571

    [1.19.0-2]
    - bump version to refrect buildah upgrade
    - Related: #1888571

    [1.16.7-2]
    - bump to release-1.19 branch
    - Related: #1888571

    [1.16.5-5]
    - update to the latest content of https://github.com/containers/buildah/tree/release-1.16
      (https://github.com/containers/buildah/commit/56ed75b)
    - Related: #1888571

    [1.16.5-4]
    - simplify spec file
    - use short commit ID in tarball name
    - Related: #1888571

    [1.16.5-3]
    - update to the latest content of https://github.com/containers/buildah/tree/release-1.16
      (https://github.com/containers/buildah/commit/9e02bf9)
    - Related: #1888571

    [1.16.5-2]
    - use shortcommit ID in branch tarball name
    - Related: #1888571

    [1.16.5-1]
    - synchronize with stream-container-tools-rhel8-rhel-8.4.0
    - Related: #1888571

    cockpit-podman
    [27.1-3]
    - run much more tests - patch from Matej Marusak
    - Related: #1888571

    [27.1-2]
    - gating tests - always set VM password
    - Related: #1888571

    [27.1-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/27.1
    - Related: #1888571

    [27-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/27
    - Related: #1888571

    [26-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/26
    - Related: #1888571

    [25-5]
    - remove redundant patch
    - Related: #1888571

    [25-4]
    - replace docker.io with quay.io for gating tests due do
      docker.io new pull rate limit requirements
    - Related: #1888571

    [25-3]
    - test: Cleanup images before pulling the ones we need - thanks to Matej Marusak
    - Related: #1888571

    [25-2]
    - remove hack in tests
    - add LICENSE
    - Related: #1888571

    [25-1]
    - synchronize with stream-container-tools-rhel8-rhel-8.4.0
    - Related: #1888571

    conmon
    [2:2.0.22-3]
    - exclude i686 as golang is not suppoerted there
    - Related: #1888571

    [2:2.0.22-2]
    - add BR: golang, go-md2man
    - add man pages
    - Related: #1888571

    [2:2.0.22-1]
    - update to https://github.com/containers/conmon/releases/tag/v2.0.22
    - Related: #1888571

    [2:2.0.21-3]
    - simplify spec
    - Related: #1888571

    [2:2.0.21-2]
    - be sure to harden the linked binary
    - compile with debuginfo enabled
    - Related: #1888571

    [2:2.0.21-1]
    - synchronize with stream-container-tools-rhel8-rhel-8.4.0
    - Related: #1888571

    containernetworking-plugins
    [0.9.0-1]
    - update to https://github.com/containernetworking/plugins/releases/tag/v0.9.0
    - Related: #1888571

    container-selinux
    [2:2.155.0-1]
    - update to https://github.com/containers/container-selinux/releases/tag/v2.155.0
    - Related: #1888571

    [2:2.154.0-1]
    - update to
      https://github.com/containers/container-selinux/releases/tag/v2.154.0
    - Related: #1888571

    [2:2.153.0-1]
    - update to
      https://github.com/containers/container-selinux/releases/tag/v2.153.0
    - Related: #1888571

    [2:2.152.0-1]
    - update to
      https://github.com/containers/container-selinux/releases/tag/v2.152.0
    - Related: #1888571

    [2:2.151.0-1]
    - update to https://github.com/containers/container-selinux/releases/tag/v2.151.0
    - Related: #1888571

    [2:2.150.0-1]
    - update to https://github.com/containers/container-selinux/releases/tag/v2.150.0
    - Related: #1888571

    [2:2.145.0-1]
    - synchronize with stream-container-tools-rhel8-rhel-8.4.0
    - Resolves: #1873064

    criu
    [3.15-1]
    - update to https://github.com/checkpoint-restore/criu/releases/tag/v3.15
    - Related: #1888571

    [3.14-2]
    - fix 'Need to fix bugs found by coverity.'
    - Related: #1821193

    [3.14-1]
    - synchronize containter-tools 8.3.0 with 8.2.1
    - Related: #1821193

    crun
    [0.16-2]
    - exclude i686 because of build failures
    - Related: #1888571

    [0.16-1]
    - update to https://github.com/containers/crun/releases/tag/0.16
    - Related: #1888571

    [0.15.1-1]
    - update to https://github.com/containers/crun/releases/tag/0.15.1
    - Related: #1888571

    [0.15-2]
    - backport 'exec: check read bytes from sync' (gscrivan@redhat.com)
      (https://github.com/containers/crun/issues/511)
    - Related: #1888571

    [0.15-1]
    - synchronize with stream-container-tools-rhel8-rhel-8.4.0
    - Related: #1888571

    fuse-overlayfs
    [1.3.0-2]
    - disable openat2 syscall again - still unsupported in current RHEL8 kernel
    - Resolves: #1921863

    [1.3.0-1]
    - update to https://github.com/containers/fuse-overlayfs/releases/tag/v1.3.0
    - Related: #1888571

    [1.2.0-3]
    - be sure to harden the linked binary
    - Related: #1888571

    [1.2.0-2]
    - ensure fuse module is loaded
    - Related: #1888571

    [1.2.0-1]
    - synchronize with stream-container-tools-rhel8-rhel-8.4.0
    - Related: #1888571

    libslirp
    oci-seccomp-bpf-hook
    [1.2.0-1]
    - update to https://github.com/containers/oci-seccomp-bpf-hook/releases/tag/v1.2.0
    - Related: #1888571

    podman
    [2.2.1-7.0.1]
    - Handling redirect from the docker registry [Orabug: 29874238] (Nikita Gerasimov)

    [2.2.1-7]
    - Resolves: #1925928 - Fix varlink GetVersion()
    - Upstream PR: https://github.com/containers/podman/pull/9274

    [2.2.1-6]
    - update to the latest content of https://github.com/containers/podman/tree/v2.2.1-rhel
      (https://github.com/containers/podman/commit/1741f15)
    - Related: #1888571

    [2.2.1-5]
    - update to the latest content of https://github.com/containers/podman/tree/v2.2.1-rhel
      (https://github.com/containers/podman/commit/b5bc6a7)
    - Related: #1877188

    [2.2.1-4]
    - add Requires: oci-runtime
    - Related: #1888571

    [2.2.1-3]
    - update to the latest content of https://github.com/containers/podman/tree/v2.2.1-rhel
      (https://github.com/containers/podman/commit/14c35f6)
    - Related: #1888571

    [2.2.1-2]
    - update to https://github.com/containers/dnsname/releases/tag/v1.1.1

    [2.2.1-1]
    - update to the latest content of https://github.com/containers/podman/tree/v2.2.1-rhel
      (https://github.com/containers/podman/commit/a0d478e)
    - Related: #1888571

    [2.2.0-2]
    - attempt to fix gatng tests
    - Related: #1888571

    [2.2.0-1]
    - update to https://github.com/containers/podman/releases/tag/v2.2.0
    - Related: #1888571

    [2.1.1-3]
    - attempt to fix linker error with golang-1.15
    - add Requires: httpd-tools to tests, needed to work around
      missing htpasswd in docker registry image, thanks to Ed Santiago
    - Related: #1888571

    [2.1.1-2]
    - update to the latest content of https://github.com/containers/podman/tree/v2.1.1-rhel
      (https://github.com/containers/podman/commit/450615a)
    - Resolves: #1873204
    - Resolves: #1884668

    [2.1.1-1]
    - update podman to 2.1.1-rhel
    - Resolves: #1743687
    - Resolves: #1811570
    - Resolves: #1869322
    - Resolves: #1678546
    - Resolves: #1853455
    - Resolves: #1874271

    python-podman-api
    [1.2.0-0.2.gitd0a45fe]
    - revert update to 1.6.0 due to new python3-pbr dependency which
      is not in RHEL
    - Related: RHELPLAN-25139

    [1.2.0-0.1.gitd0a45fe]
    - Initial package

    runc
    [1.0.0-70.rc92]
    - add Provides: oci-runtime = 1
    - Related: #1888571

    [1.0.0-69.rc92]
    - still use ExcludeArch as go_arches macro is broken for 8.4
    - Related: #1888571

    skopeo
    [1:1.2.0-9.0.1]
    - Handling redirect from the docker registry [Orabug: 29874238] (Nikita Gerasimov)
    - Add oracle registry into the conf file [Orabug: 29845934 31306708]

    [1:1.2.0-9]
    - upload proper source tarball
    - Related: #1888571

    [1:1.2.0-8]
    - revert back to version aimed at 8.3.1 - skopeo-1.2.0
    - also downgrade versions of vendored libraries
    - Related: #1888571

    [1:1.2.1-1]
    - update vendored component versions
    - update to the latest content of https://github.com/containers/skopeo/tree/release-1.2
      (https://github.com/containers/skopeo/commit/2e90a8a)
    - Related: #1888571

    [1:1.2.0-6]
    - always build with debuginfo
    - use less verbose output when compiling
    - Related: #1888571

    [1:1.2.0-5]
    - re-sync config files
    - assure events_logger = 'file'
    - Related: #1888571

    [1:1.2.0-4]
    - change default logging mechanism to use for container engine events
      in containers.conf to be events_logger = 'file' - it should fix
      RHEL gating tests for podman nonroot (thanks to Dan Walsh)
    - Related: #1888571

    [1:1.2.0-3]
    - simplify spec file
    - use short commit ID in tarball name
    - Related: #1888571

    [1:1.2.0-2]
    - use shortcommit ID in branch tarball name
    - Related: #1888571

    [1:1.2.0-1]
    - synchronize with stream-container-tools-rhel8-rhel-8.4.0
    - Related: #1888571

    slirp4netns
    [1.1.8-1]
    - update to
      https://github.com/rootless-containers/slirp4netns/releases/tag/v1.1.8
    - Related: #1888571

    [1.1.7-2]
    - exclude i686 because of build failures
    - Related: #1888571

    [1.1.7-1]
    - update to
      https://github.com/rootless-containers/slirp4netns/releases/tag/v1.1.7
    - Related: #1888571

    [1.1.6-2]
    - - be sure to harden the linked binary
    - Related: #1888571

    [1.1.6-1]
    - update to
      https://github.com/rootless-containers/slirp4netns/releases/tag/v1.1.6
    - Related: #1888571

    udica
    [0.2.4-1]
    - update to https://github.com/containers/udica/releases/tag/v0.2.4
    - Related: #1888571

    [0.2.3-1]
    - synchronize with stream-container-tools-rhel8-rhel-8.4.0
    - Related: #1888571

    [0.2.2-1]
    - https://github.com/containers/udica/releases/tag/v0.2.2
    - Related: #1821193

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-0531.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14370");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cockpit-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:crun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libslirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libslirp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oci-seccomp-bpf-hook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-podman-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:skopeo-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:udica");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/container-tools');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:ol8');
if ('ol8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module container-tools:' + module_ver);

var appstreams = {
    'container-tools:ol8': [
      {'reference':'buildah-1.16.7-4.0.1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-tests-1.16.7-4.0.1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cockpit-podman-27.1-3.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'conmon-2.0.22-3.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'container-selinux-2.155.0-1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containernetworking-plugins-0.9.0-1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containers-common-1.2.0-9.0.1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'crit-3.15-1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-0.16-2.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.3.0-2.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.3.1-1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.3.1-1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.0-1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-2.2.1-7.0.1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-catatonit-2.2.1-7.0.1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-docker-2.2.1-7.0.1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-plugins-2.2.1-7.0.1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-remote-2.2.1-7.0.1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-tests-2.2.1-7.0.1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-podman-api-1.2.0-0.2.gitd0a45fe.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-70.rc92.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'skopeo-1.2.0-9.0.1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-tests-1.2.0-9.0.1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'slirp4netns-1.1.8-1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.4-1.module+el8.3.1+9659+c1901784', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-1.16.7-4.0.1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-tests-1.16.7-4.0.1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cockpit-podman-27.1-3.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'conmon-2.0.22-3.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'container-selinux-2.155.0-1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containernetworking-plugins-0.9.0-1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containers-common-1.2.0-9.0.1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'crit-3.15-1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-0.16-2.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.3.0-2.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.3.1-1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.3.1-1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.0-1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-2.2.1-7.0.1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-catatonit-2.2.1-7.0.1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-docker-2.2.1-7.0.1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-plugins-2.2.1-7.0.1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-remote-2.2.1-7.0.1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-tests-2.2.1-7.0.1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-podman-api-1.2.0-0.2.gitd0a45fe.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-70.rc92.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'skopeo-1.2.0-9.0.1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-tests-1.2.0-9.0.1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'slirp4netns-1.1.8-1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.4-1.module+el8.3.1+9659+c1901784', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:ol8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-tests / cockpit-podman / etc');
}
