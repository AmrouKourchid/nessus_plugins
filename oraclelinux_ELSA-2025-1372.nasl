#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2025-1372.
##

include('compat.inc');

if (description)
{
  script_id(216327);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id("CVE-2024-11218");

  script_name(english:"Oracle Linux 8 : container-tools:ol8 (ELSA-2025-1372)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2025-1372 advisory.

    aardvark-dns
    buildah
    [2:1.33.12-1]
    - update to the latest content of https://github.com/containers/buildah/tree/release-1.33
      (https://github.com/containers/buildah/commit/58af1cd)
    - Resolves: RHEL-67612

    cockpit-podman
    conmon
    containernetworking-plugins
    containers-common
    [1-82.0.1]
    - Updated removed references [Orabug: 33473101] (Alex Burmashev)
    - Adjust registries.conf (Nikita Gerasimov)
    - remove references to RedHat registry (Nikita Gerasimov)

    [2:1-82]
    - update vendored components
    - Resolves: RHEL-40801

    [2:1-81]
    - Update shortnames from Pyxis
    - Related: Jira:RHEL-2110

    [2:1-80]
    - bump release to preserve upgrade path
    - Resolves: Jira:RHEL-12277

    [2:1-59]
    - update vendored components
    - Related: Jira:RHEL-2110

    [2:1-58]
    - update vendored components
    - Related: Jira:RHEL-2110

    [2:1-57]
    - fix shortnames for rhel-minimal
    - Related: Jira:RHEL-2110

    [2:1-56]
    - implement GPG auto updating mechanism from redhat-release
    - Resolves: #RHEL-2110

    [2:1-55]
    - update GPG keys to the current content of redhat-release
    - Resolves: #RHEL-3164

    [2:1-54]
    - update vendored components and shortnames
    - Related: #2176055

    [2:1-53]
    - update vendored components
    - Related: #2176055

    [2:1-52]
    - update vendored components
    - Related: #2176055

    [2:1-51]
    - be sure default_capabilities contain SYS_CHROOT
    - Resolves: #2166195

    [2:1-50]
    - improve shortnames generation
    - Related: #2176055

    [2:1-49]
    - update vendored components and configuration files
    - Related: #2123641

    [2:1-48]
    - update vendored components and configuration files
    - Related: #2123641

    [2:1-47]
    - enable NET_RAW capability for RHEL8 only
    - Related: #2123641

    [2:1-46]
    - update vendored components and configuration files
    - Related: #2123641

    [2:1-45]
    - update vendored components and configuration files
    - Related: #2123641

    [2:1-44]
    - update vendored components and configuration files
    - Related: #2123641

    [2:1-43]
    - update vendored components and configuration files
    - Related: #2123641

    [2:1-42]
    - update vendored components and configuration files
    - Related: #2123641

    [2:1-41]
    - add beta GPG key
    - Related: #2123641

    [2:1-40]
    - add beta keys to default-policy.json
    - Related: #2061390

    [2:1-39]
    - update shortnames
    - Related: #2061390

    [2:1-38]
    - arch limitation because of go-md2man (missing on i686)
    - Related: #2061390

    [2:1-37]
    - add install section
    - update vendored components
    - Related: #2061390

    [2:1-36]
    - remove aardvark-dns and netavark - packaged separately
    - update vendored components and configuration files
    - Related: #2061390

    [2:1-35]
    - update vendored components and configuration files
    - Related: #2061390

    [2:1-34]
    - remove rhel-els and update shortnames
    - Related: #2061390

    [2:1-33]
    - update shortnames
    - Related: #2061390

    [2:1-32]
    - additional fix for unqualified registries
    - Related: #2061390

    [2:1-31]
    - fix unqualified registries
    - Related: #2061390

    [2:1-30]
    - update vendored components and configuration files
    - Related: #2061390

    [2:1-29]
    - update unqualified registries list
    - Related: #2061390

    [2:1-28]
    - update aardvark-dns and netavark to 1.0.3
    - update vendored components
    - Related: #2061390

    [2:1-27]
    - add man page sources too
    - Related: #2061390

    [2:1-26]
    - add missing man pages from Fedora
    - Related: #2061390

    [2:1-25]
    - allow consuming aardvark-dns and netavark from upstream branch
    - Related: #2061390

    [2:1-24]
    - update to netavark and aardvark-dns 1.0.2
    - update vendored components
    - Related: #2061390

    [2:1-23]
    - update to netavark and aardvark-dns 1.0.1
    - Related: #2001445

    [2:1-22]
    - build rust packages with RUSTFLAGS set to make ExecShield happy
    - Related: #2001445

    [2:1-21]
    - do not specify infra_image in containers.conf
    - needed to resolve gating test failures
    - Related: #2001445

    [2:1-20]
    - update to netavark-1.0.0 and aardvark-dns-1.0.0
    - Related: #2001445

    [2:1-19]
    - package aarvark-dns and netavark as part of the containers-common
    - Related: #2001445

    [2:1-18]
    - update shortnames and vendored components
    - Related: #2001445

    [2:1-17]
    - containers.conf should contain network_backend = 'cni' in RHEL8.6
    - Related: #2001445

    [2:1-16]
    - update vendored components and configuration files
    - Related: #2001445

    [2:1-15]
    - sync vendored components
    - Related: #2001445

    [2:1-14]
    - sync vendored components
    - Related: #2001445

    [2:1-13]
    - update shortnames from Pyxis
    - Related: #2001445

    [2:1-12]
    - do not allow broken content from Pyxis to land in shortnames.conf
    - Related: #2001445

    [2:1-11]
    - sync vendored components
    - update shortnames from Pyxis
    - Related: #2001445

    [2:1-10]
    - use log_driver = 'journald' and events_logger = 'journald' for RHEL9
    - Related: #2001445

    [2:1-9]
    - consume seccomp.json from the oldest vendored version of c/common,
      not main branch
    - Related: #2001445

    [2:1-8]
    - update vendored components
    - Related: #2001445

    [2:1-7]
    - make log_driver = 'k8s-file' default in containers.conf
    - Related: #2001445

    [2:1-6]
    - sync vendored components
    - Related: #2001445

    [2:1-5]
    - update to the new vendored components
    - Related: #2001445

    [2:1-4]
    - update to the new vendored components
    - Related: #2001445

    [2:1-3]
    - update to the new vendored components
    - Related: #2001445

    [2:1-2]
    - synchronize config files for RHEL-8.5
    - Related: #1934415

    [2:1-1]
    - initial import
    - Related: #1934415

    container-selinux
    criu
    crun
    fuse-overlayfs
    libslirp
    netavark
    oci-seccomp-bpf-hook
    podman
    [4.9.4-19.0.1]
    - Fixes issue of container created in cgroupv2 not start in cgroupv1 [Orabug: 36136813]
    - Fixes container memory limit not set after host is rebooted with cgroupv2 [Orabug: 36136802]
    - Fixes issue of podman execvp error while using podmansh [Orabug: 36756665]

    [4:4.9.4-19]
    - update to the latest content of https://github.com/containers/podman/tree/v4.9-rhel
      (https://github.com/containers/podman/commit/bfdd4c2)
    - Resolves: RHEL-67601

    python-podman
    [4.9.0-3]
    - sync with release-4.9 branch
    - Resolves: RHEL-31069

    runc
    [1:1.1.12-6]
    - Add CPU affinity feature from Kir Kolishkin
    - Resolves: RHEL-74865

    skopeo
    slirp4netns
    udica

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2025-1372.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11218");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:aardvark-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cockpit-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:criu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:criu-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:crun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libslirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libslirp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netavark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oci-seccomp-bpf-hook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:skopeo-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:udica");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'aardvark-dns-1.10.1-2.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'buildah-1.33.12-1.module+el8.10.0+90509+b5e1e789', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'buildah-tests-1.33.12-1.module+el8.10.0+90509+b5e1e789', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'cockpit-podman-84.1-1.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'conmon-2.1.10-1.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'container-selinux-2.229.0-2.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containernetworking-plugins-1.4.0-5.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containers-common-1-82.0.1.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'crit-3.18-5.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.18-5.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-devel-3.18-5.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-libs-3.18-5.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-1.14.3-2.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.13-1.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.4.0-2.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.4.0-2.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netavark-1.10.3-1.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'oci-seccomp-bpf-hook-1.2.10-1.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-catatonit-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-docker-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-gvproxy-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-plugins-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-remote-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-tests-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'python3-criu-3.18-5.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-podman-4.9.0-3.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.1.12-6.module+el8.10.0+90509+b5e1e789', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-1.14.5-3.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-tests-1.14.5-3.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'slirp4netns-1.2.3-1.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.6-21.module+el8.10.0+90449+0b7c8529', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'aardvark-dns-1.10.1-2.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'buildah-1.33.12-1.module+el8.10.0+90509+b5e1e789', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'buildah-tests-1.33.12-1.module+el8.10.0+90509+b5e1e789', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'cockpit-podman-84.1-1.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'conmon-2.1.10-1.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'container-selinux-2.229.0-2.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containernetworking-plugins-1.4.0-5.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containers-common-1-82.0.1.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'crit-3.18-5.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.18-5.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-devel-3.18-5.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-libs-3.18-5.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-1.14.3-2.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.13-1.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.4.0-2.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.4.0-2.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netavark-1.10.3-1.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'oci-seccomp-bpf-hook-1.2.10-1.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-catatonit-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-docker-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-gvproxy-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-plugins-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-remote-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-tests-4.9.4-19.0.1.module+el8.10.0+90509+b5e1e789', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'python3-criu-3.18-5.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-podman-4.9.0-3.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.1.12-6.module+el8.10.0+90509+b5e1e789', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-1.14.5-3.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-tests-1.14.5-3.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'slirp4netns-1.2.3-1.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.6-21.module+el8.10.0+90449+0b7c8529', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aardvark-dns / buildah / buildah-tests / etc');
}
