#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-3968.
##

include('compat.inc');

if (description)
{
  script_id(200721);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id("CVE-2024-28176", "CVE-2024-28180");

  script_name(english:"Oracle Linux 8 : container-tools:ol8 (ELSA-2024-3968)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-3968 advisory.

    aardvark-dns
    [2:1.10.0-1]
    - update to https://github.com/containers/aardvark-dns/releases/tag/v1.10.0
    - Related: Jira:RHEL-2110

    [2:1.9.0-1]
    - update to https://github.com/containers/aardvark-dns/releases/tag/v1.9.0
    - Related: Jira:RHEL-2110

    [2:1.8.0-1]
    - update to https://github.com/containers/aardvark-dns/releases/tag/v1.8.0
    - Related: Jira:RHEL-2110

    buildah
    [2:1.33.7-2]
    - update to the latest content of https://github.com/containers/buildah/tree/release-1.33
      (https://github.com/containers/buildah/commit/997beea)
    - Resolves: RHEL-28725

    cockpit-podman
    [84.1-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/84.1
    - Related: Jira:RHEL-25557

    [84-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/84
    - Related: Jira:RHEL-2110

    [83-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/83
    - Related: Jira:RHEL-2110

    [82-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/82
    - Related: Jira:RHEL-2110

    [81-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/81
    - Related: Jira:RHEL-2110

    [80-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/80
    - Related: Jira:RHEL-2110

    [79-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/79
    - Related: Jira:RHEL-2110

    [78-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/78
    - Related: Jira:RHEL-2110

    [77-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/77
    - Related: Jira:RHEL-2110

    [75-1]
    - update to https://github.com/cockpit-project/cockpit-podman/releases/tag/75
    - Related: #2176055

    conmon
    [3:2.1.10-1]
    - update to https://github.com/containers/conmon/releases/tag/v2.1.10
    - Related: Jira:RHEL-2110

    [3:2.1.8-1]
    - update to https://github.com/containers/conmon/releases/tag/v2.1.8
    - Related: #2176055

    containernetworking-plugins
    [1:1.4.0-2]
    - rebuild
    - Resolves: RHEL-18390

    [1:1.4.0-1]
    - update to https://github.com/containernetworking/plugins/releases/tag/v1.4.0
    - Related: Jira:RHEL-2110

    containers-common
    [2:1-81.0.1]
    - Updated removed references [Orabug: 33473101] (Alex Burmashev)
    - Adjust registries.conf (Nikita Gerasimov)
    - remove references to RedHat registry (Nikita Gerasimov)

    [2:1-81]
    - Update shortnames from Pyxis
    - Related: Jira:RHEL-2110

    [2:1-80]
    - bump release to preserve upgrade path
    - Resolves: Jira:RHEL-12277

    container-selinux
    [2:2.229.0-2]
    - remove watch statements properly for RHEL8 and lower
    - Related: Jira:RHEL-2110

    [2:2.229.0-1]
    - update to https://github.com/containers/container-selinux/releases/tag/v2.229.0
    - Related: Jira:RHEL-2110

    [2:2.228.1-1]
    - update to https://github.com/containers/container-selinux/releases/tag/v2.228.1
    - Related: Jira:RHEL-2110

    [2:2.228.0-1]
    - update to https://github.com/containers/container-selinux/releases/tag/v2.228.0
    - Related: Jira:RHEL-2110

    [2:2.227.0-1]
    - update to https://github.com/containers/container-selinux/releases/tag/v2.227.0
    - Related: Jira:RHEL-2110

    [2:2.226.0-1]
    - update to https://github.com/containers/container-selinux/releases/tag/v2.226.0
    - remove dependency on policycoreutils-python-utils as it pulls in python
    - Related: Jira:RHEL-2110

    [2:2.224.0-1]
    - update to https://github.com/containers/container-selinux/releases/tag/v2.224.0
    - Related: Jira:RHEL-2110

    [2:2.222.0-1]
    - update to https://github.com/containers/container-selinux/releases/tag/v2.222.0
    - Related: Jira:RHEL-2110

    criu
    [3.18-5]
    - rebuild to preserve upgrade path
    - Related: RHEL-32671

    [3.18-4]
    - switch to egg-info on 8.9
    - Related: #2176055

    [3.18-3]
    - remove --progress-bar option
    - Related: #2176055

    [3.18-2]
    - update to 3.18
    - Related: #2176055

    [3.17-1]
    - update to 3.17
    - Resolves: #2175794

    crun
    [1.14.3-2]
    - remove BR libgcrypt-devel, no longer needed
    - Related: Jira:RHEL-2110

    [1.14.3-1]
    - update to https://github.com/containers/crun/releases/tag/1.14.3
    - Related: Jira:RHEL-2110

    [1.14.1-1]
    - update to https://github.com/containers/crun/releases/tag/1.14.1
    - Related: Jira:RHEL-2110

    [1.14-1]
    - update to https://github.com/containers/crun/releases/tag/1.14
    - Related: Jira:RHEL-2110

    [1.13-1]
    - update to https://github.com/containers/crun/releases/tag/1.13
    - Related: Jira:RHEL-2110

    [1.12-1]
    - update to https://github.com/containers/crun/releases/tag/1.12
    - Related: Jira:RHEL-2110

    [1.11.2-1]
    - update to https://github.com/containers/crun/releases/tag/1.11.2
    - Related: Jira:RHEL-2110

    [1.11.1-1]
    - update to https://github.com/containers/crun/releases/tag/1.11.1
    - Related: Jira:RHEL-2110

    [1.11-1]
    - update to https://github.com/containers/crun/releases/tag/1.11
    - Related: Jira:RHEL-2110

    [1.9.2-1]
    - update to https://github.com/containers/crun/releases/tag/1.9.2
    - Related: Jira:RHEL-2110

    [1.9.1-1]
    - update to https://github.com/containers/crun/releases/tag/1.9.1
    - Related: Jira:RHEL-2110

    [1.9-1]
    - update to https://github.com/containers/crun/releases/tag/1.9
    - Related: Jira:RHEL-2110

    fuse-overlayfs
    [1.13-1]
    - update to https://github.com/containers/fuse-overlayfs/releases/tag/v1.13
    - Related: Jira:RHEL-2110

    libslirp
    [4.4.0-2]
    - rebuild to preserve upgrade path 8.9 -> 8.10
    - Related: RHEL-32671

    netavark
    [2:1.10.3-1]
    - update to https://github.com/containers/netavark/releases/tag/v1.10.3
    - Related: Jira:RHEL-2110

    [2:1.10.2-1]
    - update to https://github.com/containers/netavark/releases/tag/v1.10.2
    - Related: Jira:RHEL-2110

    [2:1.10.1-1]
    - update to https://github.com/containers/netavark/releases/tag/v1.10.1
    - Related: Jira:RHEL-2110

    [2:1.10.0-1]
    - update to https://github.com/containers/netavark/releases/tag/v1.10.0
    - Related: Jira:RHEL-2110

    [2:1.9.0-1]
    - update to https://github.com/containers/netavark/releases/tag/v1.9.0
    - Related: Jira:RHEL-2110

    [2:1.8.0-2]
    - fix directory for systemd units
    - Related: Jira:RHEL-2110

    [2:1.8.0-1]
    - update to https://github.com/containers/netavark/releases/tag/v1.8.0
    - Related: Jira:RHEL-2110

    oci-seccomp-bpf-hook
    [1.2.10-1]
    - update to https://github.com/containers/oci-seccomp-bpf-hook/releases/tag/v1.2.10
    - Related: Jira:RHEL-2110

    podman
    [4:4.9.4-3.0.1]
    - Add devices on container startup, not on creation

    [4:4.9.4-3]
    - BR: /usr/bin/man
    - Related: RHEL-28727

    [4:4.9.4-2]
    - update to the latest content of https://github.com/containers/podman/tree/v4.9-rhel
      (https://github.com/containers/podman/commit/6464b2c)
    - Resolves: RHEL-28727

    python-podman
    [4.9.0-1]
    - update to https://github.com/containers/podman-py/releases/tag/v4.9.0
    - Related: Jira:RHEL-2110

    [4.8.2-1]
    - update to https://github.com/containers/podman-py/releases/tag/v4.8.2
    - Related: Jira:RHEL-2110

    [4.8.0.post1-1]
    - update to https://github.com/containers/podman-py/releases/tag/v4.8.0.post1
    - Related: Jira:RHEL-2110

    [4.7.0-1]
    - update to https://github.com/containers/podman-py/releases/tag/v4.7.0
    - Related: Jira:RHEL-2110

    runc
    skopeo
    [2:1.14.3-2]
    - update to the latest content of https://github.com/containers/skopeo/tree/release-1.14
      (https://github.com/containers/skopeo/commit/5f2b9af)
    - Resolves: RHEL-28728

    [2:1.14.3-1]
    - update to the latest content of https://github.com/containers/skopeo/tree/release-1.14
      (https://github.com/containers/skopeo/commit/4a2bc3a)
    - Resolves: RHEL-28226

    slirp4netns
    [1.2.3-1]
    - update to https://github.com/rootless-containers/slirp4netns/releases/tag/v1.2.3
    - Related: Jira:RHEL-2110

    [1.2.2-1]
    - update to https://github.com/rootless-containers/slirp4netns/releases/tag/v1.2.2
    - Related: Jira:RHEL-2110

    udica
    [0.2.6-21]
    - bump release to preserve update path
    - Resolves: RHEL-32671

    [0.2.6-20]
    - bump release to preserve update path
    - Related: #2139052

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-3968.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28176");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:23.1.16.0.0::ol8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:23.1.17.0.0::ol8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:24.1.2.0.0::ol8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:24.1.3.0.0::ol8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8:10:appstream_base");
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

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'aardvark-dns-1.10.0-1.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'buildah-1.33.7-2.module+el8.10.0+90352+16362864', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'buildah-tests-1.33.7-2.module+el8.10.0+90352+16362864', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'cockpit-podman-84.1-1.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'conmon-2.1.10-1.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'container-selinux-2.229.0-2.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containernetworking-plugins-1.4.0-2.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containers-common-1-81.0.1.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'crit-3.18-5.module+el8.10.0+90337+0d7b6e74', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.18-5.module+el8.10.0+90337+0d7b6e74', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-devel-3.18-5.module+el8.10.0+90337+0d7b6e74', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-libs-3.18-5.module+el8.10.0+90337+0d7b6e74', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-1.14.3-2.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.13-1.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.4.0-2.module+el8.10.0+90337+0d7b6e74', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.4.0-2.module+el8.10.0+90337+0d7b6e74', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netavark-1.10.3-1.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'oci-seccomp-bpf-hook-1.2.10-1.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-catatonit-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-docker-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-gvproxy-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-plugins-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-remote-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-tests-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'python3-criu-3.18-5.module+el8.10.0+90337+0d7b6e74', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-podman-4.9.0-1.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.1.12-1.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-1.14.3-2.module+el8.10.0+90337+0d7b6e74', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-tests-1.14.3-2.module+el8.10.0+90337+0d7b6e74', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'slirp4netns-1.2.3-1.module+el8.10.0+90298+77a9814d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.6-21.module+el8.10.0+90337+0d7b6e74', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'aardvark-dns-1.10.0-1.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'buildah-1.33.7-2.module+el8.10.0+90352+16362864', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'buildah-tests-1.33.7-2.module+el8.10.0+90352+16362864', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'cockpit-podman-84.1-1.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'conmon-2.1.10-1.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'container-selinux-2.229.0-2.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containernetworking-plugins-1.4.0-2.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containers-common-1-81.0.1.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'crit-3.18-5.module+el8.10.0+90337+0d7b6e74', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.18-5.module+el8.10.0+90337+0d7b6e74', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-devel-3.18-5.module+el8.10.0+90337+0d7b6e74', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-libs-3.18-5.module+el8.10.0+90337+0d7b6e74', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-1.14.3-2.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.13-1.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.4.0-2.module+el8.10.0+90337+0d7b6e74', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.4.0-2.module+el8.10.0+90337+0d7b6e74', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netavark-1.10.3-1.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'oci-seccomp-bpf-hook-1.2.10-1.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-catatonit-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-docker-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-gvproxy-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-plugins-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-remote-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'podman-tests-4.9.4-3.0.1.module+el8.10.0+90352+16362864', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'python3-criu-3.18-5.module+el8.10.0+90337+0d7b6e74', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-podman-4.9.0-1.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.1.12-1.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-1.14.3-2.module+el8.10.0+90337+0d7b6e74', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'skopeo-tests-1.14.3-2.module+el8.10.0+90337+0d7b6e74', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'slirp4netns-1.2.3-1.module+el8.10.0+90298+77a9814d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.6-21.module+el8.10.0+90337+0d7b6e74', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aardvark-dns / buildah / buildah-tests / etc');
}
