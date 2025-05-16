#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:4154.
##

include('compat.inc');

if (description)
{
  script_id(184562);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id("CVE-2021-3602", "CVE-2021-20291");
  script_xref(name:"RLSA", value:"2021:4154");

  script_name(english:"Rocky Linux 8 : container-tools:rhel8 (RLSA-2021:4154)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2021:4154 advisory.

  - A deadlock vulnerability was found in 'github.com/containers/storage' in versions before 1.28.1. When a
    container image is processed, each layer is unpacked using `tar`. If one of those layers is not a valid
    `tar` archive this causes an error leading to an unexpected situation where the code indefinitely waits
    for the tar unpacked stream, which never finishes. An attacker could use this vulnerability to craft a
    malicious image, which when downloaded and stored by an application using containers/storage, would then
    cause a deadlock leading to a Denial of Service (DoS). (CVE-2021-20291)

  - An information disclosure flaw was found in Buildah, when building containers using chroot isolation.
    Running processes in container builds (e.g. Dockerfile RUN commands) can access environment variables from
    parent and grandparent processes. When run in a container in a CI/CD environment, environment variables
    may include sensitive information that was shared with the container in order to be used only by Buildah
    itself (e.g. container registry credentials). (CVE-2021-3602)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:4154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1914687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1928935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1932399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1933775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1933776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1934415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1934480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1937641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1937830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1939485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1940037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1940054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1940082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1940493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1941380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1947432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1947999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1952204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1952698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1957299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1957840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1957904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1958353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1960948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1966538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1966872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1969264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1972150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1972209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1972211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1972282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1972648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1973418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1976283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1977280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1977673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1978415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1978556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1978647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1979497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1980212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1982593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1982762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1985499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1985905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1987049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1993209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1993249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1995041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1998191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1999144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2000943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2004562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2005018");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3602");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:cockpit-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:conmon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:conmon-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crun-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crun-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fuse-overlayfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fuse-overlayfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libslirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libslirp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libslirp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libslirp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-seccomp-bpf-hook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-seccomp-bpf-hook-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-seccomp-bpf-hook-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-catatonit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-gvproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-remote-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:udica");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'buildah-1.22.3-2.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'buildah-1.22.3-2.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'buildah-debuginfo-1.22.3-2.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'buildah-debuginfo-1.22.3-2.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'buildah-debugsource-1.22.3-2.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'buildah-debugsource-1.22.3-2.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'buildah-tests-1.22.3-2.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'buildah-tests-1.22.3-2.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'buildah-tests-debuginfo-1.22.3-2.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'buildah-tests-debuginfo-1.22.3-2.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cockpit-podman-33-1.module+el8.5.0+710+4c471e88', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'conmon-2.0.29-1.module+el8.4.0+643+525e162a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-2.0.29-1.module+el8.4.0+643+525e162a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-2.0.29-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-2.0.29-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-debuginfo-2.0.29-1.module+el8.4.0+643+525e162a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-debuginfo-2.0.29-1.module+el8.4.0+643+525e162a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-debuginfo-2.0.29-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-debuginfo-2.0.29-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-debugsource-2.0.29-1.module+el8.4.0+643+525e162a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-debugsource-2.0.29-1.module+el8.4.0+643+525e162a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-debugsource-2.0.29-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'conmon-debugsource-2.0.29-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'container-selinux-2.167.0-1.module+el8.4.0+653+ad26b47d', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'container-selinux-2.167.0-1.module+el8.5.0+709+440d5e7e', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'containernetworking-plugins-1.0.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containernetworking-plugins-1.0.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containernetworking-plugins-debuginfo-1.0.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containernetworking-plugins-debuginfo-1.0.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containernetworking-plugins-debugsource-1.0.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containernetworking-plugins-debugsource-1.0.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containers-common-1-2.module+el8.5.0+710+4c471e88', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'allowmaj':TRUE},
    {'reference':'crit-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crit-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debuginfo-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-debugsource-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-devel-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-devel-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-devel-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-devel-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-devel-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-devel-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-debuginfo-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-debuginfo-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-debuginfo-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-debuginfo-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-debuginfo-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'criu-libs-debuginfo-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-1.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-1.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debuginfo-1.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debuginfo-1.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debugsource-1.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'crun-debugsource-1.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-1.7.1-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-1.7.1-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-debuginfo-1.7.1-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-debuginfo-1.7.1-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-debugsource-1.7.1-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fuse-overlayfs-debugsource-1.7.1-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debuginfo-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-debugsource-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.4.0-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.4.0-1.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libslirp-devel-4.4.0-1.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-1.2.3-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-1.2.3-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-1.2.3-3.module+el8.6.0+784+32aef5de', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-1.2.3-3.module+el8.6.0+784+32aef5de', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.3-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.3-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.3-3.module+el8.6.0+784+32aef5de', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.3-3.module+el8.6.0+784+32aef5de', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.3-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.3-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.3-3.module+el8.6.0+784+32aef5de', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.3-3.module+el8.6.0+784+32aef5de', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-catatonit-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-catatonit-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-catatonit-debuginfo-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-catatonit-debuginfo-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-debuginfo-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-debuginfo-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-debugsource-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-debugsource-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-docker-3.3.1-9.module+el8.5.0+710+4c471e88', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-gvproxy-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-gvproxy-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-gvproxy-debuginfo-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-gvproxy-debuginfo-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-plugins-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-plugins-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-plugins-debuginfo-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-plugins-debuginfo-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-remote-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-remote-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-remote-debuginfo-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-remote-debuginfo-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-tests-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-tests-3.3.1-9.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.15-3.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.15-3.module+el8.6.0+1054+50b00ff4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-criu-3.15-3.module+el8.7.0+1077+0e4f03d4', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-podman-3.2.0-2.module+el8.5.0+710+4c471e88', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-1.0.2-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-1.0.2-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debuginfo-1.0.2-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debuginfo-1.0.2-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debugsource-1.0.2-1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'runc-debugsource-1.0.2-1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'skopeo-1.4.2-0.1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'skopeo-1.4.2-0.1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'skopeo-debuginfo-1.4.2-0.1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'skopeo-debuginfo-1.4.2-0.1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'skopeo-debugsource-1.4.2-0.1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'skopeo-debugsource-1.4.2-0.1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'skopeo-tests-1.4.2-0.1.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'skopeo-tests-1.4.2-0.1.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'slirp4netns-1.1.8-1.module+el8.4.0+537+38cf4e42', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-1.1.8-1.module+el8.4.0+537+38cf4e42', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-1.1.8-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-1.1.8-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-1.1.8-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-1.1.8-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-1.1.8-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-1.1.8-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.4.0+537+38cf4e42', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.4.0+537+38cf4e42', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.4.0+537+38cf4e42', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.4.0+537+38cf4e42', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-0.0.99.3-0.4.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-0.0.99.3-0.4.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-0.0.99.3-0.4.module+el8.6.0+784+32aef5de', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-0.0.99.3-0.4.module+el8.6.0+784+32aef5de', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debuginfo-0.0.99.3-0.4.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debuginfo-0.0.99.3-0.4.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debuginfo-0.0.99.3-0.4.module+el8.6.0+784+32aef5de', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debuginfo-0.0.99.3-0.4.module+el8.6.0+784+32aef5de', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debugsource-0.0.99.3-0.4.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debugsource-0.0.99.3-0.4.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debugsource-0.0.99.3-0.4.module+el8.6.0+784+32aef5de', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-debugsource-0.0.99.3-0.4.module+el8.6.0+784+32aef5de', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-tests-0.0.99.3-0.4.module+el8.5.0+710+4c471e88', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-tests-0.0.99.3-0.4.module+el8.5.0+710+4c471e88', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-tests-0.0.99.3-0.4.module+el8.6.0+784+32aef5de', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'toolbox-tests-0.0.99.3-0.4.module+el8.6.0+784+32aef5de', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'udica-0.2.5-2.module+el8.5.0+710+4c471e88', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-debuginfo / buildah-debugsource / buildah-tests / etc');
}
