#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:0705.
##

include('compat.inc');

if (description)
{
  script_id(184732);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id("CVE-2021-20188");
  script_xref(name:"RLSA", value:"2021:0705");

  script_name(english:"Rocky Linux 8 : container-tools:1.0 (RLSA-2021:0705)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2021:0705 advisory.

  - A flaw was found in podman before 1.7.0. File permissions for non-root users running in a privileged
    container are not correctly checked. This flaw can be abused by a low-privileged user inside the container
    to access any other file in the container, even if owned by the root user inside the container. It does
    not allow to directly escape the container, though being a privileged container means that a lot of
    security features are disabled when running the container. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as system availability. (CVE-2021-20188)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:0705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1915734");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20188");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fuse-overlayfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fuse-overlayfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-systemd-hook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-systemd-hook-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-systemd-hook-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-umount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-umount-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-umount-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns-debugsource");
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

var module_ver = get_kb_item('Host/RockyLinux/appstream/container-tools');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:1.0');
if ('1.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module container-tools:' + module_ver);

var appstreams = {
    'container-tools:1.0': [
      {'reference':'buildah-1.5-8.gite94b4f9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-1.5-8.gite94b4f9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-1.5-8.gite94b4f9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-1.5-8.gite94b4f9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-debuginfo-1.5-8.gite94b4f9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-debuginfo-1.5-8.gite94b4f9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-debuginfo-1.5-8.gite94b4f9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-debuginfo-1.5-8.gite94b4f9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-debugsource-1.5-8.gite94b4f9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-debugsource-1.5-8.gite94b4f9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-debugsource-1.5-8.gite94b4f9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-debugsource-1.5-8.gite94b4f9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'container-selinux-2.124.0-1.gitf958d0c.module+el8.4.0+557+48ba8b2f', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'container-selinux-2.124.0-1.gitf958d0c.module+el8.5.0+681+c9a1951f', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containernetworking-plugins-0.7.4-4.git9ebe139.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-0.7.4-4.git9ebe139.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-0.7.4-4.git9ebe139.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-0.7.4-4.git9ebe139.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debuginfo-0.7.4-4.git9ebe139.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debuginfo-0.7.4-4.git9ebe139.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debuginfo-0.7.4-4.git9ebe139.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debuginfo-0.7.4-4.git9ebe139.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debugsource-0.7.4-4.git9ebe139.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debugsource-0.7.4-4.git9ebe139.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debugsource-0.7.4-4.git9ebe139.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debugsource-0.7.4-4.git9ebe139.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containers-common-0.1.32-6.git1715c90.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containers-common-0.1.32-6.git1715c90.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containers-common-0.1.32-6.git1715c90.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containers-common-0.1.32-6.git1715c90.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'crit-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debuginfo-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debuginfo-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debuginfo-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debuginfo-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debugsource-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debugsource-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debugsource-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debugsource-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-0.3-5.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-0.3-5.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-0.3-5.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-0.3-5.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debuginfo-0.3-5.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debuginfo-0.3-5.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debuginfo-0.3-5.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debuginfo-0.3-5.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debugsource-0.3-5.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debugsource-0.3-5.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debugsource-0.3-5.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debugsource-0.3-5.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-systemd-hook-0.1.15-2.git2d0b8a3.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'oci-systemd-hook-0.1.15-2.git2d0b8a3.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'oci-systemd-hook-debuginfo-0.1.15-2.git2d0b8a3.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'oci-systemd-hook-debuginfo-0.1.15-2.git2d0b8a3.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'oci-systemd-hook-debugsource-0.1.15-2.git2d0b8a3.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'oci-systemd-hook-debugsource-0.1.15-2.git2d0b8a3.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'oci-umount-2.3.4-2.git87f9237.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'oci-umount-2.3.4-2.git87f9237.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'oci-umount-debuginfo-2.3.4-2.git87f9237.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'oci-umount-debuginfo-2.3.4-2.git87f9237.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'oci-umount-debugsource-2.3.4-2.git87f9237.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'oci-umount-debugsource-2.3.4-2.git87f9237.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'podman-1.0.0-8.git921f98f.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-1.0.0-8.git921f98f.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-1.0.0-8.git921f98f.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-1.0.0-8.git921f98f.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-debuginfo-1.0.0-8.git921f98f.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-debuginfo-1.0.0-8.git921f98f.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-debuginfo-1.0.0-8.git921f98f.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-debuginfo-1.0.0-8.git921f98f.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-debugsource-1.0.0-8.git921f98f.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-debugsource-1.0.0-8.git921f98f.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-debugsource-1.0.0-8.git921f98f.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-debugsource-1.0.0-8.git921f98f.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-docker-1.0.0-8.git921f98f.module+el8.4.0+557+48ba8b2f', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-docker-1.0.0-8.git921f98f.module+el8.5.0+681+c9a1951f', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.12-9.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.12-9.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-56.rc5.dev.git2abd837.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-56.rc5.dev.git2abd837.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-56.rc5.dev.git2abd837.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-56.rc5.dev.git2abd837.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debuginfo-1.0.0-56.rc5.dev.git2abd837.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debuginfo-1.0.0-56.rc5.dev.git2abd837.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debuginfo-1.0.0-56.rc5.dev.git2abd837.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debuginfo-1.0.0-56.rc5.dev.git2abd837.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debugsource-1.0.0-56.rc5.dev.git2abd837.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debugsource-1.0.0-56.rc5.dev.git2abd837.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debugsource-1.0.0-56.rc5.dev.git2abd837.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debugsource-1.0.0-56.rc5.dev.git2abd837.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'skopeo-0.1.32-6.git1715c90.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-0.1.32-6.git1715c90.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-0.1.32-6.git1715c90.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-0.1.32-6.git1715c90.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-debuginfo-0.1.32-6.git1715c90.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-debuginfo-0.1.32-6.git1715c90.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-debuginfo-0.1.32-6.git1715c90.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-debuginfo-0.1.32-6.git1715c90.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-debugsource-0.1.32-6.git1715c90.module+el8.4.0+557+48ba8b2f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-debugsource-0.1.32-6.git1715c90.module+el8.4.0+557+48ba8b2f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-debugsource-0.1.32-6.git1715c90.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-debugsource-0.1.32-6.git1715c90.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'slirp4netns-0.1-5.dev.gitc4e1bc5.module+el8.4.0+535+5beadeea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-0.1-5.dev.gitc4e1bc5.module+el8.4.0+535+5beadeea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-0.1-5.dev.gitc4e1bc5.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-0.1-5.dev.gitc4e1bc5.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debuginfo-0.1-5.dev.gitc4e1bc5.module+el8.4.0+535+5beadeea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debuginfo-0.1-5.dev.gitc4e1bc5.module+el8.4.0+535+5beadeea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debuginfo-0.1-5.dev.gitc4e1bc5.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debuginfo-0.1-5.dev.gitc4e1bc5.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debugsource-0.1-5.dev.gitc4e1bc5.module+el8.4.0+535+5beadeea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debugsource-0.1-5.dev.gitc4e1bc5.module+el8.4.0+535+5beadeea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debugsource-0.1-5.dev.gitc4e1bc5.module+el8.5.0+681+c9a1951f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debugsource-0.1-5.dev.gitc4e1bc5.module+el8.5.0+681+c9a1951f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RockyLinux/appstream/' + appstream_name);
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:1.0');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-debuginfo / buildah-debugsource / etc');
}
