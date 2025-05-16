#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:1064.
##

include('compat.inc');

if (description)
{
  script_id(184488);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id("CVE-2021-20295");
  script_xref(name:"RLSA", value:"2021:1064");

  script_name(english:"Rocky Linux 8 : virt:rhel and virt-devel:rhel (RLSA-2021:1064)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2021:1064 advisory.

  - It was discovered that the update for the virt:rhel module in the RHSA-2020:4676
    (https://access.redhat.com/errata/RHSA-2020:4676) erratum released as part of Red Hat Enterprise Linux 8.3
    failed to include the fix for the qemu-kvm component issue CVE-2020-10756, which was previously corrected
    in virt:rhel/qemu-kvm via erratum RHSA-2020:4059 (https://access.redhat.com/errata/RHSA-2020:4059).
    CVE-2021-20295 was assigned to that Red Hat specific security regression. For more details about the
    original security issue CVE-2020-10756, refer to bug 1835986 or the CVE page:
    https://access.redhat.com/security/cve/CVE-2020-10756. (CVE-2021-20295)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:1064");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944075");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20295");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:hivex-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-winsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libnbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libnbd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-dbus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-dbus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdfuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdfuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-basic-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-basic-filters-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-basic-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-curl-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-curl-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-example-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-gzip-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-gzip-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-linuxdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-linuxdisk-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-python-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-python-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-ssh-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-ssh-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-vddk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-vddk-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-xz-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-xz-filter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netcf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netcf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:netcf-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ocaml-hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ocaml-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ocaml-libnbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ocaml-libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Virt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Virt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libnbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:supermin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:supermin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:supermin-devel");
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
    {'reference':'hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-debugsource-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-debugsource-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-debugsource-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-devel-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-devel-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-devel-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libguestfs-winsupport-8.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libguestfs-winsupport-8.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libguestfs-winsupport-8.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-debuginfo-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-debuginfo-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-debuginfo-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-debugsource-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-debugsource-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-debugsource-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-devel-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-devel-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-devel-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-1.3.0-2.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-1.3.0-2.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-1.3.0-2.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-1.3.0-2.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-1.3.0-2.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-1.3.0-2.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-1.3.0-2.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-1.3.0-2.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-1.3.0-2.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debuginfo-1.3.0-2.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debuginfo-1.3.0-2.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debuginfo-1.3.0-2.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debuginfo-1.3.0-2.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debuginfo-1.3.0-2.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debuginfo-1.3.0-2.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debuginfo-1.3.0-2.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debuginfo-1.3.0-2.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debuginfo-1.3.0-2.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debugsource-1.3.0-2.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debugsource-1.3.0-2.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debugsource-1.3.0-2.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debugsource-1.3.0-2.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debugsource-1.3.0-2.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debugsource-1.3.0-2.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debugsource-1.3.0-2.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debugsource-1.3.0-2.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debugsource-1.3.0-2.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-python-debugsource-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-python-debugsource-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-python-debugsource-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdfuse-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdfuse-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdfuse-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdfuse-debuginfo-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdfuse-debuginfo-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdfuse-debuginfo-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-bash-completion-1.16.2-4.module+el8.4.0+534+4680a14e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-filters-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-filters-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-filters-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-filters-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-plugins-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-plugins-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-plugins-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-plugins-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-curl-plugin-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-curl-plugin-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-curl-plugin-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-curl-plugin-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-debugsource-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-debugsource-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-devel-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-devel-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-example-plugins-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-example-plugins-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-example-plugins-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-example-plugins-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-gzip-plugin-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-gzip-plugin-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-gzip-plugin-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-gzip-plugin-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-linuxdisk-plugin-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-linuxdisk-plugin-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-linuxdisk-plugin-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-linuxdisk-plugin-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-python-plugin-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-python-plugin-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-python-plugin-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-python-plugin-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-server-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-server-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-server-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-server-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-ssh-plugin-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-ssh-plugin-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-ssh-plugin-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-ssh-plugin-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-vddk-plugin-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-vddk-plugin-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-xz-filter-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-xz-filter-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-xz-filter-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-xz-filter-debuginfo-1.16.2-4.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-devel-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-devel-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-devel-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-debuginfo-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-debuginfo-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-debuginfo-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-devel-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-devel-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-devel-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-debuginfo-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-debuginfo-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-debuginfo-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-debugsource-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-debugsource-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-debugsource-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libnbd-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libnbd-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libnbd-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libnbd-debuginfo-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libnbd-debuginfo-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libnbd-debuginfo-1.2.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libvirt-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libvirt-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libvirt-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libvirt-debuginfo-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libvirt-debuginfo-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libvirt-debuginfo-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'seabios-1.13.0-2.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'seabios-bin-1.13.0-2.module+el8.4.0+534+4680a14e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'seavgabios-bin-1.13.0-2.module+el8.4.0+534+4680a14e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sgabios-0.20170427git-3.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-0.20170427git-3.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-0.20170427git-3.module+el8.6.0+847+b490afdd', 'cpu':'i686', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-0.20170427git-3.module+el8.6.0+847+b490afdd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-0.20170427git-3.module+el8.7.0+1084+97b81f61', 'cpu':'i686', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-0.20170427git-3.module+el8.7.0+1084+97b81f61', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-bin-0.20170427git-3.module+el8.4.0+534+4680a14e', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-bin-0.20170427git-3.module+el8.6.0+847+b490afdd', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-bin-0.20170427git-3.module+el8.7.0+1084+97b81f61', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'supermin-5.1.19-10.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-5.1.19-10.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-debuginfo-5.1.19-10.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-debuginfo-5.1.19-10.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-debugsource-5.1.19-10.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-debugsource-5.1.19-10.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-devel-5.1.19-10.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-devel-5.1.19-10.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hivex / hivex-debuginfo / hivex-debugsource / hivex-devel / etc');
}
