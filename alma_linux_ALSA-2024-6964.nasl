#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:6964.
##

include('compat.inc');

if (description)
{
  script_id(207759);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id("CVE-2024-3446", "CVE-2024-7383", "CVE-2024-7409");
  script_xref(name:"ALSA", value:"2024:6964");

  script_name(english:"AlmaLinux 8 : virt:rhel and virt-devel:rhel (ALSA-2024:6964)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:6964 advisory.

    * QEMU: virtio: DMA reentrancy issue leads to double free vulnerability (CVE-2024-3446)
    * QEMU: Denial of Service via Improper Synchronization in QEMU NBD Server During Socket Closure
    (CVE-2024-7409)
    * libnbd: NBD server improper certificate validation (CVE-2024-7383)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-6964.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7383");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-3446");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(295, 415, 662);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:SLOF");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-appliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-winsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnbd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libtpms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libtpms-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-iscsi-direct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdfuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-basic-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-curl-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-gzip-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-gzip-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-linuxdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-nbd-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-python-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-ssh-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-tar-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-tar-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-tmpdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-vddk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdkit-xz-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ocaml-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ocaml-libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-hw-usbredir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-ui-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:qemu-kvm-ui-spice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:supermin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:swtpm-tools-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-v2v-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-v2v-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:virt-v2v-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var appstreams = {
    'virt-devel:rhel': [
      {'reference':'hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'hivex-devel-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-bash-completion-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-inspect-icons-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-javadoc-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-ja-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-uk-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-winsupport-8.10-1.module_el8.10.0+3768+dfd76e10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libguestfs-winsupport-8.10-1.module_el8.10.0+3768+dfd76e10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libguestfs-winsupport-8.10-1.module_el8.10.0+3768+dfd76e10', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libguestfs-winsupport-8.10-1.module_el8.10.0+3768+dfd76e10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libguestfs-xfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-xfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-xfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-xfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libiscsi-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libnbd-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libnbd-bash-completion-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libnbd-devel-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-devel-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-devel-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-devel-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-devel-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-client-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-client-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-client-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-client-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-qemu-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-qemu-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-qemu-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-qemu-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-kvm-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-kvm-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-kvm-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-kvm-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-devel-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-devel-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-devel-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-devel-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-docs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-docs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-docs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-docs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-libs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-libs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-libs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-libs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-lock-sanlock-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-lock-sanlock-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-lock-sanlock-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-lock-sanlock-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-nss-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-nss-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-nss-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-nss-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-wireshark-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-wireshark-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-wireshark-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-wireshark-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'lua-guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'lua-guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'lua-guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'lua-guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nbdfuse-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-bash-completion-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-filters-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-filters-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-filters-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-filters-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-curl-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-curl-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-curl-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-curl-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-devel-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-devel-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-devel-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-devel-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-example-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-example-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-example-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-example-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-nbd-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-nbd-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-nbd-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-nbd-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-python-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-python-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-python-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-python-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-server-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-server-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-server-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-server-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-ssh-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-ssh-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-ssh-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-ssh-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-vddk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-vddk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-vddk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-vddk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-xz-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-xz-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-xz-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-xz-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-devel-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-devel-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-devel-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-devel-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-libs-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-libs-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-libs-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-libs-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ocaml-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ocaml-hivex-devel-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ocaml-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libnbd-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ocaml-libnbd-devel-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Virt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Virt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Virt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Virt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libnbd-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libvirt-8.0.0-2.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libvirt-8.0.0-2.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libvirt-8.0.0-2.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libvirt-8.0.0-2.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'qemu-guest-agent-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-guest-agent-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-guest-agent-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-guest-agent-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-docs-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-docs-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-docs-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-docs-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-hw-usbredir-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-hw-usbredir-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-hw-usbredir-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-hw-usbredir-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-tests-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-tests-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-tests-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-tests-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-opengl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-opengl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-opengl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-opengl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-spice-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-spice-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-spice-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-spice-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'ruby-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ruby-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ruby-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ruby-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'seabios-1.16.0-4.module_el8.9.0+3659+9c8643f3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'seabios-1.16.0-4.module_el8.9.0+3659+9c8643f3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'seabios-1.16.0-4.module_el8.9.0+3659+9c8643f3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'seabios-1.16.0-4.module_el8.9.0+3659+9c8643f3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'seabios-bin-1.16.0-4.module_el8.9.0+3659+9c8643f3', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'seavgabios-bin-1.16.0-4.module_el8.9.0+3659+9c8643f3', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'sgabios-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-bin-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'SLOF-20210217-2.module_el8.10.0+3768+dfd76e10', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-devel-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-devel-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-devel-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-devel-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'virt-dib-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-dib-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-dib-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-dib-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-bash-completion-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-man-pages-ja-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-man-pages-uk-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ],
    'virt:rhel': [
      {'reference':'hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'hivex-devel-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-bash-completion-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-inspect-icons-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-javadoc-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-ja-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-uk-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-winsupport-8.10-1.module_el8.10.0+3768+dfd76e10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libguestfs-winsupport-8.10-1.module_el8.10.0+3768+dfd76e10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libguestfs-winsupport-8.10-1.module_el8.10.0+3768+dfd76e10', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libguestfs-winsupport-8.10-1.module_el8.10.0+3768+dfd76e10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libguestfs-xfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-xfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-xfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-xfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libiscsi-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libnbd-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libnbd-bash-completion-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libnbd-devel-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-devel-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-devel-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-devel-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libtpms-devel-0.9.1-2.20211126git1ff6fe1f43.module_el8.9.0+3659+9c8643f3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-client-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-client-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-client-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-client-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-config-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-interface-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-network-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nodedev-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-qemu-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-qemu-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-qemu-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-qemu-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-secret-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-core-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-kvm-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-kvm-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-kvm-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-daemon-kvm-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-devel-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-devel-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-devel-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-devel-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-docs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-docs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-docs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-docs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-libs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-libs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-libs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-libs-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-lock-sanlock-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-lock-sanlock-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-lock-sanlock-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-lock-sanlock-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-nss-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-nss-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-nss-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-nss-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-wireshark-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-wireshark-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-wireshark-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'libvirt-wireshark-8.0.0-23.2.module_el8.10.0+3869+b8959270', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'lua-guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'lua-guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'lua-guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'lua-guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nbdfuse-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-bash-completion-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-filters-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-filters-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-filters-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-filters-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-basic-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-curl-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-curl-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-curl-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-curl-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-devel-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-devel-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-devel-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-devel-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-example-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-example-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-example-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-example-plugins-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-gzip-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-nbd-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-nbd-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-nbd-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-nbd-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-python-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-python-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-python-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-python-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-server-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-server-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-server-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-server-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-ssh-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-ssh-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-ssh-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-ssh-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tar-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-vddk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-vddk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-vddk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-vddk-plugin-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-xz-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-xz-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-xz-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'nbdkit-xz-filter-1.24.0-5.module_el8.8.0+3485+7cffc4a3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-devel-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-devel-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-devel-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-devel-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-libs-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-libs-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-libs-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'netcf-libs-0.2.8-12.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ocaml-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ocaml-hivex-devel-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ocaml-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-devel-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libnbd-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ocaml-libnbd-devel-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Guestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Virt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Virt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Virt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Virt-8.0.0-1.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libnbd-1.6.0-6.module_el8.10.0+3897+eb84924d', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libvirt-8.0.0-2.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libvirt-8.0.0-2.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libvirt-8.0.0-2.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libvirt-8.0.0-2.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'qemu-guest-agent-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-guest-agent-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-guest-agent-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-guest-agent-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-docs-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-docs-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-docs-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-docs-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-hw-usbredir-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-hw-usbredir-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-hw-usbredir-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-hw-usbredir-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-tests-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-tests-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-tests-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-tests-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-opengl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-opengl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-opengl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-opengl-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-spice-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-spice-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-spice-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-ui-spice-6.2.0-53.module_el8.10.0+3897+eb84924d', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'ruby-hivex-1.3.18-23.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ruby-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ruby-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ruby-libguestfs-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'seabios-1.16.0-4.module_el8.9.0+3659+9c8643f3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'seabios-1.16.0-4.module_el8.9.0+3659+9c8643f3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'seabios-1.16.0-4.module_el8.9.0+3659+9c8643f3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'seabios-1.16.0-4.module_el8.9.0+3659+9c8643f3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'seabios-bin-1.16.0-4.module_el8.9.0+3659+9c8643f3', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'seavgabios-bin-1.16.0-4.module_el8.9.0+3659+9c8643f3', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'sgabios-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'cpu':'s390x', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-bin-0.20170427git-3.module_el8.6.0+2880+7d9e3703', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'SLOF-20210217-2.module_el8.10.0+3768+dfd76e10', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-devel-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-devel-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-devel-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'supermin-devel-5.2.1-2.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module_el8.7.0+3346+68867adb', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'virt-dib-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-dib-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-dib-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'s390x', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-dib-1.44.0-9.module_el8.7.0+3493+5ed0bd1c.alma', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'cpu':'s390x', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-bash-completion-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-man-pages-ja-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-man-pages-uk-1.42.0-22.module_el8.9.0+3659+9c8643f3', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
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
      var cves = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt-devel:rhel / virt:rhel');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'SLOF / hivex / hivex-devel / libguestfs / libguestfs-appliance / etc');
}
