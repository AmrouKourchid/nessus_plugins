#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2023:3822.
##

include('compat.inc');

if (description)
{
  script_id(184521);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id("CVE-2023-2700");
  script_xref(name:"RLSA", value:"2023:3822");

  script_name(english:"Rocky Linux 8 : virt:rhel and virt-devel:rhel (RLSA-2023:3822)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2023:3822 advisory.

  - A vulnerability was found in libvirt. This security flaw ouccers due to repeatedly querying an SR-IOV PCI
    device's capabilities that exposes a memory leak caused by a failure to free the virPCIVirtualFunction
    array within the parent struct's g_autoptr cleanup. (CVE-2023-2700)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2023:3822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2180030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2181575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2203653");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:hivex-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-appliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-gobject-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-java-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-tools-c-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-winsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libiscsi-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libnbd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libnbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libnbd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libtpms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libtpms-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libtpms-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libtpms-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-interface-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-network-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-nodedev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-nwfilter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-secret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-disk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-gluster-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-iscsi-direct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-iscsi-direct-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-logical-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-mpath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-scsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-dbus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-dbus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-lock-sanlock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lua-guestfs-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-gzip-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-gzip-filter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-gzip-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-gzip-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-linuxdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-linuxdisk-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-nbd-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-nbd-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-python-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-python-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-ssh-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-ssh-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-tar-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-tar-filter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-tar-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-tar-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-tmpdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nbdkit-tmpdisk-plugin-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ocaml-libguestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ocaml-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ocaml-libnbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ocaml-libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Guestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Virt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Virt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libguestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libnbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-img-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-block-gluster-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-hw-usbredir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-hw-usbredir-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-ui-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-ui-opengl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-ui-spice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-ui-spice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-libguestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:supermin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:supermin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:supermin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:swtpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:swtpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:swtpm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:swtpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:swtpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:swtpm-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:swtpm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:swtpm-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:swtpm-tools-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:virt-dib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:virt-v2v-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:virt-v2v-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:virt-v2v-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:virt-v2v-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:virt-v2v-man-pages-uk");
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
    {'reference':'hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-debugsource-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-debugsource-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-debugsource-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-devel-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-devel-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'hivex-devel-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libguestfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-appliance-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-appliance-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-bash-completion-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-debugsource-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-debugsource-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-devel-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-devel-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gfs2-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gfs2-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gobject-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gobject-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gobject-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gobject-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gobject-devel-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gobject-devel-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-inspect-icons-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-devel-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-devel-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-javadoc-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-man-pages-ja-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-man-pages-uk-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-rescue-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-rescue-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-rsync-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-rsync-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-c-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-c-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-c-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-c-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-winsupport-8.8-1.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libguestfs-winsupport-8.8-1.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libguestfs-winsupport-8.8-1.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libguestfs-xfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-xfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libiscsi-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debuginfo-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-debugsource-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-devel-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiscsi-utils-debuginfo-1.18.0-8.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-bash-completion-1.6.0-5.module+el8.8.0+1279+230c2115', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-debuginfo-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-debuginfo-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-debuginfo-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-debugsource-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-debugsource-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-debugsource-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-devel-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-devel-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnbd-devel-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtpms-0.9.1-2.20211126git1ff6fe1f43.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtpms-0.9.1-2.20211126git1ff6fe1f43.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtpms-debuginfo-0.9.1-2.20211126git1ff6fe1f43.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtpms-debuginfo-0.9.1-2.20211126git1ff6fe1f43.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtpms-debugsource-0.9.1-2.20211126git1ff6fe1f43.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtpms-debugsource-0.9.1-2.20211126git1ff6fe1f43.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtpms-devel-0.9.1-2.20211126git1ff6fe1f43.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtpms-devel-0.9.1-2.20211126git1ff6fe1f43.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-network-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-network-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-network-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-nwfilter-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-nwfilter-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-nwfilter-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-qemu-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-qemu-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-qemu-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-qemu-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-gluster-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-gluster-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-gluster-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-direct-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-direct-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-direct-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-direct-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-rbd-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-rbd-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-rbd-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-kvm-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-kvm-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-1.3.0-2.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-1.3.0-2.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-1.3.0-2.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debuginfo-1.3.0-2.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debuginfo-1.3.0-2.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debuginfo-1.3.0-2.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debugsource-1.3.0-2.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debugsource-1.3.0-2.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-dbus-debugsource-1.3.0-2.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-debugsource-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-debugsource-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-debugsource-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-devel-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-devel-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-devel-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-docs-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-docs-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-docs-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-lock-sanlock-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-lock-sanlock-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-lock-sanlock-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-lock-sanlock-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-python-debugsource-8.0.0-2.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-python-debugsource-8.0.0-2.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-python-debugsource-8.0.0-2.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-wireshark-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-wireshark-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-wireshark-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-wireshark-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-wireshark-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-wireshark-debuginfo-8.0.0-19.2.module+el8.8.0+1321+70d049b2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lua-guestfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'lua-guestfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'lua-guestfs-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'lua-guestfs-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nbdfuse-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdfuse-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdfuse-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdfuse-debuginfo-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdfuse-debuginfo-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdfuse-debuginfo-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-bash-completion-1.24.0-5.module+el8.8.0+1279+230c2115', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-filters-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-filters-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-filters-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-filters-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-plugins-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-plugins-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-plugins-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-basic-plugins-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-curl-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-curl-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-curl-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-curl-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-debugsource-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-debugsource-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-devel-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-devel-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-example-plugins-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-example-plugins-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-example-plugins-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-example-plugins-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-gzip-filter-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-gzip-filter-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-gzip-filter-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-gzip-filter-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-gzip-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-gzip-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-gzip-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-gzip-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-linuxdisk-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-linuxdisk-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-linuxdisk-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-linuxdisk-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-nbd-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-nbd-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-nbd-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-nbd-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-python-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-python-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-python-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-python-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-server-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-server-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-server-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-server-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-ssh-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-ssh-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-ssh-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-ssh-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-tar-filter-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-tar-filter-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-tar-filter-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-tar-filter-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-tar-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-tar-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-tar-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-tar-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-tmpdisk-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-tmpdisk-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-tmpdisk-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-tmpdisk-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-vddk-plugin-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-vddk-plugin-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-xz-filter-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-xz-filter-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-xz-filter-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nbdkit-xz-filter-debuginfo-1.24.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debuginfo-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-debugsource-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-devel-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netcf-libs-debuginfo-0.2.8-12.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-devel-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-devel-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-hivex-devel-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libguestfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-devel-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-devel-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libnbd-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-debuginfo-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-debuginfo-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-debuginfo-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-devel-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-devel-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocaml-libnbd-devel-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Guestfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Sys-Guestfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Sys-Guestfs-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Sys-Guestfs-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Sys-Virt-8.0.0-1.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-8.0.0-1.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-8.0.0-1.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-debuginfo-8.0.0-1.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-debuginfo-8.0.0-1.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-debuginfo-8.0.0-1.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-debugsource-8.0.0-1.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-debugsource-8.0.0-1.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Sys-Virt-debugsource-8.0.0-1.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libguestfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3-libguestfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3-libguestfs-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3-libguestfs-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3-libnbd-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libnbd-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libnbd-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libnbd-debuginfo-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libnbd-debuginfo-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libnbd-debuginfo-1.6.0-5.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libvirt-8.0.0-2.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libvirt-8.0.0-2.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libvirt-8.0.0-2.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libvirt-debuginfo-8.0.0-2.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libvirt-debuginfo-8.0.0-2.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libvirt-debuginfo-8.0.0-2.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-guest-agent-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-guest-agent-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-guest-agent-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-guest-agent-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-curl-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-curl-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-curl-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-curl-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-gluster-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-gluster-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-iscsi-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-iscsi-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-iscsi-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-iscsi-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-rbd-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-rbd-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-rbd-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-rbd-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-ssh-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-ssh-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-ssh-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-ssh-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-common-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-common-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-common-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-common-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-debugsource-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-debugsource-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-docs-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-docs-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-hw-usbredir-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-hw-usbredir-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-tests-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-tests-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-ui-opengl-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-ui-opengl-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-ui-spice-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-ui-spice-debuginfo-6.2.0-32.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'ruby-hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-debuginfo-1.3.18-23.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libguestfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ruby-libguestfs-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ruby-libguestfs-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ruby-libguestfs-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'seabios-1.16.0-3.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'seabios-bin-1.16.0-3.module+el8.8.0+1279+230c2115', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'seavgabios-bin-1.16.0-3.module+el8.8.0+1279+230c2115', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sgabios-0.20170427git-3.module+el8.8.0+1279+230c2115', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-0.20170427git-3.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'sgabios-bin-0.20170427git-3.module+el8.8.0+1279+230c2115', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'supermin-5.2.1-2.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-5.2.1-2.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-debuginfo-5.2.1-2.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-debuginfo-5.2.1-2.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-debugsource-5.2.1-2.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-debugsource-5.2.1-2.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-devel-5.2.1-2.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'supermin-devel-5.2.1-2.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-debuginfo-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-debuginfo-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-debugsource-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-debugsource-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-devel-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-libs-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-libs-debuginfo-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-libs-debuginfo-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-tools-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-tools-debuginfo-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-tools-debuginfo-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'swtpm-tools-pkcs11-0.7.0-4.20211109gitb79fd91.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virt-dib-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-dib-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-dib-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-dib-debuginfo-1.44.0-9.module+el8.8.0+1279+230c2115.rocky', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-v2v-1.42.0-22.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-v2v-bash-completion-1.42.0-22.module+el8.8.0+1279+230c2115', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-v2v-debuginfo-1.42.0-22.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-v2v-debugsource-1.42.0-22.module+el8.8.0+1279+230c2115', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-v2v-man-pages-ja-1.42.0-22.module+el8.8.0+1279+230c2115', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-v2v-man-pages-uk-1.42.0-22.module+el8.8.0+1279+230c2115', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_WARNING,
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
