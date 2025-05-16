#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:1762.
##

include('compat.inc');

if (description)
{
  script_id(184965);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/07");

  script_cve_id(
    "CVE-2020-11947",
    "CVE-2020-16092",
    "CVE-2020-25637",
    "CVE-2020-25707",
    "CVE-2020-25723",
    "CVE-2020-27821",
    "CVE-2020-28916",
    "CVE-2020-29129",
    "CVE-2020-29130",
    "CVE-2020-29443"
  );
  script_xref(name:"IAVB", value:"2020-B-0075-S");
  script_xref(name:"RLSA", value:"2021:1762");

  script_name(english:"Rocky Linux 8 : virt:rhel and virt-devel:rhel (RLSA-2021:1762)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2021:1762 advisory.

  - iscsi_aio_ioctl_cb in block/iscsi.c in QEMU 4.1.0 has a heap-based buffer over-read that may disclose
    unrelated information from process memory to an attacker. (CVE-2020-11947)

  - In QEMU through 5.0.0, an assertion failure can occur in the network packet processing. This issue affects
    the e1000e and vmxnet3 network devices. A malicious guest user/process could use this flaw to abort the
    QEMU process on the host, resulting in a denial of service condition in net_tx_pkt_add_raw_fragment in
    hw/net/net_tx_pkt.c. (CVE-2020-16092)

  - A double free memory issue was found to occur in the libvirt API, in versions before 6.8.0, responsible
    for requesting information about network interfaces of a running QEMU domain. This flaw affects the polkit
    access control driver. Specifically, clients connecting to the read-write socket with limited ACL
    permissions could use this flaw to crash the libvirt daemon, resulting in a denial of service, or
    potentially escalate their privileges on the system. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25637)

  - A reachable assertion issue was found in the USB EHCI emulation code of QEMU. It could occur while
    processing USB requests due to missing handling of DMA memory map failure. A malicious privileged user
    within the guest may abuse this flaw to send bogus USB requests and crash the QEMU process on the host,
    resulting in a denial of service. (CVE-2020-25723)

  - A flaw was found in the memory management API of QEMU during the initialization of a memory region cache.
    This issue could lead to an out-of-bounds write access to the MSI-X table while performing MMIO
    operations. A guest user may abuse this flaw to crash the QEMU process on the host, resulting in a denial
    of service. This flaw affects QEMU versions prior to 5.2.0. (CVE-2020-27821)

  - hw/net/e1000e_core.c in QEMU 5.0.0 has an infinite loop via an RX descriptor with a NULL buffer address.
    (CVE-2020-28916)

  - ncsi.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29129)

  - slirp.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29130)

  - ide_atapi_cmd_reply_end in hw/ide/atapi.c in QEMU 5.1.0 allows out-of-bounds read access because a buffer
    index is not validated. (CVE-2020-29443)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:1762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1384241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1798463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1828952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1834281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1837495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1843852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1846975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1850680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1859494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1860283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1872854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1874304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1874780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1876297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1876742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1880418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1880546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1881037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1884531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1893895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1898579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1901837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1902231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1902651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1902960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1903064");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1910220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1910267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1910326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1912765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1917446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1918708");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25637");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:hivex-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-benchmarking");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libguestfs-benchmarking-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libnbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libnbd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-admin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-bash-completion");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:qemu-kvm-tests-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:virt-dib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:virt-v2v-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
    {'reference':'libguestfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-bash-completion-1.40.2-27.module+el8.4.0+534+4680a14e', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-benchmarking-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-benchmarking-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-benchmarking-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-benchmarking-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-debugsource-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-debugsource-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-devel-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-devel-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gfs2-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gfs2-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gobject-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gobject-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gobject-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gobject-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gobject-devel-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-gobject-devel-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-inspect-icons-1.40.2-27.module+el8.4.0+534+4680a14e', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-devel-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-java-devel-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-javadoc-1.40.2-27.module+el8.4.0+534+4680a14e', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-man-pages-ja-1.40.2-27.module+el8.4.0+534+4680a14e', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-man-pages-uk-1.40.2-27.module+el8.4.0+534+4680a14e', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-rescue-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-rescue-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-rsync-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-rsync-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-1.40.2-27.module+el8.4.0+534+4680a14e', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-c-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-c-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-c-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-tools-c-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-winsupport-8.2-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libguestfs-winsupport-8.2-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libguestfs-winsupport-8.2-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libguestfs-xfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libguestfs-xfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
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
    {'reference':'libvirt-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-admin-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-admin-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-admin-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-admin-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-admin-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-admin-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-bash-completion-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-bash-completion-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-bash-completion-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-network-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-network-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-network-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-nwfilter-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-nwfilter-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-nwfilter-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-qemu-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-qemu-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-qemu-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-qemu-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-gluster-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-gluster-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-gluster-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-gluster-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-direct-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-direct-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-direct-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-direct-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-direct-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-direct-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-rbd-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-rbd-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-rbd-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-rbd-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-rbd-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-rbd-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-kvm-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-kvm-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
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
    {'reference':'libvirt-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-debugsource-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-debugsource-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-debugsource-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-devel-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-devel-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-devel-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-docs-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-docs-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-docs-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-lock-sanlock-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-lock-sanlock-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-lock-sanlock-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-lock-sanlock-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-debuginfo-6.0.0-35.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-python-debugsource-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-python-debugsource-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-python-debugsource-6.0.0-1.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lua-guestfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'lua-guestfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'lua-guestfs-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'lua-guestfs-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
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
    {'reference':'ocaml-libguestfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-devel-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ocaml-libguestfs-devel-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
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
    {'reference':'perl-Sys-Guestfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Sys-Guestfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Sys-Guestfs-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Sys-Guestfs-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
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
    {'reference':'python3-libguestfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3-libguestfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3-libguestfs-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3-libguestfs-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
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
    {'reference':'qemu-guest-agent-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-guest-agent-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-guest-agent-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-guest-agent-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-curl-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-curl-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-curl-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-curl-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-gluster-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-gluster-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-iscsi-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-iscsi-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-iscsi-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-iscsi-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-rbd-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-rbd-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-rbd-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-rbd-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-ssh-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-ssh-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-ssh-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-block-ssh-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-common-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-common-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-common-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-common-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-debugsource-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-debugsource-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-tests-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-tests-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-tests-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-tests-debuginfo-4.2.0-48.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'ruby-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-hivex-debuginfo-1.3.18-20.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libguestfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ruby-libguestfs-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ruby-libguestfs-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'ruby-libguestfs-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
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
    {'reference':'supermin-devel-5.1.19-10.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virt-dib-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-dib-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-dib-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-dib-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-v2v-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virt-v2v-debuginfo-1.40.2-27.module+el8.4.0+534+4680a14e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_HOLE,
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
