#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5173. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(162703);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2021-4197",
    "CVE-2022-0494",
    "CVE-2022-0812",
    "CVE-2022-0854",
    "CVE-2022-1011",
    "CVE-2022-1012",
    "CVE-2022-1016",
    "CVE-2022-1048",
    "CVE-2022-1184",
    "CVE-2022-1195",
    "CVE-2022-1198",
    "CVE-2022-1199",
    "CVE-2022-1204",
    "CVE-2022-1205",
    "CVE-2022-1353",
    "CVE-2022-1419",
    "CVE-2022-1516",
    "CVE-2022-1652",
    "CVE-2022-1729",
    "CVE-2022-1734",
    "CVE-2022-1974",
    "CVE-2022-1975",
    "CVE-2022-2153",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21166",
    "CVE-2022-23960",
    "CVE-2022-26490",
    "CVE-2022-27666",
    "CVE-2022-28356",
    "CVE-2022-28388",
    "CVE-2022-28389",
    "CVE-2022-28390",
    "CVE-2022-29581",
    "CVE-2022-30594",
    "CVE-2022-32250",
    "CVE-2022-32296",
    "CVE-2022-33981"
  );

  script_name(english:"Debian DSA-5173-1 : linux - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5173 advisory.

    Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation,
    denial of service or information leaks. CVE-2021-4197 Eric Biederman reported that incorrect permission
    checks in the cgroup process migration implementation can allow a local attacker to escalate privileges.
    CVE-2022-0494 The scsi_ioctl() was susceptible to an information leak only exploitable by users with
    CAP_SYS_ADMIN or CAP_SYS_RAWIO capabilities. CVE-2022-0812 It was discovered that the RDMA transport for
    NFS (xprtrdma) miscalculated the size of message headers, which could lead to a leak of sensitive
    information between NFS servers and clients. CVE-2022-0854 Ali Haider discovered a potential information
    leak in the DMA subsystem. On systems where the swiotlb feature is needed, this might allow a local user
    to read sensitive information. CVE-2022-1011 Jann Horn discovered a flaw in the FUSE (Filesystem in User-
    Space) implementation. A local user permitted to mount FUSE filesystems could exploit this to cause a use-
    after-free and read sensitive information. CVE-2022-1012, CVE-2022-32296 Moshe Kol, Amit Klein, and Yossi
    Gilad discovered a weakness in randomisation of TCP source port selection. CVE-2022-1016 David Bouman
    discovered a flaw in the netfilter subsystem where the nft_do_chain function did not initialize register
    data that nf_tables expressions can read from and write to. A local attacker can take advantage of this to
    read sensitive information. CVE-2022-1048 Hu Jiahui discovered a race condition in the sound subsystem
    that can result in a use-after-free. A local user permitted to access a PCM sound device can take
    advantage of this flaw to crash the system or potentially for privilege escalation. CVE-2022-1184 A flaw
    was discovered in the ext4 filesystem driver which can lead to a use-after-free. A local user permitted to
    mount arbitrary filesystems could exploit this to cause a denial of service (crash or memory corruption)
    or possibly for privilege escalation. CVE-2022-1195 Lin Ma discovered race conditions in the 6pack and
    mkiss hamradio drivers, which could lead to a use-after-free. A local user could exploit these to cause a
    denial of service (memory corruption or crash) or possibly for privilege escalation. CVE-2022-1198 Duoming
    Zhou discovered a race condition in the 6pack hamradio driver, which could lead to a use-after-free. A
    local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for
    privilege escalation. CVE-2022-1199, CVE-2022-1204, CVE-2022-1205 Duoming Zhou discovered race conditions
    in the AX.25 hamradio protocol, which could lead to a use-after-free or null pointer dereference. A local
    user could exploit this to cause a denial of service (memory corruption or crash) or possibly for
    privilege escalation. CVE-2022-1353 The TCS Robot tool found an information leak in the PF_KEY subsystem.
    A local user can receive a netlink message when an IPsec daemon registers with the kernel, and this could
    include sensitive information. CVE-2022-1419 Minh Yuan discovered a race condition in the vgem virtual GPU
    driver that can lead to a use-after-free. A local user permitted to access the GPU device can exploit this
    to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.
    CVE-2022-1516 A NULL pointer dereference flaw in the implementation of the X.25 set of standardized
    network protocols, which can result in denial of service. This driver is not enabled in Debian's official
    kernel configurations. CVE-2022-1652 Minh Yuan discovered a race condition in the floppy driver that can
    lead to a use-after-free. A local user permitted to access a floppy drive device can exploit this to cause
    a denial of service (crash or memory corruption) or possibly for privilege escalation. CVE-2022-1729
    Norbert Slusarek discovered a race condition in the perf subsystem which could result in local privilege
    escalation to root. The default settings in Debian prevent exploitation unless more permissive settings
    have been applied in the kernel.perf_event_paranoid sysctl. CVE-2022-1734 Duoming Zhou discovered race
    conditions in the nfcmrvl NFC driver that could lead to a use-after-free, double-free or null pointer
    dereference. A local user might be able to exploit these for denial of service (crash or memory
    corruption) or possibly for privilege escalation. This driver is not enabled in Debian's official kernel
    configurations. CVE-2022-1974, CVE-2022-1975 Duoming Zhou discovered that the NFC netlink interface was
    suspectible to denial of service. CVE-2022-2153 kangel reported a flaw in the KVM implementation for x86
    processors which could lead to a null pointer dereference. A local user permitted to access /dev/kvm could
    exploit this to cause a denial of service (crash). CVE-2022-21123, CVE-2022-21125, CVE-2022-21166 Various
    researchers discovered flaws in Intel x86 processors, collectively referred to as MMIO Stale Data
    vulnerabilities. These are similar to the previously published Microarchitectural Data Sampling (MDS)
    issues and could be exploited by local users to leak sensitive information. For some CPUs, the mitigations
    for these issues require updated microcode. An updated intel-microcode package may be provided at a later
    date. The updated CPU microcode may also be available as part of a system firmware (BIOS) update.
    Further information on the mitigation can be found at https://www.kernel.org/doc/html/latest/admin-
    guide/hw-vuln/processor_mmio_stale_data.html or in the linux-doc-4.19 package. CVE-2022-23960 Researchers
    at VUSec discovered that the Branch History Buffer in Arm processors can be exploited to create
    information side channels with speculative execution. This issue is similar to Spectre variant 2, but
    requires additional mitigations on some processors. This was previously mitigated for 32-bit Arm (armel
    and armhf) architectures and is now also mitigated for 64-bit Arm (arm64). This can be exploited to obtain
    sensitive information from a different security context, such as from user-space to the kernel, or from a
    KVM guest to the kernel. CVE-2022-26490 Buffer overflows in the STMicroelectronics ST21NFCA core driver
    can result in denial of service or privilege escalation. This driver is not enabled in Debian's official
    kernel configurations. CVE-2022-27666 valis reported a possible buffer overflow in the IPsec ESP
    transformation code. A local user can take advantage of this flaw to cause a denial of service or for
    privilege escalation. CVE-2022-28356 Beraphin discovered that the ANSI/IEEE 802.2 LLC type 2 driver did
    not properly perform reference counting on some error paths. A local attacker can take advantage of this
    flaw to cause a denial of service. CVE-2022-28388 A double free vulnerability was discovered in the 8
    devices USB2CAN interface driver. CVE-2022-28389 A double free vulnerability was discovered in the
    Microchip CAN BUS Analyzer interface driver. CVE-2022-28390 A double free vulnerability was discovered in
    the EMS CPC-USB/ARM7 CAN/USB interface driver. CVE-2022-29581 Kyle Zeng discovered a reference-counting
    bug in the cls_u32 network classifier which can lead to a use-after-free. A local user can exploit this to
    cause a denial of service (crash or memory corruption) or possibly for privilege escalation.
    CVE-2022-30594 Jann Horn discovered a flaw in the interaction between ptrace and seccomp subsystems. A
    process sandboxed using seccomp() but still permitted to use ptrace() could exploit this to remove the
    seccomp restrictions. CVE-2022-32250 Aaron Adams discovered a use-after-free in Netfilter which may result
    in local privilege escalation to root. CVE-2022-33981 Yuan Ming from Tsinghua University reported a race
    condition in the floppy driver involving use of the FDRAWCMD ioctl, which could lead to a use-after-free.
    A local user with access to a floppy drive device could exploit this to cause a denial of service (crash
    or memory corruption) or possibly for privilege escalation. This ioctl is now disabled by default. For the
    oldstable distribution (buster), these problems have been fixed in version 4.19.249-2. Due to an issue in
    the signing service (Cf. Debian bug #1012741), the vport-vxlan module cannot be loaded for the signed
    kernel for amd64 in this update. This update also corrects a regression in the network scheduler subsystem
    (bug #1013299). For the 32-bit Arm (armel and armhf) architectures, this update enables optimised
    implementations of several cryptographic and CRC algorithms. For at least AES, this should remove a timing
    sidechannel that could lead to a leak of sensitive information. This update includes many more bug fixes
    from stable updates 4.19.236-4.19.249 inclusive, including for bug #1006346. The random driver has been
    backported from Linux 5.19, fixing numerous performance and correctness issues. Some changes will be
    visible: The entropy pool size is now 256 bits instead of 4096. You may need to adjust the configuration
    of system monitoring or user-space entropy gathering services to allow for this. On systems without a
    hardware RNG, the kernel may log more uses of /dev/urandom before it is fully initialised. These uses were
    previously under-counted and this is not a regression. We recommend that you upgrade your linux packages.
    For the detailed security status of linux please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/linux

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=922204");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5173");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4197");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0494");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0812");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0854");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1011");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1012");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1048");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1195");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1198");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1199");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1204");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1205");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1353");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1419");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1516");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1652");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1729");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1734");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1974");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1975");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21123");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21125");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21166");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2153");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23960");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26490");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27666");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28356");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28388");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28389");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28390");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29581");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30594");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32250");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32296");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33981");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32250");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-mips64el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-mipsel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-ppc64el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'hyperv-daemons', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'libbpf-dev', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'libbpf4.19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'libcpupower-dev', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'libcpupower1', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-arm', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-s390', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-x86', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-config-4.19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-cpupower', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-doc-4.19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-4kc-malta', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-5kc-malta', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-686', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-686-pae', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-amd64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-arm64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-armel', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-armhf', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-i386', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-mips', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-mips64el', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-mipsel', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-ppc64el', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-s390x', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-amd64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-arm64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-armmp', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-armmp-lpae', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-cloud-amd64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-common', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-common-rt', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-loongson-3', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-marvell', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-octeon', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-powerpc64le', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rpi', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-686-pae', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-amd64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-arm64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-armmp', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-s390x', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-4kc-malta', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-4kc-malta-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-5kc-malta', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-5kc-malta-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-pae-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-pae-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-amd64-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-amd64-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-arm64-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-arm64-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-lpae', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-lpae-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-cloud-amd64-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-cloud-amd64-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-loongson-3', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-loongson-3-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-marvell', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-marvell-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-octeon', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-octeon-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-powerpc64le', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-powerpc64le-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rpi', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rpi-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-686-pae-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-686-pae-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-amd64-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-amd64-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-arm64-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-arm64-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-armmp', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-armmp-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-s390x', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-s390x-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-kbuild-4.19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-libc-dev', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-perf-4.19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-source-4.19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-support-4.19.0-19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'usbip', 'reference': '4.19.249-2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hyperv-daemons / libbpf-dev / libbpf4.19 / libcpupower-dev / etc');
}
