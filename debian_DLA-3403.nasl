#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3403. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175926);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2022-2873",
    "CVE-2022-3424",
    "CVE-2022-3545",
    "CVE-2022-3707",
    "CVE-2022-4744",
    "CVE-2022-36280",
    "CVE-2022-41218",
    "CVE-2022-45934",
    "CVE-2022-47929",
    "CVE-2023-0045",
    "CVE-2023-0266",
    "CVE-2023-0394",
    "CVE-2023-0458",
    "CVE-2023-0459",
    "CVE-2023-0461",
    "CVE-2023-1073",
    "CVE-2023-1074",
    "CVE-2023-1078",
    "CVE-2023-1079",
    "CVE-2023-1118",
    "CVE-2023-1281",
    "CVE-2023-1513",
    "CVE-2023-1670",
    "CVE-2023-1829",
    "CVE-2023-1855",
    "CVE-2023-1859",
    "CVE-2023-1989",
    "CVE-2023-1990",
    "CVE-2023-1998",
    "CVE-2023-2162",
    "CVE-2023-2194",
    "CVE-2023-23454",
    "CVE-2023-23455",
    "CVE-2023-23559",
    "CVE-2023-26545",
    "CVE-2023-28328",
    "CVE-2023-30456",
    "CVE-2023-30772"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Debian dla-3403 : hyperv-daemons - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3403 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3403-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Ben Hutchings
    May 3, 2023                                   https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : linux
    Version        : 4.19.282-1
    CVE ID         : CVE-2022-2873 CVE-2022-3424 CVE-2022-3545 CVE-2022-3707
                     CVE-2022-4744 CVE-2022-36280 CVE-2022-41218 CVE-2022-45934
                     CVE-2022-47929 CVE-2023-0045 CVE-2023-0266 CVE-2023-0394
                     CVE-2023-0458 CVE-2023-0459 CVE-2023-0461 CVE-2023-1073
                     CVE-2023-1074 CVE-2023-1078 CVE-2023-1079 CVE-2023-1118
                     CVE-2023-1281 CVE-2023-1513 CVE-2023-1670 CVE-2023-1829
                     CVE-2023-1855 CVE-2023-1859 CVE-2023-1989 CVE-2023-1990
                     CVE-2023-1998 CVE-2023-2162 CVE-2023-2194 CVE-2023-23454
                     CVE-2023-23455 CVE-2023-23559 CVE-2023-26545 CVE-2023-28328
                     CVE-2023-30456 CVE-2023-30772
    Debian Bug     : 825141

    Several vulnerabilities have been discovered in the Linux kernel that
    may lead to a privilege escalation, denial of service, or information
    leak.

    CVE-2022-2873

        Zheyu Ma discovered that an out-of-bounds memory access flaw in
        the Intel iSMT SMBus 2.0 host controller driver may result in
        denial of service (system crash).

    CVE-2022-3424

        Zheng Wang and Zhuorao Yang reported a flaw in the SGI GRU driver
        which could lead to a use-after-free.  On systems where this driver
        is used, a local user can explit this for denial of service (crash
        or memory corruption) or possibly for privilege escalation.

        This driver is not enabled in Debian's official kernel
        configurations.

    CVE-2022-3545

        It was discovered that the Netronome Flow Processor (NFP) driver
        contained a use-after-free flaw in area_cache_get(), which may
        result in denial of service or the execution of arbitrary code.

    CVE-2022-3707

        Zheng Wang reported a flaw in the i915 graphics driver's
        virtualisation (GVT-g) support that could lead to a double-free.
        On systems where this feature is used, a guest can exploit this
        for denial of service (crash or memory corruption) or possibly for
        privilege escalation.

    CVE-2022-4744

        The syzkaller tool found a flaw in the TUN/TAP network driver,
        which can lead to a double-free.  A local user can exploit this
        for denial of service (crash or memory corruption) or possibly for
        privilege escalation.

    CVE-2022-36280

        An out-of-bounds memory write vulnerability was discovered in the
        vmwgfx driver, which may allow a local unprivileged user to cause
        a denial of service (system crash).

    CVE-2022-41218

        Hyunwoo Kim reported a use-after-free flaw in the Media DVB core
        subsystem caused by refcount races, which may allow a local user
        to cause a denial of service or escalate privileges.

    CVE-2022-45934

        An integer overflow in l2cap_config_req() in the Bluetooth
        subsystem was discovered, which may allow a physically proximate
        attacker to cause a denial of service (system crash).

    CVE-2022-47929

        Frederick Lawler reported a NULL pointer dereference in the
        traffic control subsystem allowing an unprivileged user to cause a
        denial of service by setting up a specially crafted traffic
        control configuration.

    CVE-2023-0045

        Rodrigo Branco and Rafael Correa De Ysasi reported that when a
        user-space task told the kernel to enable Spectre v2 mitigation
        for it, the mitigation was not enabled until the task was next
        rescheduled.  This might be exploitable by a local or remote
        attacker to leak sensitive information from such an application.

    CVE-2023-0266

        A use-after-free flaw in the sound subsystem due to missing
        locking may result in denial of service or privilege escalation.

    CVE-2023-0394

        Kyle Zeng discovered a NULL pointer dereference flaw in
        rawv6_push_pending_frames() in the network subsystem allowing a
        local user to cause a denial of service (system crash).

    CVE-2023-0458

        Jordy Zimmer and Alexandra Sandulescu found that getrlimit() and
        related system calls were vulnerable to speculative execution
        attacks such as Spectre v1.  A local user could explot this to
        leak sensitive information from the kernel.

    CVE-2023-0459

        Jordy Zimmer and Alexandra Sandulescu found a regression in
        Spectre v1 mitigation in the user-copy functions for the amd64
        (64-bit PC) architecture.  Where the CPUs do not implement SMAP or
        it is disabled, a local user could exploit this to leak sensitive
        information from the kernel.  Other architectures may also be
        affected.

    CVE-2023-0461

        slipper reported a flaw in the kernel's support for ULPs (Upper
        Layer Protocols) on top of TCP that can lead to a double-free when
        using kernel TLS sockets.  A local user can exploit this for
        denial of service (crash or memory corruption) or possibly for
        privilege escalation.

        Kernel TLS is not enabled in Debian's official kernel
        configurations.

    CVE-2023-1073

        Pietro Borrello reported a type confusion flaw in the HID (Human
        Interface Device) subsystem.  An attacker able to insert and
        remove USB devices might be able to use this to cause a denial of
        service (crash or memory corruption) or possibly to run arbitrary
        code in the kernel.

    CVE-2023-1074

        Pietro Borrello reported a type confusion flaw in the SCTP
        protocol implementation which can lead to a memory leak.  A local
        user could exploit this to cause a denial of service (resource
        exhaustion).

    CVE-2023-1078

        Pietro Borrello reported a type confusion flaw in the RDS protocol
        implementation.  A local user could exploit this to cause a denial
        of service (crash or memory corruption) or possibly for privilege
        escalation.

    CVE-2023-1079

        Pietro Borrello reported a race condition in the hid-asus HID
        driver which could lead to a use-after-free.  An attacker able to
        insert and remove USB devices can use this to cause a denial of
        service (crash or memory corruption) or possibly to run arbitrary
        code in the kernel.

    CVE-2023-1118

        Duoming Zhou reported a race condition in the ene_ir remote
        control driver that can lead to a use-after-free if the driver
        is unbound.  It is not clear what the security impact of this is.

    CVE-2023-1281, CVE-2023-1829

        valis reported two flaws in the cls_tcindex network traffic
        classifier which could lead to a use-after-free.  A local user can
        exploit these for privilege escalation.  This update removes
        cls_tcindex entirely.

    CVE-2023-1513

        Xingyuan Mo reported an information leak in the KVM implementation
        for the i386 (32-bit PC) architecture.  A local user could exploit
        this to leak sensitive information from the kernel.

    CVE-2023-1670

        Zheng Wang reported a race condition in the xirc2ps_cs network
        driver which can lead to a use-after-free.  An attacker able to
        insert and remove PCMCIA devices can use this to cause a denial of
        service (crash or memory corruption) or possibly to run arbitrary
        code in the kernel.

    CVE-2023-1855

        Zheng Wang reported a race condition in the xgene-hwmon hardware
        monitoring driver that may lead to a use-after-free.  It is not
        clear what the security impact of this is.

    CVE-2023-1859

        Zheng Wang reported a race condition in the 9pnet_xen transport
        for the 9P filesystem on Xen, which can lead to a use-after-free.
        On systems where this feature is used, a backend driver in another
        domain can use this to cause a denial of service (crash or memory
        corruption) or possibly to run arbitrary code in the vulnerable
        domain.

    CVE-2023-1989

        Zheng Wang reported a race condition in the btsdio Bluetooth
        adapter driver that can lead to a use-after-free.  An attacker
        able to insert and remove SDIO devices can use this to cause a
        denial of service (crash or memory corruption) or possibly to run
        arbitrary code in the kernel.

    CVE-2023-1990

        Zheng Wang reported a race condition in the st-nci NFC adapter
        driver that can lead to a use-after-free.  It is not clear what
        the security impact of this is.

        This driver is not enabled in Debian's official kernel
        configurations.

    CVE-2023-1998

        Jos Oliveira and Rodrigo Branco reported a regression in Spectre
        v2 mitigation for user-space on x86 CPUs supporting IBRS but not
        eIBRS.  This might be exploitable by a local or remote attacker to
        leak sensitive information from a user-space application.

    CVE-2023-2162

        Mike Christie reported a race condition in the iSCSI TCP transport
        that can lead to a use-after-free.  On systems where this feature
        is used, a local user might be able to use this to cause a denial
        of service (crash or memory corruption) or possibly for privilege
        escalation.

    CVE-2023-2194

        Wei Chen reported a potential heap buffer overflow in the
        i2c-xgene-slimpro IC adapter driver.  A local user with
        permission to access such a device can use this to cause a denial
        of service (crash or memory corruption) and probably for privilege
        escalation.

    CVE-2023-23454

        Kyle Zeng reported that the Class Based Queueing (CBQ) network
        scheduler was prone to denial of service due to interpreting
        classification results before checking the classification return
        code.

    CVE-2023-23455

        Kyle Zeng reported that the ATM Virtual Circuits (ATM) network
        scheduler was prone to a denial of service due to interpreting
        classification results before checking the classification return
        code.

    CVE-2023-23559

        Szymon Heidrich reported incorrect bounds checks in the rndis_wlan
        Wi-Fi driver which may lead to a heap buffer overflow or overread.
        An attacker able to insert and remove USB devices can use this to
        cause a denial of service (crash or memory corruption) or
        information leak, or possibly to run arbitrary code in the kernel.

    CVE-2023-26545

        Lianhui Tang reported a flaw in the MPLS protocol implementation
        that could lead to a double-free.  A local user might be able to
        exploit this to cause a denial of service (crash or memory
        corruption) or possibl for privilege escalation.

    CVE-2023-28328

        Wei Chen reported a flaw in the az6927 DVB driver that can lead to
        a null pointer dereference.  A local user permitted to access an
        IC adapter device that this driver creates can use this to cause
        a denial of service (crash).

    CVE-2023-30456

        Reima ISHII reported a flaw in the KVM implementation for Intel
        CPUs affecting nested virtualisation.  When KVM was used as the L0
        hypervisor, and EPT and/or unrestricted guest mode was disabled,
        it did not prevent an L2 guest from being configured with an
        architecturally invalid protection/paging mode.  A malicious guest
        could exploit this to cause a denial of service (crash).

    CVE-2023-30772

        Zheng Wang reported a race condition in the da9150 charger driver
        which could lead to a use-after-free.  It is not clear what the
        security impact of this is.

        This driver is not enabled in Debian's official kernel
        configurations.

    For Debian 10 buster, these problems have been fixed in version
    4.19.282-1.  This update additionally fixes Debian bug #825141, and
    includes many more bug fixes from stable updates 4.19.270-4.19.282
    inclusive.

    We recommend that you upgrade your linux packages.

    For the detailed security status of linux please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/linux

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2873");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3424");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36280");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3707");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41218");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45934");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4744");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47929");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0045");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0266");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0394");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0458");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0459");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0461");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1073");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1074");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1078");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1079");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1118");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1281");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1513");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1670");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1829");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1855");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1859");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1989");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1990");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1998");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2162");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2194");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23454");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23455");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23559");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-26545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28328");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-30456");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-30772");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the hyperv-daemons packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0045");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-23559");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-26-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-26-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'hyperv-daemons', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'libbpf-dev', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'libbpf4.19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'libcpupower-dev', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'libcpupower1', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-arm', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-x86', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-config-4.19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-cpupower', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-doc-4.19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-686', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-686-pae', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-amd64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-arm64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-armhf', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-i386', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-amd64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-arm64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-armmp', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-armmp-lpae', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-cloud-amd64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-common', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-common-rt', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-686-pae', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-amd64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-arm64', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-armmp', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-686-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-686-pae-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-amd64-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-arm64-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-lpae', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-lpae-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-cloud-amd64-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-686-pae-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-amd64-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-arm64-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-armmp', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-armmp-dbg', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-4.19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-libc-dev', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-perf-4.19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-source-4.19', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'linux-support-4.19.0-26', 'reference': '4.19.282-1'},
    {'release': '10.0', 'prefix': 'usbip', 'reference': '4.19.282-1'}
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
