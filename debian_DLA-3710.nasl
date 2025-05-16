#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3710. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(189094);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id(
    "CVE-2021-44879",
    "CVE-2023-0590",
    "CVE-2023-1077",
    "CVE-2023-1206",
    "CVE-2023-1989",
    "CVE-2023-3212",
    "CVE-2023-3390",
    "CVE-2023-3609",
    "CVE-2023-3611",
    "CVE-2023-3772",
    "CVE-2023-3776",
    "CVE-2023-4206",
    "CVE-2023-4207",
    "CVE-2023-4208",
    "CVE-2023-4244",
    "CVE-2023-4622",
    "CVE-2023-4623",
    "CVE-2023-4921",
    "CVE-2023-5717",
    "CVE-2023-6606",
    "CVE-2023-6931",
    "CVE-2023-6932",
    "CVE-2023-25775",
    "CVE-2023-34319",
    "CVE-2023-34324",
    "CVE-2023-35001",
    "CVE-2023-39189",
    "CVE-2023-39192",
    "CVE-2023-39193",
    "CVE-2023-39194",
    "CVE-2023-40283",
    "CVE-2023-42753",
    "CVE-2023-42754",
    "CVE-2023-42755",
    "CVE-2023-45863",
    "CVE-2023-45871",
    "CVE-2023-51780",
    "CVE-2023-51781",
    "CVE-2023-51782"
  );

  script_name(english:"Debian dla-3710 : hyperv-daemons - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3710 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3710-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Ben Hutchings
    January 10, 2024                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : linux
    Version        : 4.19.304-1
    CVE ID         : CVE-2021-44879 CVE-2023-0590 CVE-2023-1077 CVE-2023-1206
                     CVE-2023-1989 CVE-2023-3212 CVE-2023-3390 CVE-2023-3609
                     CVE-2023-3611 CVE-2023-3772 CVE-2023-3776 CVE-2023-4206
                     CVE-2023-4207 CVE-2023-4208 CVE-2023-4244 CVE-2023-4622
                     CVE-2023-4623 CVE-2023-4921 CVE-2023-5717 CVE-2023-6606
                     CVE-2023-6931 CVE-2023-6932 CVE-2023-25775 CVE-2023-34319
                     CVE-2023-34324 CVE-2023-35001 CVE-2023-39189 CVE-2023-39192
                     CVE-2023-39193 CVE-2023-39194 CVE-2023-40283 CVE-2023-42753
                     CVE-2023-42754 CVE-2023-42755 CVE-2023-45863 CVE-2023-45871
                     CVE-2023-51780 CVE-2023-51781 CVE-2023-51782

    Several vulnerabilities have been discovered in the Linux kernel that
    may lead to a privilege escalation, denial of service or information
    leaks.

    CVE-2021-44879

        Wenqing Liu reported a NULL pointer dereference in the f2fs
        implementation. An attacker able to mount a specially crafted image
        can take advantage of this flaw for denial of service.

    CVE-2023-0590

        Dmitry Vyukov discovered a race condition in the network scheduler
        core that that can lead to a use-after-free.  A local user with
        the CAP_NET_ADMIN capability in any user or network namespace
        could exploit this to cause a denial of service (crash or memory
        corruption) or possibly for privilege escalation.

    CVE-2023-1077

        Pietro Borrello reported a type confusion flaw in the task
        scheduler.  A local user might be able to exploit this to cause a
        denial of service (crash or memory corruption) or possibly for
        privilege escalation.

    CVE-2023-1206

        It was discovered that the networking stack permits attackers to
        force hash collisions in the IPv6 connection lookup table, which
        may result in denial of service (significant increase in the cost
        of lookups, increased CPU utilization).

    CVE-2023-1989

        Zheng Wang reported a race condition in the btsdio Bluetooth
        adapter driver that can lead to a use-after-free.  An attacker
        able to insert and remove SDIO devices can use this to cause a
        denial of service (crash or memory corruption) or possibly to run
        arbitrary code in the kernel.

    CVE-2023-3212

        Yang Lan discovered that missing validation in the GFS2 filesystem
        could result in denial of service via a NULL pointer dereference
        when mounting a malformed GFS2 filesystem.

    CVE-2023-3390

        A use-after-free flaw in the netfilter subsystem caused by
        incorrect error path handling may result in denial of service or
        privilege escalation.

    CVE-2023-3609, CVE-2023-3776, CVE-2023-4206, CVE-2023-4207, CVE-2023-4208

        It was discovered that a use-after-free in the cls_fw, cls_u32,
        cls_route and network classifiers may result in denial of service
        or potential local privilege escalation.

    CVE-2023-3611

        It was discovered that an out-of-bounds write in the traffic
        control subsystem for the Quick Fair Queueing scheduler (QFQ) may
        result in denial of service or privilege escalation.

    CVE-2023-3772

        Lin Ma discovered a NULL pointer dereference flaw in the XFRM
        subsystem which may result in denial of service.

    CVE-2023-4244

        A race condition was found in the nftables subsystem that could
        lead to a use-after-free.  A local user could exploit this to
        cause a denial of service (crash), information leak, or possibly
        for privilege escalation.

    CVE-2023-4622

        Bing-Jhong Billy Jheng discovered a use-after-free within the Unix
        domain sockets component, which may result in local privilege
        escalation.

    CVE-2023-4623

        Budimir Markovic reported a missing configuration check in the
        sch_hfsc network scheduler that could lead to a use-after-free or
        other problems.  A local user with the CAP_NET_ADMIN capability in
        any user or network namespace could exploit this to cause a denial
        of service (crash or memory corruption) or possibly for privilege
        escalation.

    CVE-2023-4921

        valis reported flaws in the sch_qfq network scheduler that could
        lead to a use-after-free.  A local user with the CAP_NET_ADMIN
        capability in any user or network namespace could exploit this to
        cause a denial of service (crash or memory corruption) or possibly
        for privilege escalation.

    CVE-2023-5717

        Budimir Markovic reported a heap out-of-bounds write vulnerability
        in the Linux kernel's Performance Events system caused by improper
        handling of event groups, which may result in denial of service or
        privilege escalation. The default settings in Debian prevent
        exploitation unless more permissive settings have been applied in
        the kernel.perf_event_paranoid sysctl.

    CVE-2023-6606

        j51569436 reported a potential out-of-bounds read in the CIFS
        filesystem implementation.  If a CIFS filesystem is mounted from a
        malicious server, the server could possibly exploit this to cause
        a denial of service (crash).

    CVE-2023-6931

        Budimir Markovic reported a heap out-of-bounds write vulnerability
        in the Linux kernel's Performance Events system which may result in
        denial of service or privilege escalation. The default settings in
        Debian prevent exploitation unless more permissive settings have
        been applied in the kernel.perf_event_paranoid sysctl.

    CVE-2023-6932

        A use-after-free vulnerability in the IPv4 IGMP implementation may
        result in denial of service or privilege escalation.

    CVE-2023-25775

        Ivan D Barrera, Christopher Bednarz, Mustafa Ismail and Shiraz
        Saleem discovered that improper access control in the Intel Ethernet
        Controller RDMA driver may result in privilege escalation.

    CVE-2023-34319

        Ross Lagerwall discovered a buffer overrun in Xen's netback driver
        which may allow a Xen guest to cause denial of service to the
        virtualisation host by sending malformed packets.

    CVE-2023-34324

        Marek Marczykowski-Gorecki reported a possible deadlock in the Xen
        guests event channel code which may allow a malicious guest
        administrator to cause a denial of service.

    CVE-2023-35001

        Tanguy DUBROCA discovered an out-of-bounds reads and write flaw in
        the Netfilter nf_tables implementation when processing an
        nft_byteorder expression, which may result in local privilege
        escalation for a user with the CAP_NET_ADMIN capability in any
        user or network namespace.

    CVE-2023-39189, CVE-2023-39192, CVE-2023-39193

        Lucas Leong of Trend Micro Zero Day Initiative reported missing
        bounds checks in the nfnetlink_osf, xt_u32, and xt_sctp netfilter
        modules.  A local user with the CAP_NET_ADMIN capability in any
        user or network namespace could exploit these to leak sensitive
        information from the kernel or for denial of service (crash).

    CVE-2023-39194

        Lucas Leong of Trend Micro Zero Day Initiative reported a missing
        bounds check in the xfrm (IPsec) subsystem.  A local user with the
        CAP_NET_ADMIN capability in any user or network namespace could
        exploit this to leak sensitive information from the kernel or for
        denial of service (crash).

    CVE-2023-40283

        A use-after-free was discovered in Bluetooth L2CAP socket
        handling.

    CVE-2023-42753

        Kyle Zeng discovered an off-by-one error in the netfilter ipset
        subsystem which could lead to out-of-bounds memory access.  A
        local user with the CAP_NET_ADMIN capability in any user or
        network namespace could exploit this to cause a denial of service
        (memory corruption or crash) and possibly for privilege
        escalation.

    CVE-2023-42754

        Kyle Zeng discovered a flaw in the IPv4 implementation which could
        lead to a null pointer deference.  A local user could exploit this
        for denial of service (crash).

    CVE-2023-42755

        Kyle Zeng discovered missing configuration validation in the
        cls_rsvp network classifier which could lead to out-of-bounds
        reads.  A local user with the CAP_NET_ADMIN capability in any user
        or network namespace could exploit this to cause a denial of
        service (crash) or to leak sensitive information.

        This flaw has been mitigated by removing the cls_rsvp classifier.

    CVE-2023-45863

        A race condition in library routines for handling generic kernel
        objects may result in an out-of-bounds write in the
        fill_kobj_path() function.

    CVE-2023-45871

        Manfred Rudigier reported a flaw in the igb network driver for
        Intel Gigabit Ethernet interfaces.  When the rx-all feature was
        enabled on such a network interface, an attacker on the same
        network segment could send packets that would overflow a receive
        buffer, leading to a denial of service (crash or memory
        corruption) or possibly remote code execution.

    CVE-2023-51780

        It was discovered that a race condition in the ATM (Asynchronous
        Transfer Mode) subsystem may lead to a use-after-free.

    CVE-2023-51781

        It was discovered that a race condition in the Appletalk subsystem
        may lead to a use-after-free.

    CVE-2023-51782

        It was discovered that a race condition in the Amateur Radio X.25
        PLP (Rose) support may lead to a use-after-free. This module is not
        auto-loaded on Debian systems, so this issue only affects systems
        where it is explicitly loaded.

    For Debian 10 buster, these problems have been fixed in version
    4.19.304-1.  This update additionally includes many more bug fixes
    from stable updates 4.19.290-4.19.304 inclusive.

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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44879");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0590");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1077");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1206");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1989");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-25775");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3212");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3390");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-34319");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-34324");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35001");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3609");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3611");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3772");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3776");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39189");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39192");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39193");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39194");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40283");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4206");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4207");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4208");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4244");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-42753");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-42754");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-42755");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45863");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45871");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4622");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4623");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4921");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-51780");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-51781");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-51782");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-5717");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6606");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6931");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6932");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the hyperv-daemons packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44879");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-25775");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-3776");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

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

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'hyperv-daemons', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'libbpf-dev', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'libbpf4.19', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'libcpupower-dev', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'libcpupower1', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-arm', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-x86', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-config-4.19', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-cpupower', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-doc-4.19', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-686', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-686-pae', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-amd64', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-arm64', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-armhf', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-i386', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-amd64', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-arm64', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-armmp', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-armmp-lpae', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-cloud-amd64', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-common', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-common-rt', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-686-pae', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-amd64', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-arm64', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-armmp', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-686-dbg', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-686-pae-dbg', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-amd64-dbg', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-arm64-dbg', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-dbg', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-lpae', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-lpae-dbg', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-cloud-amd64-dbg', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-686-pae-dbg', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-amd64-dbg', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-arm64-dbg', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-armmp', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-armmp-dbg', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-4.19', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-libc-dev', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-perf-4.19', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-source-4.19', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'linux-support-4.19.0-26', 'reference': '4.19.304-1'},
    {'release': '10.0', 'prefix': 'usbip', 'reference': '4.19.304-1'}
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
    severity   : SECURITY_WARNING,
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
