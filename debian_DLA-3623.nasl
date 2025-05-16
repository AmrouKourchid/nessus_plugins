#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3623. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(183491);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2022-4269",
    "CVE-2022-39189",
    "CVE-2023-1206",
    "CVE-2023-1380",
    "CVE-2023-2002",
    "CVE-2023-2007",
    "CVE-2023-2124",
    "CVE-2023-2269",
    "CVE-2023-2898",
    "CVE-2023-3090",
    "CVE-2023-3111",
    "CVE-2023-3141",
    "CVE-2023-3212",
    "CVE-2023-3268",
    "CVE-2023-3338",
    "CVE-2023-3389",
    "CVE-2023-3609",
    "CVE-2023-3611",
    "CVE-2023-3772",
    "CVE-2023-3773",
    "CVE-2023-3776",
    "CVE-2023-3863",
    "CVE-2023-4004",
    "CVE-2023-4128",
    "CVE-2023-4132",
    "CVE-2023-4147",
    "CVE-2023-4194",
    "CVE-2023-4244",
    "CVE-2023-4273",
    "CVE-2023-4622",
    "CVE-2023-4623",
    "CVE-2023-4921",
    "CVE-2023-20588",
    "CVE-2023-21255",
    "CVE-2023-21400",
    "CVE-2023-31084",
    "CVE-2023-34256",
    "CVE-2023-34319",
    "CVE-2023-35788",
    "CVE-2023-35823",
    "CVE-2023-35824",
    "CVE-2023-40283",
    "CVE-2023-42753",
    "CVE-2023-42755",
    "CVE-2023-42756"
  );

  script_name(english:"Debian dla-3623 : linux-config-5.10 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3623 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3623-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Ben Hutchings
    October 19, 2023                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : linux-5.10
    Version        : 5.10.197-1~deb10u1
    CVE ID         : CVE-2022-4269 CVE-2022-39189 CVE-2023-1206 CVE-2023-1380
                     CVE-2023-2002 CVE-2023-2007 CVE-2023-2124 CVE-2023-2269
                     CVE-2023-2898 CVE-2023-3090 CVE-2023-3111 CVE-2023-3141
                     CVE-2023-3212 CVE-2023-3268 CVE-2023-3338 CVE-2023-3389
                     CVE-2023-3609 CVE-2023-3611 CVE-2023-3772 CVE-2023-3773
                     CVE-2023-3776 CVE-2023-3863 CVE-2023-4004 CVE-2023-4128
                     CVE-2023-4132 CVE-2023-4147 CVE-2023-4194 CVE-2023-4244
                     CVE-2023-4273 CVE-2023-4622 CVE-2023-4623 CVE-2023-4921
                     CVE-2023-20588 CVE-2023-21255 CVE-2023-21400 CVE-2023-31084
                     CVE-2023-34256 CVE-2023-34319 CVE-2023-35788 CVE-2023-35823
                     CVE-2023-35824 CVE-2023-40283 CVE-2023-42753 CVE-2023-42755
                     CVE-2023-42756
    Debian Bug     : 871216 1035359 1036543 1044518 1050622

    Several vulnerabilities have been discovered in the Linux kernel that
    may lead to a privilege escalation, denial of service or information
    leaks.

    CVE-2022-4269

        William Zhao discovered that a flaw in the Traffic Control (TC)
        subsystem when using a specific networking configuration
        (redirecting egress packets to ingress using TC action mirred),
        may allow a local unprivileged user to cause a denial of service
        (triggering a CPU soft lockup).

    CVE-2022-39189

        Jann Horn discovered that TLB flush operations are mishandled in
        the KVM subsystem in certain KVM_VCPU_PREEMPTED situations, which
        may allow an unprivileged guest user to compromise the guest
        kernel.

    CVE-2023-1206

        It was discovered that the networking stack permits attackers to
        force hash collisions in the IPv6 connection lookup table, which
        may result in denial of service (significant increase in the cost
        of lookups, increased CPU utilization).

    CVE-2023-1380

        Jisoo Jang reported a heap out-of-bounds read in the brcmfmac
        Wi-Fi driver. On systems using this driver, a local user could
        exploit this to read sensitive information or to cause a denial of
        service.

    CVE-2023-2002

        Ruiahn Li reported an incorrect permissions check in the Bluetooth
        subsystem. A local user could exploit this to reconfigure local
        Bluetooth interfaces, resulting in information leaks, spoofing, or
        denial of service (loss of connection).

    CVE-2023-2007

        Lucas Leong and Reno Robert discovered a
        time-of-check-to-time-of-use flaw in the dpt_i2o SCSI controller
        driver. A local user with access to a SCSI device using this
        driver could exploit this for privilege escalation.

        This flaw has been mitigated by removing support for the I2OUSRCMD
        operation.

    CVE-2023-2124

        Kyle Zeng, Akshay Ajayan and Fish Wang discovered that missing
        metadata validation may result in denial of service or potential
        privilege escalation if a corrupted XFS disk image is mounted.

    CVE-2023-2269

        Zheng Zhang reported that improper handling of locking in the
        device mapper implementation may result in denial of service.

    CVE-2023-2898

        It was discovered that missing sanitising in the f2fs file system
        may result in denial of service if a malformed file system is
        accessed.

    CVE-2023-3090

        It was discovered that missing initialization in ipvlan networking
        may lead to an out-of-bounds write vulnerability, resulting in
        denial of service or potentially the execution of arbitrary code.

    CVE-2023-3111

        The TOTE Robot tool found a flaw in the Btrfs filesystem driver
        that can lead to a use-after-free. It's unclear whether an
        unprivileged user can exploit this.

    CVE-2023-3141

        A flaw was discovered in the r592 memstick driver that could lead
        to a use-after-free after the driver is removed or unbound from a
        device. The security impact of this is unclear.

    CVE-2023-3212

        Yang Lan discovered that missing validation in the GFS2 filesystem
        could result in denial of service via a NULL pointer dereference
        when mounting a malformed GFS2 filesystem.

    CVE-2023-3268

        It was discovered that an out-of-bounds memory access in relayfs
        could result in denial of service or an information leak.

    CVE-2023-3338

        Davide Ornaghi discovered a flaw in the DECnet protocol
        implementation which could lead to a null pointer dereference or
        use-after-free. A local user can exploit this to cause a denial of
        service (crash or memory corruption) and probably for privilege
        escalation.

        This flaw has been mitigated by removing the DECnet protocol
        implementation.

    CVE-2023-3389

        Querijn Voet discovered a use-after-free in the io_uring
        subsystem, which may result in denial of service or privilege
        escalation.

    CVE-2023-3609, CVE-2023-3776. CVE-2023-4128

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

    CVE-2023-3773

        Lin Ma discovered a flaw in the XFRM subsystem, which may result
        in denial of service for a user with the CAP_NET_ADMIN capability
        in any user or network namespace.

    CVE-2023-3863

        It was discovered that a use-after-free in the NFC implementation
        may result in denial of service, an information leak or potential
        local privilege escalation.

    CVE-2023-4004

        It was discovered that a use-after-free in Netfilter's
        implementation of PIPAPO (PIle PAcket POlicies) may result in
        denial of service or potential local privilege escalation for a
        user with the CAP_NET_ADMIN capability in any user or network
        namespace.

    CVE-2023-4132

        A use-after-free in the driver for Siano SMS1xxx based MDTV
        receivers may result in local denial of service.

    CVE-2023-4147

        Kevin Rich discovered a use-after-free in Netfilter when adding a
        rule with NFTA_RULE_CHAIN_ID, which may result in local privilege
        escalation for a user with the CAP_NET_ADMIN capability in any
        user or network namespace.

    CVE-2023-4194

        A type confusion in the implementation of TUN/TAP network devices
        may allow a local user to bypass network filters.

    CVE-2023-4244

        A race condition was found in the nftables subsystem that could
        lead to a use-after-free.  A local user could exploit this to
        cause a denial of service (crash), information leak, or possibly
        for privilege escalation.

    CVE-2023-4273

        Maxim Suhanov discovered a stack overflow in the exFAT driver,
        which may result in local denial of service via a malformed file
        system.

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

    CVE-2023-20588

        Jana Hofmann, Emanuele Vannacci, Cedric Fournet, Boris Koepf and
        Oleksii Oleksenko discovered that on some AMD CPUs with the Zen1
        micro architecture an integer division by zero may leave stale
        quotient data from a previous division, resulting in a potential
        leak of sensitive data.

    CVE-2023-21255

        A use-after-free was discovered in the Android binder driver,
        which may result in local privilege escalation on systems where
        the binder driver is loaded.

    CVE-2023-21400

        Ye Zhang and Nicolas Wu discovered a double-free in the io_uring
        subsystem, which may result in denial of service or privilege
        escalation.

    CVE-2023-31084

        It was discovered that the DVB Core driver does not properly
        handle locking of certain events, allowing a local user to cause a
        denial of service.

    CVE-2023-34256

        The syzbot tool found a time-of-check-to-time-of-use flaw in the
        ext4 filesystem driver. An attacker able to mount a disk image or
        device that they can also write to directly could exploit this to
        cause an out-of-bounds read, possibly resulting in a leak of
        sensitive information or denial of service (crash).

    CVE-2023-34319

        Ross Lagerwall discovered a buffer overrun in Xen's netback driver
        which may allow a Xen guest to cause denial of service to the
        virtualisation host by sending malformed packets.

    CVE-2023-35788

        Hangyu Hua discovered that an off-by-one in the Flower traffic
        classifier may result in local denial of service or the execution
        of privilege escalation.

    CVE-2023-35823

        A flaw was discovered in the saa7134 media driver that could lead
        to a use-after-free after the driver is removed or unbound from a
        device. The security impact of this is unclear.

    CVE-2023-35824

        A flaw was discovered in the dm1105 media driver that could lead
        to a use-after-free after the driver is removed or unbound from a
        device. The security impact of this is unclear.

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

    CVE-2023-42755

        Kyle Zeng discovered missing configuration validation in the
        cls_rsvp network classifier which could lead to out-of-bounds
        reads.  A local user with the CAP_NET_ADMIN capability in any user
        or network namespace could exploit this to cause a denial of
        service (crash) or to leak sensitive information.

        This flaw has been mitigated by removing the cls_rsvp classifier.

    CVE-2023-42756

        Kyle Zeng discovered a race condition in the netfiler ipset
        subsystem which could lead to an assertion failure.  A local user
        with the CAP_NET_ADMIN capability in any user or network namespace
        could exploit this to cause a denial of service (crash).

    For Debian 10 buster, these problems have been fixed in version
    5.10.197-1~deb10u1.  This update additionally fixes Debian bugs
    #871216, #1035359, #1036543, #1044518, and #1050622; and includes many
    more bug fixes from stable updates 5.10.180-5.10.197 inclusive.

    We recommend that you upgrade your linux-5.10 packages.

    For the detailed security status of linux-5.10 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/linux-5.10

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux-5.10");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39189");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4269");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1206");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1380");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2002");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2007");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-20588");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2124");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-21255");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-21400");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2269");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2898");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3090");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-31084");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3111");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3141");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3212");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3268");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3338");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3389");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-34256");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-34319");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35788");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35823");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35824");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3609");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3611");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3772");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3773");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3776");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3863");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4004");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40283");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4128");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4132");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4147");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4194");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4244");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4273");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-42753");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-42755");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-42756");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4622");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4623");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4921");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux-5.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux-config-5.10 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4921");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-4004");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.24-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.26-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.27-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.28-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.29-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.30-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.24-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.26-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.27-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.28-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.29-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.30-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.29");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.30");
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
    {'release': '10.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-686', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-686-pae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-cloud-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-cloud-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-common', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-common-rt', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-rt-686-pae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-rt-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-rt-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-686', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-686-pae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-cloud-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-cloud-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-common', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-common-rt', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-rt-686-pae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-rt-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-rt-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-686', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-686-pae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-cloud-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-cloud-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-common', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-common-rt', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-rt-686-pae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-rt-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-rt-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-686', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-686-pae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-cloud-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-cloud-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-common', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-common-rt', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-rt-686-pae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-rt-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-rt-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-686', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-686-pae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-cloud-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-cloud-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-common', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-common-rt', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-rt-686-pae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-rt-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-rt-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-686', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-686-pae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-cloud-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-cloud-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-common', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-common-rt', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-rt-686-pae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-rt-amd64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-rt-arm64', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-signed-template', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-signed-template', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-i386-signed-template', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-686-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-armmp-lpae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-cloud-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-cloud-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-686-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-armmp-lpae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-cloud-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-cloud-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-686-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-armmp-lpae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-cloud-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-cloud-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-686-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-armmp-lpae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-cloud-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-cloud-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-686-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-armmp-lpae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-cloud-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-cloud-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-686-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-armmp-lpae', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-armmp-lpae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-cloud-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-cloud-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-686-pae-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-amd64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-arm64-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-armmp', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-armmp-dbg', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.24', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.26', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.27', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.28', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.29', 'reference': '5.10.197-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.30', 'reference': '5.10.197-1~deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-config-5.10 / linux-doc-5.10 / linux-headers-5.10-armmp / etc');
}
