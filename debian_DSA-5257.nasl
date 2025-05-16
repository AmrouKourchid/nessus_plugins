#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5257. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(166232);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2021-4037",
    "CVE-2022-0171",
    "CVE-2022-1184",
    "CVE-2022-2602",
    "CVE-2022-2663",
    "CVE-2022-3061",
    "CVE-2022-3176",
    "CVE-2022-3303",
    "CVE-2022-20421",
    "CVE-2022-39188",
    "CVE-2022-39842",
    "CVE-2022-40307",
    "CVE-2022-41674",
    "CVE-2022-42719",
    "CVE-2022-42720",
    "CVE-2022-42721",
    "CVE-2022-42722"
  );

  script_name(english:"Debian DSA-5257-1 : linux - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5257 advisory.

    Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation,
    denial of service or information leaks. CVE-2021-4037 Christian Brauner reported that the inode_init_owner
    function for the XFS filesystem in the Linux kernel allows local users to create files with an unintended
    group ownership allowing attackers to escalate privileges by making a plain file executable and SGID.
    CVE-2022-0171 Mingwei Zhang reported that a cache incoherence issue in the SEV API in the KVM subsystem
    may result in denial of service. CVE-2022-1184 A flaw was discovered in the ext4 filesystem driver which
    can lead to a use-after-free. A local user permitted to mount arbitrary filesystems could exploit this to
    cause a denial of service (crash or memory corruption) or possibly for privilege escalation. CVE-2022-2602
    A race between handling an io_uring request and the Unix socket garbage collector was discovered. An
    attacker can take advantage of this flaw for local privilege escalation. CVE-2022-2663 David Leadbeater
    reported flaws in the nf_conntrack_irc connection-tracking protocol module. When this module is enabled on
    a firewall, an external user on the same IRC network as an internal user could exploit its lax parsing to
    open arbitrary TCP ports in the firewall, to reveal their public IP address, or to block their IRC
    connection at the firewall. CVE-2022-3061 A flaw was discovered in the i740 driver which may result in
    denial of service. This driver is not enabled in Debian's official kernel configurations. CVE-2022-3176 A
    use-after-free flaw was discovered in the io_uring subsystem which may result in local privilege
    escalation to root. CVE-2022-3303 A race condition in the snd_pcm_oss_sync function in the sound subsystem
    in the Linux kernel due to improper locking may result in denial of service. CVE-2022-20421 A use-after-
    free vulnerability was discovered in the binder_inc_ref_for_node function in the Android binder driver. On
    systems where the binder driver is loaded, a local user could exploit this for privilege escalation.
    CVE-2022-39188 Jann Horn reported a race condition in the kernel's handling of unmapping of certain memory
    ranges. When a driver created a memory mapping with the VM_PFNMAP flag, which many GPU drivers do, the
    memory mapping could be removed and freed before it was flushed from the CPU TLBs. This could result in a
    page use-after-free. A local user with access to such a device could exploit this to cause a denial of
    service (crash or memory corruption) or possibly for privilege escalation. CVE-2022-39842 An integer
    overflow was discovered in the pxa3xx-gcu video driver which could lead to a heap out-of-bounds write.
    This driver is not enabled in Debian's official kernel configurations. CVE-2022-40307 A race condition was
    discovered in the EFI capsule-loader driver, which could lead to use-after-free. A local user permitted to
    access this device (/dev/efi_capsule_loader) could exploit this to cause a denial of service (crash or
    memory corruption) or possibly for privilege escalation. However, this device is normally only accessible
    by the root user. CVE-2022-41674, CVE-2022-42719, CVE-2022-42720, CVE-2022-42721, CVE-2022-42722 Soenke
    Huster discovered several vulnerabilities in the mac80211 subsystem triggered by WLAN frames which may
    result in denial of service or the execution or arbitrary code. For the stable distribution (bullseye),
    these problems have been fixed in version 5.10.149-1. We recommend that you upgrade your linux packages.
    For the detailed security status of linux please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/linux

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5257");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4037");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0171");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-20421");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2602");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2663");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3061");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3176");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3303");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39188");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39842");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-40307");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41674");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42719");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42720");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42721");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42722");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.149-1.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42719");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'bpftool', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'hyperv-daemons', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'libcpupower-dev', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'libcpupower1', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-arm', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-s390', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-x86', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-cpupower', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-doc', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-4kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-4kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-5kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-686', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-686-pae', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-amd64', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-arm64', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-armmp-lpae', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-cloud-amd64', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-cloud-arm64', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-common', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-common-rt', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-loongson-3', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-marvell', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-octeon', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-powerpc64le', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-rpi', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-rt-686-pae', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-rt-amd64', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-rt-arm64', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-rt-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-s390x', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp-lpae', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-loongson-3', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-marvell', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-octeon', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-powerpc64le', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rpi', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rt-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-s390x', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-4kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-4kc-malta-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-5kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-5kc-malta-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-686-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-686-pae-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-686-pae-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-686-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-amd64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-amd64-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-arm64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-arm64-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-armmp-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-armmp-lpae', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-armmp-lpae-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-cloud-amd64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-cloud-amd64-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-cloud-arm64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-cloud-arm64-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-loongson-3', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-loongson-3-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-marvell', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-marvell-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-octeon', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-octeon-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-powerpc64le', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-powerpc64le-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rpi', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rpi-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-686-pae-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-686-pae-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-amd64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-amd64-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-arm64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-arm64-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-armmp-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-s390x', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-s390x-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-pae-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-amd64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-arm64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-marvell', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-marvell-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-octeon', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-octeon-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rpi', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rpi-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-686-pae-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-amd64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-arm64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-s390x', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-s390x-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-libc-dev', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-perf', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-source', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-support-5.10.0-16', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usbip', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'affs-modules-5.10.0-16-4kc-malta-di / etc');
}
