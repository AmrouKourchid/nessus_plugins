#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5402. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175664);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2023-0386", "CVE-2023-31436", "CVE-2023-32233");

  script_name(english:"Debian DSA-5402-1 : linux - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5402 advisory.

  - A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with
    capabilities was found in the Linux kernel's OverlayFS subsystem in how a user copies a capable file from
    a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges
    on the system. (CVE-2023-0386)

  - qfq_change_class in net/sched/sch_qfq.c in the Linux kernel before 6.2.13 allows an out-of-bounds write
    because lmax can exceed QFQ_MIN_LMAX. (CVE-2023-31436)

  - In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests
    can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users
    can obtain root privileges. This occurs because anonymous sets are mishandled. (CVE-2023-32233)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5402");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0386");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-31436");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32233");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.179-1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32233");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Local Privilege Escalation via CVE-2023-0386');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-22-marvell-di");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-20-s390x");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-20-s390x-dbg");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-22-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-22-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-20-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-20-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-20-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-20-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-20-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-20-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-22-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-22-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-22-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-22-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-22-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-22-s390x-di");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'bpftool', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'hyperv-daemons', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'libcpupower-dev', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'libcpupower1', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-arm', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-s390', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-x86', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-cpupower', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-doc', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-4kc-malta', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-4kc-malta', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-5kc-malta', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-686', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-686-pae', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-amd64', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-arm64', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-armmp', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-armmp-lpae', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-cloud-amd64', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-cloud-arm64', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-common', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-common-rt', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-loongson-3', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-marvell', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-octeon', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-powerpc64le', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-rpi', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-rt-686-pae', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-rt-amd64', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-rt-arm64', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-rt-armmp', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-20-s390x', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5kc-malta', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp-lpae', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-loongson-3', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-marvell', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-octeon', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-powerpc64le', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rpi', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rt-armmp', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-headers-s390x', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-4kc-malta', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-4kc-malta-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-5kc-malta', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-5kc-malta-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-686-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-686-pae-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-686-pae', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-686', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-amd64-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-amd64', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-arm64-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-arm64', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-armmp', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-armmp-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-armmp-lpae', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-armmp-lpae-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-cloud-amd64-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-cloud-amd64', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-cloud-arm64-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-cloud-arm64', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-loongson-3', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-loongson-3-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-marvell', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-marvell-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-octeon', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-octeon-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-powerpc64le', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-powerpc64le-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-rpi', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-rpi-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-rt-686-pae-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-rt-686-pae', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-rt-amd64-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-rt-amd64', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-rt-arm64-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-rt-arm64', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-rt-armmp', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-rt-armmp-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-s390x', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-20-s390x-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-pae-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-amd64-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-arm64-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-marvell', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-marvell-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-octeon', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-octeon-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-rpi', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-rpi-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-686-pae-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-amd64-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-arm64-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-s390x', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-image-s390x-dbg', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-libc-dev', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-perf', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-source', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'linux-support-5.10.0-20', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-22-armmp-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-22-marvell-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'usbip', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-20-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-20-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-20-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-20-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-20-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-20-s390x-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-22-4kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-22-5kc-malta-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-22-loongson-3-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-22-octeon-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-22-powerpc64le-di', 'reference': '5.10.179-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-22-s390x-di', 'reference': '5.10.179-1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'affs-modules-5.10.0-20-4kc-malta-di / etc');
}
