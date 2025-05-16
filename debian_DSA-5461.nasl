#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5461. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(179043);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2023-3390", "CVE-2023-3610", "CVE-2023-20593");

  script_name(english:"Debian DSA-5461-1 : linux - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5461 advisory.

  - An issue in Zen 2 CPUs, under specific microarchitectural circumstances, may allow an attacker to
    potentially access sensitive information. (CVE-2023-20593)

  - A use-after-free vulnerability was found in the Linux kernel's netfilter subsystem in
    net/netfilter/nf_tables_api.c. Mishandled error handling with NFT_MSG_NEWRULE makes it possible to use a
    dangling pointer in the same transaction causing a use-after-free vulnerability. This flaw allows a local
    attacker with user access to cause a privilege escalation issue. We recommend upgrading past commit
    1240eb93f0616b21c675416516ff3d74798fdc97. (CVE-2023-3390)

  - A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation. Flaw in the error handling of bound chains causes a use-after-free in
    the abort path of NFT_MSG_NEWRULE. The vulnerability requires CAP_NET_ADMIN to be triggered. We recommend
    upgrading past commit 4bedf9eee016286c835e3d8fa981ddece5338795. (CVE-2023-3610)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5461");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-20593");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3390");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3610");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3610");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-23-marvell-di");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-12-s390x");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-12-s390x-dbg");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-23-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-12-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-12-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-14-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-14-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-15-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-15-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-17-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-17-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-19-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-19-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-21-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-21-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-23-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-23-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-12-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-12-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-12-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-12-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-12-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-12-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-14-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-14-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-14-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-14-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-14-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-14-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-15-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-15-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-15-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-15-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-15-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-15-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-17-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-17-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-17-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-17-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-17-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-17-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-19-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-19-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-19-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-19-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-19-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-19-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-21-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-21-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-21-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-21-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-21-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-21-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-23-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-23-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-23-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-23-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-23-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-23-s390x-di");
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
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'bpftool', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'hyperv-daemons', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'libcpupower-dev', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'libcpupower1', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-arm', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-s390', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-x86', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-cpupower', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-doc', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-4kc-malta', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-4kc-malta', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-5kc-malta', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-686', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-686-pae', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-amd64', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-arm64', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-armmp', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-armmp-lpae', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-cloud-amd64', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-cloud-arm64', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-common', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-common-rt', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-loongson-3', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-marvell', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-octeon', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-powerpc64le', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-rpi', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-rt-686-pae', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-rt-amd64', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-rt-arm64', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-rt-armmp', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-12-s390x', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-5kc-malta', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp-lpae', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-loongson-3', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-marvell', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-octeon', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-powerpc64le', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-rpi', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-rt-armmp', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-headers-s390x', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-4kc-malta', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-4kc-malta-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-5kc-malta', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-5kc-malta-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-686-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-686-pae-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-686-pae', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-686', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-amd64-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-amd64', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-arm64-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-arm64', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-armmp', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-armmp-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-armmp-lpae', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-armmp-lpae-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-cloud-amd64-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-cloud-amd64', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-cloud-arm64-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-cloud-arm64', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-loongson-3', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-loongson-3-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-marvell', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-marvell-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-octeon', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-octeon-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-powerpc64le', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-powerpc64le-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-rpi', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-rpi-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-rt-686-pae-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-rt-686-pae', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-rt-amd64-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-rt-amd64', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-rt-arm64-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-rt-arm64', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-rt-armmp', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-rt-armmp-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-s390x', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-12-s390x-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-686-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-686-pae-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-armmp', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-amd64-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-arm64-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-marvell', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-marvell-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-octeon', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-octeon-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-rpi', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-rpi-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-rt-686-pae-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-rt-amd64-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-rt-arm64-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-s390x', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-image-s390x-dbg', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-libc-dev', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-perf', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-source', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'linux-support-5.10.0-12', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-12-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-12-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-14-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-14-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-15-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-15-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-17-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-17-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-19-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-19-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-21-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-21-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-23-armmp-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-23-marvell-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'usbip', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-12-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-12-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-12-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-12-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-12-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-12-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-14-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-14-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-14-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-14-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-14-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-14-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-15-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-15-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-15-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-15-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-15-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-15-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-17-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-17-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-17-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-17-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-17-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-17-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-19-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-19-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-19-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-19-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-19-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-19-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-21-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-21-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-21-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-21-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-21-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-21-s390x-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-23-4kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-23-5kc-malta-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-23-loongson-3-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-23-octeon-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-23-powerpc64le-di', 'reference': '5.10.179-3'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-23-s390x-di', 'reference': '5.10.179-3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'affs-modules-5.10.0-12-4kc-malta-di / etc');
}
