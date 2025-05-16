#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2714. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153148);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2020-36311",
    "CVE-2021-3609",
    "CVE-2021-33909",
    "CVE-2021-34693"
  );
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"Debian DLA-2714-1 : linux-4.19 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2714 advisory.

    Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation,
    denial of service or information leaks. This update is not yet available for the armhf (ARM EABI hard-
    float) architecture. CVE-2020-36311 A flaw was discovered in the KVM subsystem for AMD CPUs, allowing an
    attacker to cause a denial of service by triggering destruction of a large SEV VM. CVE-2021-3609 Norbert
    Slusarek reported a race condition vulnerability in the CAN BCM networking protocol, allowing a local
    attacker to escalate privileges. CVE-2021-33909 The Qualys Research Labs discovered a size_t-to-int
    conversion vulnerability in the Linux kernel's filesystem layer. An unprivileged local attacker able to
    create, mount, and then delete a deep directory structure whose total path length exceeds 1GB, can take
    advantage of this flaw for privilege escalation. Details can be found in the Qualys advisory at
    https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt
    CVE-2021-34693 Norbert Slusarek discovered an information leak in the CAN BCM networking protocol. A local
    attacker can take advantage of this flaw to obtain sensitive information from kernel stack memory. For
    Debian 9 stretch, these problems have been fixed in version 4.19.194-3~deb9u1. This additionally fixes a
    regression in the previous update (#990072) that affected LXC. We recommend that you upgrade your
    linux-4.19 packages. For the detailed security status of linux-4.19 please refer to its security tracker
    page at: https://security-tracker.debian.org/tracker/linux-4.19 Further information about Debian LTS
    security advisories, how to apply these updates to your system and frequently asked questions can be found
    at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=990072");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux-4.19");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2714");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36311");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33909");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-34693");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3609");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/linux-4.19");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux-4.19 packages.

For Debian 9 stretch, these problems have been fixed in version 4.19.194-3~deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33909");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.11-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.12-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.13-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.14-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.16-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.17-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.11-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.12-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.13-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.14-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.16-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.17-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-0.bpo.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-0.bpo.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-0.bpo.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-0.bpo.13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-0.bpo.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-0.bpo.16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-0.bpo.17");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(9)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'linux-config-4.19', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-doc-4.19', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-all', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-all-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-all-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-all-armel', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-all-armhf', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-all-i386', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-common', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-common-rt', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.10-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-all', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-all-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-all-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-all-armel', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-all-armhf', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-all-i386', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-common', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-common-rt', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.11-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-all', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-all-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-all-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-all-armel', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-all-armhf', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-all-i386', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-common', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-common-rt', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.12-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-all', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-all-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-all-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-all-armel', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-all-armhf', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-all-i386', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-common', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-common-rt', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.13-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-all', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-all-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-all-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-all-armel', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-all-armhf', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-all-i386', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-common', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-common-rt', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.14-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-all', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-all-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-all-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-all-armel', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-all-armhf', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-all-i386', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-common', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-common-rt', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.16-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-all', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-all-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-all-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-all-armel', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-all-armhf', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-all-i386', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-common', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-common-rt', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-headers-4.19.0-0.bpo.17-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-686-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-armmp-lpae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-cloud-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-marvell-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-rpi-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-rt-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-rt-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-rt-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.10-rt-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-686-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-armmp-lpae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-cloud-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-marvell-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-rpi-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-rt-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-rt-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-rt-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.11-rt-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-686-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-armmp-lpae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-cloud-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-marvell-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-rpi-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-rt-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-rt-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-rt-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.12-rt-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-686-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-armmp-lpae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-cloud-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-marvell-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-rpi-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-rt-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-rt-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-rt-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.13-rt-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-686-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-armmp-lpae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-cloud-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-marvell-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-rpi-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-rt-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-rt-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-rt-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.14-rt-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-686-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-armmp-lpae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-cloud-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-marvell-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-rpi-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-rt-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-rt-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-rt-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.16-rt-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-686', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-686-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-armmp-lpae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-armmp-lpae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-cloud-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-cloud-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-marvell', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-marvell-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-rpi', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-rpi-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-rt-686-pae', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-rt-686-pae-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-rt-amd64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-rt-amd64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-rt-arm64', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-rt-arm64-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-rt-armmp', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-image-4.19.0-0.bpo.17-rt-armmp-dbg', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-kbuild-4.19', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-perf-4.19', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-source-4.19', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-support-4.19.0-0.bpo.10', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-support-4.19.0-0.bpo.11', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-support-4.19.0-0.bpo.12', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-support-4.19.0-0.bpo.13', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-support-4.19.0-0.bpo.14', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-support-4.19.0-0.bpo.16', 'reference': '4.19.194-3~deb9u1'},
    {'release': '9.0', 'prefix': 'linux-support-4.19.0-0.bpo.17', 'reference': '4.19.194-3~deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-config-4.19 / linux-doc-4.19 / linux-headers-4.19.0-0.bpo.10-686 / etc');
}
