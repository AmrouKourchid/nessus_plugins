#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3102. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164947);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2022-2585",
    "CVE-2022-2586",
    "CVE-2022-2588",
    "CVE-2022-26373",
    "CVE-2022-29900",
    "CVE-2022-29901",
    "CVE-2022-36879",
    "CVE-2022-36946"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/17");

  script_name(english:"Debian dla-3102 : linux-config-5.10 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3102 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3102-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Ben Hutchings
    September 11, 2022                            https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : linux-5.10
    Version        : 5.10.136-1~deb10u3
    CVE ID         : CVE-2022-2585 CVE-2022-2586 CVE-2022-2588 CVE-2022-26373
                     CVE-2022-29900 CVE-2022-29901 CVE-2022-36879 CVE-2022-36946

    Linux 5.10 has been packaged for Debian 10 as linux-5.10.  This
    provides a supported upgrade path for systems that currently use
    kernel packages from the buster-backports suite.

    There is no need to upgrade systems using Linux 4.19, as that kernel
    version will also continue to be supported in the LTS period.

    The apt full-upgrade command will *not* automatically install the
    updated kernel packages.  You should explicitly install one of the
    following metapackages first, as appropriate for your system:

        linux-image-5.10-686
        linux-image-5.10-686-pae
        linux-image-5.10-amd64
        linux-image-5.10-arm64
        linux-image-5.10-armmp
        linux-image-5.10-armmp-lpae
        linux-image-5.10-cloud-amd64
        linux-image-5.10-cloud-arm64
        linux-image-5.10-rt-686-pae
        linux-image-5.10-rt-amd64
        linux-image-5.10-rt-arm64
        linux-image-5.10-rt-armmp

    For example, if the command uname -r currently shows
    5.10.0-0.deb10.16-amd64, you should install linux-image-5.10-amd64.

    This backport does not include the following binary packages:

        bpftool hyperv-daemons libcpupower-dev libcpupower1
        linux-compiler-gcc-8-arm linux-compiler-gcc-8-x86 linux-cpupower
        linux-libc-dev usbip

    Older versions of most of those are built from the linux source
    package in Debian 10.

    Several vulnerabilities have been discovered in the Linux kernel that
    may lead to a privilege escalation, denial of service or information
    leaks.

    CVE-2022-2585

        A use-after-free flaw in the implementation of POSIX CPU timers
        may result in denial of service or in local privilege escalation.

    CVE-2022-2586

        A use-after-free in the Netfilter subsystem may result in local
        privilege escalation for a user with the CAP_NET_ADMIN capability
        in any user or network namespace.

    CVE-2022-2588

        Zhenpeng Lin discovered a use-after-free flaw in the cls_route
        filter implementation which may result in local privilege
        escalation for a user with the CAP_NET_ADMIN capability in any
        user or network namespace.

    CVE-2022-26373

        It was discovered that on certain processors with Intel's Enhanced
        Indirect Branch Restricted Speculation (eIBRS) capabilities there
        are exceptions to the documented properties in some situations,
        which may result in information disclosure.

        Intel's explanation of the issue can be found at
        https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-
    guidance/advisory-guidance/post-barrier-return-stack-buffer-predictions.html

    CVE-2022-29900

        Johannes Wikner and Kaveh Razavi reported that for AMD/Hygon
        processors, mis-trained branch predictions for return instructions
        may allow arbitrary speculative code execution under certain
        microarchitecture-dependent conditions.

        A list of affected AMD CPU types can be found at
        https://www.amd.com/en/corporate/product-security/bulletin/amd-sb-1037

    CVE-2022-29901

        Johannes Wikner and Kaveh Razavi reported that for Intel
        processors (Intel Core generation 6, 7 and 8), protections against
        speculative branch target injection attacks were insufficient in
        some circumstances, which may allow arbitrary speculative code
        execution under certain microarchitecture-dependent conditions.

        More information can be found at
        https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-
    guidance/advisory-guidance/return-stack-buffer-underflow.html

    CVE-2022-36879

        A flaw was discovered in xfrm_expand_policies in the xfrm
        subsystem which can cause a reference count to be dropped twice.

    CVE-2022-36946

        Domingo Dirutigliano and Nicola Guerrera reported a memory
        corruption flaw in the Netfilter subsystem which may result in
        denial of service.

    For Debian 10 buster, these problems have been fixed in version
    5.10.136-1~deb10u3. This update additionally includes many more bug
    fixes from stable updates 5.10.128-5.10.136 inclusive.

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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2585");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2588");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26373");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29900");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29901");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36879");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36946");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux-5.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux-config-5.10 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29900");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2588");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/12");

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
    {'release': '10.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-686', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-686-pae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-cloud-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-cloud-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-common', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-common-rt', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-rt-686-pae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-rt-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-rt-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.24-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-686', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-686-pae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-cloud-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-cloud-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-common', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-common-rt', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-rt-686-pae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-rt-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-rt-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.26-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-686', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-686-pae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-cloud-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-cloud-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-common', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-common-rt', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-rt-686-pae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-rt-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-rt-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.27-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-686', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-686-pae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-cloud-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-cloud-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-common', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-common-rt', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-rt-686-pae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-rt-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-rt-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.28-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-686', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-686-pae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-cloud-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-cloud-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-common', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-common-rt', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-rt-686-pae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-rt-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-rt-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.29-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-686', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-686-pae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-cloud-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-cloud-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-common', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-common-rt', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-rt-686-pae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-rt-amd64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-rt-arm64', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.30-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-signed-template', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-signed-template', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-i386-signed-template', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-686-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-armmp-lpae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-cloud-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-cloud-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.24-rt-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-686-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-armmp-lpae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-cloud-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-cloud-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.26-rt-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-686-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-armmp-lpae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-cloud-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-cloud-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.27-rt-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-686-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-armmp-lpae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-cloud-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-cloud-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.28-rt-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-686-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-armmp-lpae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-cloud-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-cloud-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.29-rt-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-686-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-armmp-lpae', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-armmp-lpae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-cloud-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-cloud-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-686-pae-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-amd64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-arm64-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-armmp', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.30-rt-armmp-dbg', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.24', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.26', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.27', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.28', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.29', 'reference': '5.10.136-1~deb10u3'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.30', 'reference': '5.10.136-1~deb10u3'}
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
    severity   : SECURITY_NOTE,
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
