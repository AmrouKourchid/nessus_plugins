#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3131. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165623);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2021-4159",
    "CVE-2021-33655",
    "CVE-2021-33656",
    "CVE-2022-1462",
    "CVE-2022-1679",
    "CVE-2022-2153",
    "CVE-2022-2318",
    "CVE-2022-2586",
    "CVE-2022-2588",
    "CVE-2022-2663",
    "CVE-2022-3028",
    "CVE-2022-26365",
    "CVE-2022-26373",
    "CVE-2022-33740",
    "CVE-2022-33741",
    "CVE-2022-33742",
    "CVE-2022-33744",
    "CVE-2022-36879",
    "CVE-2022-36946",
    "CVE-2022-39188",
    "CVE-2022-39842",
    "CVE-2022-40307"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/17");

  script_name(english:"Debian dla-3131 : hyperv-daemons - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3131 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3131-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Ben Hutchings
    October 01, 2022                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : linux
    Version        : 4.19.260-1
    CVE ID         : CVE-2021-4159 CVE-2021-33655 CVE-2021-33656 CVE-2022-1462
                     CVE-2022-1679 CVE-2022-2153 CVE-2022-2318 CVE-2022-2586
                     CVE-2022-2588 CVE-2022-2663 CVE-2022-3028 CVE-2022-26365
                     CVE-2022-26373 CVE-2022-33740 CVE-2022-33741 CVE-2022-33742
                     CVE-2022-33744 CVE-2022-36879 CVE-2022-36946 CVE-2022-39188
                     CVE-2022-39842 CVE-2022-40307
    Debian Bug     : 1018752

    Several vulnerabilities have been discovered in the Linux kernel that
    may lead to privilege escalation, denial of service or information
    leaks.

    CVE-2021-4159

        A flaw was found in the eBPF verifier which could lead to an
        out-of-bounds read.  If unprivileged use of eBPF is enabled, this
        could leak sensitive information.  This was already disabled by
        default, which would fully mitigate the vulnerability.

    CVE-2021-33655

        A user with access to a framebuffer console device could cause a
        memory out-of-bounds write via the FBIOPUT_VSCREENINFO ioctl.

    CVE-2021-33656

        A user with access to a framebuffer console device could cause a
        memory out-of-bounds write via some font setting ioctls.  These
        obsolete ioctls have been removed.

    CVE-2022-1462

         reported a race condition in the pty (pseudo-terminal)
        subsystem that can lead to a slab out-of-bounds write.  A local
        user could exploit this to cause a denial of service (crash or
        memory corruption) or possibly for privilege escalation.

    CVE-2022-1679

        The syzbot tool found a race condition in the ath9k_htc driver
        which can lead to a use-after-free.  This might be exploitable to
        cause a denial service (crash or memory corruption) or possibly
        for privilege escalation.

    CVE-2022-2153

        kangel reported a flaw in the KVM implementation for x86
        processors which could lead to a null pointer dereference. A local
        user permitted to access /dev/kvm could exploit this to cause a
        denial of service (crash).

    CVE-2022-2318

        A use-after-free in the Amateur Radio X.25 PLP (Rose) support may
        result in denial of service.

    CVE-2022-2586

        A use-after-free in the Netfilter subsystem may result in local
        privilege escalation for a user with the CAP_NET_ADMIN capability
        in any user or network namespace.

    CVE-2022-2588

        Zhenpeng Lin discovered a use-after-free flaw in the cls_route
        filter implementation which may result in local privilege
        escalation for a user with the CAP_NET_ADMIN capability in any
        user or network namespace.

    CVE-2022-2663

        David Leadbeater reported flaws in the nf_conntrack_irc
        connection-tracking protocol module.  When this module is enabled
        on a firewall, an external user on the same IRC network as an
        internal user could exploit its lax parsing to open arbitrary TCP
        ports in the firewall, to reveal their public IP address, or to
        block their IRC connection at the firewall.

    CVE-2022-3028

        Abhishek Shah reported a race condition in the AF_KEY subsystem,
        which could lead to an out-of-bounds write or read.  A local user
        could exploit this to cause a denial of service (crash or memory
        corruption), to obtain sensitive information, or possibly for
        privilege escalation.

    CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742

        Roger Pau Monne discovered that Xen block and network PV device
        frontends don't zero out memory regions before sharing them with
        the backend, which may result in information disclosure.
        Additionally it was discovered that the granularity of the grant
        table doesn't permit sharing less than a 4k page, which may also
        result in information disclosure.

    CVE-2022-26373

        It was discovered that on certain processors with Intel's Enhanced
        Indirect Branch Restricted Speculation (eIBRS) capabilities there
        are exceptions to the documented properties in some situations,
        which may result in information disclosure.

        Intel's explanation of the issue can be found at
        https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-
    guidance/advisory-guidance/post-barrier-return-stack-buffer-predictions.html

    CVE-2022-33744

        Oleksandr Tyshchenko discovered that ARM Xen guests can cause a
        denial of service to the Dom0 via paravirtual devices.

    CVE-2022-36879

        A flaw was discovered in xfrm_expand_policies in the xfrm
        subsystem which can cause a reference count to be dropped twice.

    CVE-2022-36946

        Domingo Dirutigliano and Nicola Guerrera reported a memory
        corruption flaw in the Netfilter subsystem which may result in
        denial of service.

    CVE-2022-39188

        Jann Horn reported a race condition in the kernel's handling of
        unmapping of certain memory ranges.  When a driver created a
        memory mapping with the VM_PFNMAP flag, which many GPU drivers do,
        the memory mapping could be removed and freed before it was
        flushed from the CPU TLBs.  This could result in a page use-after-
        free.  A local user with access to such a device could exploit
        this to cause a denial of service (crash or memory corruption) or
        possibly for privilege escalation.

    CVE-2022-39842

        An integer overflow was discovered in the pxa3xx-gcu video driver
        which could lead to a heap out-of-bounds write.

        This driver is not enabled in Debian's official kernel
        configurations.

    CVE-2022-40307

        A race condition was discovered in the EFI capsule-loader driver,
        which could lead to use-after-free.  A local user permitted to
        access this device (/dev/efi_capsule_loader) could exploit this to
        cause a denial of service (crash or memory corruption) or possibly
        for privilege escalation.  However, this device is normally only
        accessible by the root user.

    For Debian 10 buster, these problems have been fixed in version
    4.19.260-1.

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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33655");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33656");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4159");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1462");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1679");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2153");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2318");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2588");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26365");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26373");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2663");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3028");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33740");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33741");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33742");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33744");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36879");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36946");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39188");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39842");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-40307");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the hyperv-daemons packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1679");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2588");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/02");

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
    {'release': '10.0', 'prefix': 'hyperv-daemons', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'libbpf-dev', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'libbpf4.19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'libcpupower-dev', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'libcpupower1', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-arm', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-x86', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-config-4.19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-cpupower', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-doc-4.19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-686', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-686-pae', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-amd64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-arm64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-armhf', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-i386', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-amd64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-arm64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-armmp', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-armmp-lpae', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-cloud-amd64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-common', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-common-rt', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-686-pae', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-amd64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-arm64', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-armmp', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-686-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-686-pae-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-amd64-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-arm64-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-lpae', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-lpae-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-cloud-amd64-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-686-pae-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-amd64-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-arm64-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-armmp', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-armmp-dbg', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-4.19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-libc-dev', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-perf-4.19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-source-4.19', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'linux-support-4.19.0-26', 'reference': '4.19.260-1'},
    {'release': '10.0', 'prefix': 'usbip', 'reference': '4.19.260-1'}
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
