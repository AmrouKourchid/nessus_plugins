#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3245. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(169294);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2022-2978",
    "CVE-2022-3521",
    "CVE-2022-3524",
    "CVE-2022-3564",
    "CVE-2022-3565",
    "CVE-2022-3594",
    "CVE-2022-3621",
    "CVE-2022-3628",
    "CVE-2022-3640",
    "CVE-2022-3643",
    "CVE-2022-3646",
    "CVE-2022-3649",
    "CVE-2022-4378",
    "CVE-2022-20369",
    "CVE-2022-29901",
    "CVE-2022-40768",
    "CVE-2022-41849",
    "CVE-2022-41850",
    "CVE-2022-42328",
    "CVE-2022-42329",
    "CVE-2022-42895",
    "CVE-2022-42896",
    "CVE-2022-43750"
  );

  script_name(english:"Debian dla-3245 : hyperv-daemons - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3245 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3245-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Ben Hutchings
    December 21, 2022                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : linux
    Version        : 4.19.269-1
    CVE ID         : CVE-2022-2978 CVE-2022-3521 CVE-2022-3524 CVE-2022-3564
                     CVE-2022-3565 CVE-2022-3594 CVE-2022-3621 CVE-2022-3628
                     CVE-2022-3640 CVE-2022-3643 CVE-2022-3646 CVE-2022-3649
                     CVE-2022-4378 CVE-2022-20369 CVE-2022-29901 CVE-2022-40768
                     CVE-2022-41849 CVE-2022-41850 CVE-2022-42328 CVE-2022-42329
                     CVE-2022-42895 CVE-2022-42896 CVE-2022-43750

    Several vulnerabilities have been discovered in the Linux kernel that
    may lead to a privilege escalation, denial of service or information
    leaks.

    CVE-2022-2978

        butt3rflyh4ck, Hao Sun, and Jiacheng Xu reported a flaw in the
        nilfs2 filesystem driver which can lead to a use-after-free.  A
        local use might be able to exploit this to cause a denial of
        service (crash or memory corruption) or possibly for privilege
        escalation.

    CVE-2022-3521

        The syzbot tool found a race condition in the KCM subsystem
        which could lead to a crash.

        This subsystem is not enabled in Debian's official kernel
        configurations.

    CVE-2022-3524

        The syzbot tool found a race condition in the IPv6 stack which
        could lead to a memory leak.  A local user could exploit this to
        cause a denial of service (memory exhaustion).

    CVE-2022-3564

        A flaw was discovered in the Bluetooh L2CAP subsystem which
        would lead to a use-after-free.  This might be exploitable
        to cause a denial of service (crash or memory corruption) or
        possibly for privilege escalation.

    CVE-2022-3565

        A flaw was discovered in the mISDN driver which would lead to a
        use-after-free.  This might be exploitable to cause a denial of
        service (crash or memory corruption) or possibly for privilege
        escalation.

    CVE-2022-3594

        Andrew Gaul reported that the r8152 Ethernet driver would log
        excessive numbers of messages in response to network errors.  A
        remote attacker could possibly exploit this to cause a denial of
        service (resource exhaustion).

    CVE-2022-3621, CVE-2022-3646

        The syzbot tool found flaws in the nilfs2 filesystem driver which
        can lead to a null pointer dereference or memory leak.  A user
        permitted to mount arbitrary filesystem images could use these to
        cause a denial of service (crash or resource exhaustion).

    CVE-2022-3628

        Dokyung Song, Jisoo Jang, and Minsuk Kang reported a potential
        heap-based buffer overflow in the brcmfmac Wi-Fi driver.  A user
        able to connect a malicious USB device could exploit this to cause
        a denial of service (crash or memory corruption) or possibly for
        privilege escalation.

    CVE-2022-3640

        A flaw was discovered in the Bluetooh L2CAP subsystem which
        would lead to a use-after-free.  This might be exploitable
        to cause a denial of service (crash or memory corruption) or
        possibly for privilege escalation.

    CVE-2022-3643 (XSA-423)

        A flaw was discovered in the Xen network backend driver that would
        result in it generating malformed packet buffers.  If these
        packets were forwarded to certain other network devices, a Xen
        guest could exploit this to cause a denial of service (crash or
        device reset).

    CVE-2022-3649

        The syzbot tool found flaws in the nilfs2 filesystem driver which
        can lead to a use-after-free.  A user permitted to mount arbitrary
        filesystem images could use these to cause a denial of service
        (crash or memory corruption) or possibly for privilege escalation.

    CVE-2022-4378

        Kyle Zeng found a flaw in procfs that would cause a stack-based
        buffer overflow.  A local user permitted to write to a sysctl
        could use this to cause a denial of service (crash or memory
        corruption) or possibly for privilege escalation.

    CVE-2022-20369

        A flaw was found in the v4l2-mem2mem media driver that would lead
        to an out-of-bounds write.  A local user with access to such a
        device could exploit this for privilege escalation.

    CVE-2022-29901

        Johannes Wikner and Kaveh Razavi reported that for Intel
        processors (Intel Core generation 6, 7 and 8), protections against
        speculative branch target injection attacks were insufficient in
        some circumstances, which may allow arbitrary speculative code
        execution under certain microarchitecture-dependent conditions.

        More information can be found at
        https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-
    guidance/advisory-guidance/return-stack-buffer-underflow.html

    CVE-2022-40768

        hdthky reported that the stex SCSI adapter driver did not fully
        initialise a structure that is copied to user-space.  A local user
        with access to such a device could exploit this to leak sensitive
        information.

    CVE-2022-41849

        A race condition was discovered in the smscufx graphics driver,
        which could lead to a use-after-free.  A user able to remove the
        physical device while also accessing its device node could exploit
        this to cause a denial of service (crash or memory corruption) or
        possibly for privilege escalation.

    CVE-2022-41850

        A race condition was discovered in the hid-roccat input driver,
        which could lead to a use-after-free.  A local user able to access
        such a device could exploit this to cause a denial of service
        (crash or memory corruption) or possibly for privilege escalation.

    CVE-2022-42328, CVE-2022-42329 (XSA-424)

        Yang Yingliang reported that the Xen network backend driver did
        not use the proper function to free packet buffers in one case,
        which could lead to a deadlock.  A Xen guest could exploit this to
        cause a denial of service (hang).

    CVE-2022-42895

        Tams Koczka reported a flaw in the Bluetooh L2CAP subsystem
        that would result in reading uninitialised memory.  A nearby
        attacker able to make a Bluetooth connection could exploit
        this to leak sensitive information.

    CVE-2022-42896

        Tams Koczka reported flaws in the Bluetooh L2CAP subsystem that
        can lead to a use-after-free.  A nearby attacker able to make a
        Bluetooth SMP connection could exploit this to cause a denial of
        service (crash or memory corruption) or possibly for remote code
        execution.

    CVE-2022-43750

        The syzbot tool found that the USB monitor (usbmon) driver allowed
        user-space programs to overwrite the driver's data structures.  A
        local user permitted to access a USB monitor device could exploit
        this to cause a denial of service (memory corruption or crash) or
        possibly for privilege escalation.  However, by default only the
        root user can access such devices.

    For Debian 10 buster, these problems have been fixed in version
    4.19.269-1.

    We recommend that you upgrade your linux packages.

    For the detailed security status of linux please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/linux

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

    --
    Ben Hutchings - Debian developer, member of kernel, installer and LTS
    teams
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2978");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3521");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3524");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3564");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3565");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3594");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3621");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3628");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3640");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3643");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3646");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3649");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4378");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-20369");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29901");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-40768");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41849");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41850");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42328");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42329");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42895");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42896");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43750");
  script_set_attribute(attribute:"solution", value:
"Upgrade the hyperv-daemons packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29901");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42896");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/24");

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
    {'release': '10.0', 'prefix': 'hyperv-daemons', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'libbpf-dev', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'libbpf4.19', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'libcpupower-dev', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'libcpupower1', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-arm', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-x86', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-config-4.19', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-cpupower', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-doc-4.19', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-686', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-686-pae', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-amd64', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-arm64', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-armhf', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-all-i386', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-amd64', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-arm64', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-armmp', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-armmp-lpae', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-cloud-amd64', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-common', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-common-rt', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-686-pae', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-amd64', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-arm64', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-26-rt-armmp', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-686-dbg', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-686-pae-dbg', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-amd64-dbg', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-arm64-dbg', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-dbg', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-lpae', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-armmp-lpae-dbg', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-cloud-amd64-dbg', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-686-pae-dbg', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-amd64-dbg', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-arm64-dbg', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-armmp', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-26-rt-armmp-dbg', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-4.19', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-libc-dev', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-perf-4.19', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-source-4.19', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'linux-support-4.19.0-26', 'reference': '4.19.269-1'},
    {'release': '10.0', 'prefix': 'usbip', 'reference': '4.19.269-1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hyperv-daemons / libbpf-dev / libbpf4.19 / libcpupower-dev / etc');
}
