#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0061. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187320);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/28");

  script_cve_id(
    "CVE-2020-14381",
    "CVE-2020-16166",
    "CVE-2020-25211",
    "CVE-2020-25643",
    "CVE-2020-28374",
    "CVE-2020-29661",
    "CVE-2021-3347",
    "CVE-2021-3501",
    "CVE-2021-4083",
    "CVE-2021-22555",
    "CVE-2021-27364",
    "CVE-2021-27365",
    "CVE-2021-32399",
    "CVE-2021-33033",
    "CVE-2021-33034",
    "CVE-2021-33909",
    "CVE-2021-37576",
    "CVE-2021-38201"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : kernel Multiple Vulnerabilities (NS-SA-2023-0061)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has kernel packages installed that are affected by multiple
vulnerabilities:

  - A flaw was found in the Linux kernel's futex implementation. This flaw allows a local attacker to corrupt
    system memory or escalate their privileges when creating a futex on a filesystem that is about to be
    unmounted. The highest threat from this vulnerability is to confidentiality, integrity, as well as system
    availability. (CVE-2020-14381)

  - The Linux kernel through 5.7.11 allows remote attackers to make observations that help to obtain sensitive
    information about the internal state of the network RNG, aka CID-f227e3ec3b5c. This is related to
    drivers/char/random.c and kernel/time/timer.c. (CVE-2020-16166)

  - In the Linux kernel through 5.8.7, local attackers able to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in net/netfilter/nf_conntrack_netlink.c, aka CID-1cc5ef91d2ff.
    (CVE-2020-25211)

  - A flaw was found in the HDLC_PPP module of the Linux kernel in versions before 5.9-rc7. Memory corruption
    and a read overflow is caused by improper input validation in the ppp_cp_parse_cr function which can cause
    the system to crash or cause a denial of service. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25643)

  - In drivers/target/target_core_xcopy.c in the Linux kernel before 5.10.7, insufficient identifier checking
    in the LIO SCSI target code can be used by remote attackers to read or write files via directory traversal
    in an XCOPY request, aka CID-2896c93811e3. For example, an attack can occur over a network if the attacker
    has access to one iSCSI LUN. The attacker gains control over file access because I/O operations are
    proxied via an attacker-selected backstore. (CVE-2020-28374)

  - A locking issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free attack against TIOCSPGRP, aka CID-54ffccbf053b.
    (CVE-2020-29661)

  - A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c.
    This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name
    space (CVE-2021-22555)

  - An issue was discovered in the Linux kernel through 5.11.3. drivers/scsi/scsi_transport_iscsi.c is
    adversely affected by the ability of an unprivileged user to craft Netlink messages. (CVE-2021-27364)

  - An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have
    appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can
    send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a
    Netlink message. (CVE-2021-27365)

  - net/bluetooth/hci_request.c in the Linux kernel through 5.12.2 has a race condition for removal of the HCI
    controller. (CVE-2021-32399)

  - The Linux kernel before 5.11.14 has a use-after-free in cipso_v4_genopt in net/ipv4/cipso_ipv4.c because
    the CIPSO and CALIPSO refcounting for the DOI definitions is mishandled, aka CID-ad5d07f4a9cd. This leads
    to writing an arbitrary value. (CVE-2021-33033)

  - In the Linux kernel before 5.12.4, net/bluetooth/hci_event.c has a use-after-free when destroying an
    hci_chan, aka CID-5c4c8c954409. This leads to writing an arbitrary value. (CVE-2021-33034)

  - An issue was discovered in the Linux kernel through 5.10.11. PI futexes have a kernel stack use-after-free
    during fault handling, allowing local users to execute code in the kernel, aka CID-34b1a1ce1458.
    (CVE-2021-3347)

  - fs/seq_file.c in the Linux kernel 3.16 through 5.13.x before 5.13.4 does not properly restrict seq buffer
    allocations, leading to an integer overflow, an Out-of-bounds Write, and escalation to root by an
    unprivileged user, aka CID-8cae8cd89f05. (CVE-2021-33909)

  - A flaw was found in the Linux kernel in versions before 5.12. The value of internal.ndata, in the KVM API,
    is mapped to an array index, which can be updated by a user process at anytime which could lead to an out-
    of-bounds write. The highest threat from this vulnerability is to data integrity and system availability.
    (CVE-2021-3501)

  - arch/powerpc/kvm/book3s_rtas.c in the Linux kernel through 5.13.5 on the powerpc platform allows KVM guest
    OS users to cause host OS memory corruption via rtas_args.nargs, aka CID-f62f3c20647e. (CVE-2021-37576)

  - net/sunrpc/xdr.c in the Linux kernel before 5.13.4 allows remote attackers to cause a denial of service
    (xdr_set_page_base slab-out-of-bounds access) by performing many NFS 4.2 READ_PLUS operations.
    (CVE-2021-38201)

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2023-0061");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-14381");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-16166");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-25211");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-25643");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-28374");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-29661");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-22555");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-27364");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-27365");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-32399");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-33033");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-33034");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3347");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-33909");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3501");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-37576");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-38201");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-4083");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-28374");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter x_tables Heap OOB Write Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-ipaclones-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-selftests-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-sign-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'bpftool-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'bpftool-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-abi-whitelists-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-core-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-cross-headers-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-debug-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-debug-core-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-debug-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-debug-devel-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-debug-modules-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-debug-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-debug-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-debuginfo-common-x86_64-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-devel-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-headers-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-ipaclones-internal-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-modules-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-selftests-internal-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-sign-keys-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-tools-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-tools-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-tools-libs-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'kernel-tools-libs-devel-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'perf-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'perf-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'python3-perf-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786',
    'python3-perf-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.389.32.g3e8996786'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
