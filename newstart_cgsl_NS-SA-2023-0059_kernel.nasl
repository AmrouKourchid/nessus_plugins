#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0059. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187321);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/28");

  script_cve_id(
    "CVE-2020-14416",
    "CVE-2022-0330",
    "CVE-2022-0435",
    "CVE-2022-2639",
    "CVE-2022-3542",
    "CVE-2022-3545",
    "CVE-2022-3586",
    "CVE-2022-3594",
    "CVE-2022-40768",
    "CVE-2022-41218",
    "CVE-2022-43750"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : kernel Multiple Vulnerabilities (NS-SA-2023-0059)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has kernel packages installed that are affected by multiple
vulnerabilities:

  - In the Linux kernel before 5.4.16, a race condition in tty->disc_data handling in the slip and slcan line
    discipline could lead to a use-after-free, aka CID-0ace17d56824. This affects drivers/net/slip/slip.c and
    drivers/net/can/slcan.c. (CVE-2020-14416)

  - A random memory access flaw was found in the Linux kernel's GPU i915 kernel driver functionality in the
    way a user may run malicious code on the GPU. This flaw allows a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-0330)

  - A stack overflow flaw was found in the Linux kernel's TIPC protocol functionality in the way a user sends
    a packet with malicious content where the number of domain member nodes is higher than the 64 allowed.
    This flaw allows a remote user to crash the system or possibly escalate their privileges if they have
    access to the TIPC network. (CVE-2022-0435)

  - An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of
    actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size()
    function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This
    flaw allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-2639)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn
    by its CNA. Further investigation showed that it was not a security issue. Notes: none. (CVE-2022-3542)

  - A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability
    is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the
    component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211045 was assigned to this vulnerability. (CVE-2022-3545)

  - A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb
    enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed)
    into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of
    service. (CVE-2022-3586)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function intr_callback of the file drivers/net/usb/r8152.c of the component BPF. The
    manipulation leads to logging of excessive data. The attack can be launched remotely. It is recommended to
    apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211363.
    (CVE-2022-3594)

  - drivers/scsi/stex.c in the Linux kernel through 5.19.9 allows local users to obtain sensitive information
    from kernel memory because stex_queuecommand_lck lacks a memset for the PASSTHRU_CMD case.
    (CVE-2022-40768)

  - In drivers/media/dvb-core/dmxdev.c in the Linux kernel through 5.19.10, there is a use-after-free caused
    by refcount races, affecting dvb_demux_open and dvb_dmxdev_release. (CVE-2022-41218)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2023-0059");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-14416");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-0330");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-0435");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2639");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3542");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3545");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3586");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3594");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-40768");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-41218");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-43750");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0435");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-ipaclones-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-selftests-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-sign-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf");
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
    'bpftool-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-abi-whitelists-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-core-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-cross-headers-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-debug-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-debug-core-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-debug-devel-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-debug-modules-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-debug-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-debug-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-devel-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-headers-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-ipaclones-internal-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-modules-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-selftests-internal-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-sign-keys-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-tools-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-tools-libs-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'kernel-tools-libs-devel-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'perf-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f',
    'python3-perf-4.18.0-193.14.2.el8_2.cgslv6_2.528.24.gdfbf1535f'
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
