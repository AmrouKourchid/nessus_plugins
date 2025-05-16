#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0105. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187365);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/27");

  script_cve_id(
    "CVE-2022-3105",
    "CVE-2022-3107",
    "CVE-2022-3108",
    "CVE-2022-3110",
    "CVE-2022-3111",
    "CVE-2022-3115",
    "CVE-2022-3239",
    "CVE-2022-3565",
    "CVE-2022-41858",
    "CVE-2022-42328",
    "CVE-2022-42329",
    "CVE-2022-45884",
    "CVE-2022-45885",
    "CVE-2022-45886",
    "CVE-2022-45887",
    "CVE-2022-45919",
    "CVE-2022-45934",
    "CVE-2023-23454",
    "CVE-2023-23455"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : kernel Multiple Vulnerabilities (NS-SA-2023-0105)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has kernel packages installed that are affected by multiple
vulnerabilities:

  - An issue was discovered in the Linux kernel through 5.16-rc6. uapi_finalize in
    drivers/infiniband/core/uverbs_uapi.c lacks check of kmalloc_array(). (CVE-2022-3105)

  - An issue was discovered in the Linux kernel through 5.16-rc6. netvsc_get_ethtool_stats in
    drivers/net/hyperv/netvsc_drv.c lacks check of the return value of kvmalloc_array() and will cause the
    null pointer dereference. (CVE-2022-3107)

  - An issue was discovered in the Linux kernel through 5.16-rc6. kfd_parse_subtype_iolink in
    drivers/gpu/drm/amd/amdkfd/kfd_crat.c lacks check of the return value of kmemdup(). (CVE-2022-3108)

  - An issue was discovered in the Linux kernel through 5.16-rc6. _rtw_init_xmit_priv in
    drivers/staging/r8188eu/core/rtw_xmit.c lacks check of the return value of rtw_alloc_hwxmits() and will
    cause the null pointer dereference. (CVE-2022-3110)

  - An issue was discovered in the Linux kernel through 5.16-rc6. free_charger_irq() in
    drivers/power/supply/wm8350_power.c lacks free of WM8350_IRQ_CHG_FAST_RDY, which is registered in
    wm8350_init_charger(). (CVE-2022-3111)

  - An issue was discovered in the Linux kernel through 5.16-rc6. malidp_crtc_reset in
    drivers/gpu/drm/arm/malidp_crtc.c lacks check of the return value of kzalloc() and will cause the null
    pointer dereference. (CVE-2022-3115)

  - A flaw use after free in the Linux kernel video4linux driver was found in the way user triggers
    em28xx_usb_probe() for the Empia 28xx based TV cards. A local user could use this flaw to crash the system
    or potentially escalate their privileges on the system. (CVE-2022-3239)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function del_timer of the file drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    of this vulnerability is VDB-211088. (CVE-2022-3565)

  - A flaw was found in the Linux kernel. A NULL pointer dereference may occur while a slip driver is in
    progress to detach in sl_tx_timeout in drivers/net/slip/slip.c. This issue could allow an attacker to
    crash the system or leak internal kernel information. (CVE-2022-41858)

  - Guests can trigger deadlock in Linux netback driver T[his CNA information record relates to multiple CVEs;
    the text explains which aspects/vulnerabilities correspond to which CVE.] The patch for XSA-392 introduced
    another issue which might result in a deadlock when trying to free the SKB of a packet dropped due to the
    XSA-392 handling (CVE-2022-42328). Additionally when dropping packages for other reasons the same deadlock
    could occur in case of netpoll being active for the interface the xen-netback driver is connected to
    (CVE-2022-42329). (CVE-2022-42328, CVE-2022-42329)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvbdev.c has a use-
    after-free, related to dvb_register_device dynamically allocating fops. (CVE-2022-45884)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvb_frontend.c has a
    race condition that can cause a use-after-free when a device is disconnected. (CVE-2022-45885)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvb_net.c has a
    .disconnect versus dvb_device_open race condition that leads to a use-after-free. (CVE-2022-45886)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/usb/ttusb-dec/ttusb_dec.c has a
    memory leak because of the lack of a dvb_frontend_detach call. (CVE-2022-45887)

  - An issue was discovered in the Linux kernel through 6.0.10. In drivers/media/dvb-core/dvb_ca_en50221.c, a
    use-after-free can occur is there is a disconnect after an open, because of the lack of a wait_event.
    (CVE-2022-45919)

  - An issue was discovered in the Linux kernel through 6.0.10. l2cap_config_req in net/bluetooth/l2cap_core.c
    has an integer wraparound via L2CAP_CONF_REQ packets. (CVE-2022-45934)

  - cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes
    indicate a TC_ACT_SHOT condition rather than valid classification results). (CVE-2023-23454)

  - atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition
    rather than valid classification results). (CVE-2023-23455)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2023-0105");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3105");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3107");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3108");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3110");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3111");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3115");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3239");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3565");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-41858");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42328");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42329");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45884");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45885");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45886");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45887");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45919");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-45934");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23454");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23455");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/14");
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
    'bpftool-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'bpftool-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-abi-whitelists-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-core-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-cross-headers-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-debug-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-debug-core-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-debug-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-debug-devel-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-debug-modules-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-debug-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-debug-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-debuginfo-common-x86_64-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-devel-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-headers-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-ipaclones-internal-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-modules-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-selftests-internal-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-sign-keys-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-tools-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-tools-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-tools-libs-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'kernel-tools-libs-devel-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'perf-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'perf-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'python3-perf-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5',
    'python3-perf-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.667.ga349278a5'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
