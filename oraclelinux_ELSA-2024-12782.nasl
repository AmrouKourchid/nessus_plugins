#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12782.
##

include('compat.inc');

if (description)
{
  script_id(209005);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/14");

  script_cve_id(
    "CVE-2024-27397",
    "CVE-2024-41012",
    "CVE-2024-41015",
    "CVE-2024-41017",
    "CVE-2024-41020",
    "CVE-2024-41042",
    "CVE-2024-41059",
    "CVE-2024-41063",
    "CVE-2024-41064",
    "CVE-2024-41065",
    "CVE-2024-41068",
    "CVE-2024-41070",
    "CVE-2024-41072",
    "CVE-2024-41081",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-42131",
    "CVE-2024-42259",
    "CVE-2024-42265",
    "CVE-2024-42271",
    "CVE-2024-42276",
    "CVE-2024-42280",
    "CVE-2024-42281",
    "CVE-2024-42283",
    "CVE-2024-42284",
    "CVE-2024-42285",
    "CVE-2024-42286",
    "CVE-2024-42287",
    "CVE-2024-42288",
    "CVE-2024-42289",
    "CVE-2024-42290",
    "CVE-2024-42292",
    "CVE-2024-42295",
    "CVE-2024-42297",
    "CVE-2024-42301",
    "CVE-2024-42304",
    "CVE-2024-42305",
    "CVE-2024-42306",
    "CVE-2024-42308",
    "CVE-2024-42309",
    "CVE-2024-42310",
    "CVE-2024-42311",
    "CVE-2024-42313",
    "CVE-2024-43829",
    "CVE-2024-43830",
    "CVE-2024-43839",
    "CVE-2024-43841",
    "CVE-2024-43846",
    "CVE-2024-43856",
    "CVE-2024-43858",
    "CVE-2024-43860",
    "CVE-2024-43861",
    "CVE-2024-43867",
    "CVE-2024-43871",
    "CVE-2024-43879",
    "CVE-2024-43880",
    "CVE-2024-43882",
    "CVE-2024-43883",
    "CVE-2024-43890",
    "CVE-2024-43893",
    "CVE-2024-43894",
    "CVE-2024-43908",
    "CVE-2024-43914",
    "CVE-2024-44935",
    "CVE-2024-44944",
    "CVE-2024-44948",
    "CVE-2024-44954",
    "CVE-2024-44960",
    "CVE-2024-44965",
    "CVE-2024-44968",
    "CVE-2024-44969",
    "CVE-2024-46738"
  );

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel-container (ELSA-2024-12782)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2024-12782 advisory.

    - VMCI: Fix use-after-free when removing resource in vmci_resource_remove() (David Fernandez Gonzalez)
    [Orabug: 37037205] {CVE-2024-46738}
    - exec: Fix ToCToU between perm check and set-uid/gid usage (Kees Cook) [Orabug: 36984017]
    {CVE-2024-43882}
    - drm/i915/gem: Fix Virtual Memory mapping boundaries calculation (Andi Shyti) [Orabug: 36953969]
    {CVE-2024-42259}
    - netfilter: nf_tables: prefer nft_chain_validate (Florian Westphal) [Orabug: 36896846] {CVE-2024-41042}
    - netfilter: nf_tables: use timestamp to check for set element timeout (Pablo Neira Ayuso) [Orabug:
    36630432] {CVE-2024-27397}
    - x86/mtrr: Check if fixed MTRRs exist before saving them (Andi Kleen) [Orabug: 37028936] {CVE-2024-44948}
    - tracing: Fix overflow in get_free_elt() (Tze-nan Wu) [Orabug: 36992998] {CVE-2024-43890}
    - serial: core: check uartclk for zero to avoid divide by zero (George Kennedy) [Orabug: 36993009]
    {CVE-2024-43893}
    - tick/broadcast: Move per CPU pointer access into the atomic section (Thomas Gleixner) [Orabug: 37036032]
    {CVE-2024-44968}
    - usb: gadget: core: Check for unset descriptor (Chris Wulff) [Orabug: 37028988] {CVE-2024-44960}
    - usb: vhci-hcd: Do not drop references before new references are gained (Oliver Neukum) [Orabug:
    36992971] {CVE-2024-43883}
    - ALSA: line6: Fix racy access to midibuf (Takashi Iwai) [Orabug: 37028957] {CVE-2024-44954}
    - drm/client: fix null pointer dereference in drm_client_modeset_probe (Ma Ke) [Orabug: 36993014]
    {CVE-2024-43894}
    - s390/sclp: Prevent release of buffer in I/O (Peter Oberparleiter) [Orabug: 37029020] {CVE-2024-44969}
    - drm/amdgpu: Fix the null pointer dereference to ras_manager (Ma Jun) [Orabug: 36993084] {CVE-2024-43908}
    - md/raid5: avoid BUG_ON() while continue reshape after reassembling (Yu Kuai) [Orabug: 36993127]
    {CVE-2024-43914}
    - net: usb: qmi_wwan: fix memory leak for not ip packets (Daniele Palmas) [Orabug: 36983959]
    {CVE-2024-43861}
    - sctp: Fix null-ptr-deref in reuseport_add_sock(). (Kuniyuki Iwashima) [Orabug: 36993147]
    {CVE-2024-44935}
    - x86/mm: Fix pti_clone_pgtable() alignment assumption (Peter Zijlstra) [Orabug: 37029012]
    {CVE-2024-44965}
    - protect the fetch of ->fd[fd] in do_dup2() from mispredictions (Al Viro) [Orabug: 36963808]
    {CVE-2024-42265}
    - net/iucv: fix use after free in iucv_sock_close() (Alexandra Winter) [Orabug: 36964006] {CVE-2024-42271}
    - drm/nouveau: prime: fix refcount underflow (Danilo Krummrich) [Orabug: 36983979] {CVE-2024-43867}
    - remoteproc: imx_rproc: Skip over memory region when node value is NULL (Aleksandr Mishin) [Orabug:
    36964537] {CVE-2024-43860}
    - irqchip/imx-irqsteer: Handle runtime power management correctly (Shenwei Wang) [Orabug: 36964085]
    {CVE-2024-42290}
    - devres: Fix memory leakage caused by driver API devm_free_percpu() (Zijun Hu) [Orabug: 36983991]
    {CVE-2024-43871}
    - dev/parport: fix the array out-of-bounds risk (tuhaowen) [Orabug: 36964223] {CVE-2024-42301}
    - mm: avoid overflows in dirty throttling logic (Jan Kara) [Orabug: 36897803] {CVE-2024-42131}
    - nvme-pci: add missing condition check for existence of mapped data (Leon Romanovsky) [Orabug: 36964022]
    {CVE-2024-42276}
    - mISDN: Fix a use after free in hfcmulti_tx() (Dan Carpenter) [Orabug: 36964032] {CVE-2024-42280}
    - bpf: Fix a segment issue when downgrading gso_size (Fred Li) [Orabug: 36964038] {CVE-2024-42281}
    - net: nexthop: Initialize all fields in dumped nexthops (Petr Machata) [Orabug: 36964044]
    {CVE-2024-42283}
    - tipc: Return non-zero value from tipc_udp_addr2str() on error (Shigeru Yoshida) [Orabug: 36964047]
    {CVE-2024-42284}
    - dma: fix call order in dmam_free_coherent (Lance Richardson) [Orabug: 36964523] {CVE-2024-43856}
    - jfs: Fix array-index-out-of-bounds in diFree (Jeongjun Park) [Orabug: 36964530] {CVE-2024-43858}
    - nilfs2: handle inconsistent state in nilfs_btnode_create_block() (Ryusuke Konishi) [Orabug: 36964203]
    {CVE-2024-42295}
    - RDMA/iwcm: Fix a use-after-free related to destroying CM IDs (Bart Van Assche) [Orabug: 36964054]
    {CVE-2024-42285}
    - scsi: qla2xxx: validate nvme_local_port correctly (Nilesh Javali) [Orabug: 36964059] {CVE-2024-42286}
    - scsi: qla2xxx: Complete command early within lock (Shreyas Deodhar) [Orabug: 36964065] {CVE-2024-42287}
    - scsi: qla2xxx: Fix for possible memory corruption (Shreyas Deodhar) [Orabug: 36964070] {CVE-2024-42288}
    - scsi: qla2xxx: During vport delete send async logout explicitly (Manish Rangankar) [Orabug: 36964080]
    {CVE-2024-42289}
    - kobject_uevent: Fix OOB access within zap_modalias_env() (Zijun Hu) [Orabug: 36964092] {CVE-2024-42292}
    - f2fs: fix to don't dirty inode for readonly filesystem (Chao Yu) [Orabug: 36964213] {CVE-2024-42297}
    - ext4: make sure the first directory block is not a hole (Baokun Li) [Orabug: 36964232] {CVE-2024-42304}
    - ext4: check dot and dotdot of dx_root before making dir indexed (Baokun Li) [Orabug: 36964237]
    {CVE-2024-42305}
    - udf: Avoid using corrupted block bitmap buffer (Jan Kara) [Orabug: 36964242] {CVE-2024-42306}
    - drm/amd/display: Check for NULL pointer (Sung Joon Kim) [Orabug: 36964247] {CVE-2024-42308}
    - drm/gma500: fix null pointer dereference in psb_intel_lvds_get_modes (Ma Ke) [Orabug: 36964253]
    {CVE-2024-42309}
    - drm/gma500: fix null pointer dereference in cdv_intel_lvds_get_modes (Ma Ke) [Orabug: 36964260]
    {CVE-2024-42310}
    - hfs: fix to initialize fields of hfs_inode_info after hfs_alloc_inode() (Chao Yu) [Orabug: 36964265]
    {CVE-2024-42311}
    - media: venus: fix use after free in vdec_close (Dikshita Agarwal) [Orabug: 36964275] {CVE-2024-42313}
    - netfilter: ctnetlink: use helper function to calculate expect ID (Pablo Neira Ayuso) [Orabug: 37013755]
    {CVE-2024-44944}
    - drm/qxl: Add check for drm_cvt_mode (Chen Ni) [Orabug: 36964456] {CVE-2024-43829}
    - leds: trigger: Unregister sysfs attributes before calling deactivate() (Hans de Goede) [Orabug:
    36964459] {CVE-2024-43830}
    - bna: adjust 'name' buf size of bna_tcb and bna_ccb structures (Alexey Kodanev) [Orabug: 36964480]
    {CVE-2024-43839}
    - wifi: virt_wifi: avoid reporting connection success with wrong SSID (En-Wei Wu) [Orabug: 36964487]
    {CVE-2024-43841}
    - wifi: cfg80211: handle 2x996 RU allocation in cfg80211_calculate_bitrate_he() (Baochen Qiang) [Orabug:
    36984010] {CVE-2024-43879}
    - mlxsw: spectrum_acl_erp: Fix object nesting warning (Ido Schimmel) [Orabug: 36984013] {CVE-2024-43880}
    - lib: objagg: Fix general protection fault (Ido Schimmel) [Orabug: 36964495] {CVE-2024-43846}
    - tap: add missing verification for short frame (Si-Wei Liu)   [Orabug: 36660755] {CVE-2024-41090}
    - tun: add missing verification for short frame (Dongli Zhang)   [Orabug: 36660755] {CVE-2024-41091}
    - filelock: Fix fcntl/close race recovery compat path (Jann Horn) [Orabug: 36896789] {CVE-2024-41020}
    {CVE-2024-41012}
    - jfs: don't walk off the end of ealist (lei lu) [Orabug: 36891667] {CVE-2024-41017}
    - ocfs2: add bounds checking to ocfs2_check_dir_entry() (lei lu) [Orabug: 36891655] {CVE-2024-41015}
    - hfsplus: fix uninit-value in copy_name (Edward Adam Davis) [Orabug: 36896969] {CVE-2024-41059}
    - Bluetooth: hci_core: cancel all works upon hci_unregister_dev() (Tetsuo Handa) [Orabug: 36896994]
    {CVE-2024-41063}
    - powerpc/eeh: avoid possible crash when edev->pdev changes (Ganesh Goudar) [Orabug: 36897003]
    {CVE-2024-41064}
    - powerpc/pseries: Whitelist dtl slub object for copying to userspace (Anjali K) [Orabug: 36897009]
    {CVE-2024-41065}
    - s390/sclp: Fix sclp_init() cleanup on failure (Heiko Carstens) [Orabug: 36897032] {CVE-2024-41068}
    - KVM: PPC: Book3S HV: Prevent UAF in kvm_spapr_tce_attach_iommu_group() (Michael Ellerman) [Orabug:
    36897048] {CVE-2024-41070}
    - wifi: cfg80211: wext: add extra SIOCSIWSCAN data check (Dmitry Antipov) [Orabug: 36897312]
    {CVE-2024-41072}
    - ila: block BH in ila_output() (Eric Dumazet) [Orabug: 36897360] {CVE-2024-41081}
    - filelock: Remove locks reliably when fcntl/close race is detected (Jann Horn) [Orabug: 36874758]
    {CVE-2024-41012} {CVE-2024-41020}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12782.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek-container and / or kernel-uek-container-debug packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46738");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:10:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^(7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7 / 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.4.17-2136.336.5.1.el7uek', '5.4.17-2136.336.5.1.el8uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-12782');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.4';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-container-5.4.17-2136.336.5.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.336.5.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'},
    {'reference':'kernel-uek-container-5.4.17-2136.336.5.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.336.5.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek-container / kernel-uek-container-debug');
}
