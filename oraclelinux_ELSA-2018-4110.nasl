#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-4110.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109881);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2017-15299",
    "CVE-2017-16532",
    "CVE-2017-16537",
    "CVE-2017-16643",
    "CVE-2017-17448",
    "CVE-2017-17558",
    "CVE-2018-1068",
    "CVE-2018-1093",
    "CVE-2018-5332"
  );

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2018-4110)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2018-4110 advisory.

    - media: imon: Fix null-ptr-deref in imon_probe (Arvind Yadav)  [Orabug: 27208383]  {CVE-2017-16537}
    - Input: gtco - fix potential out-of-bound access (Dmitry Torokhov)  [Orabug: 27215095]  {CVE-2017-16643}
    - usb: usbtest: fix NULL pointer dereference (Alan Stern)  [Orabug: 27602321]  {CVE-2017-16532}
    - netfilter: ebtables: CONFIG_COMPAT: dont trust userland offsets (Florian Westphal)  [Orabug: 27774010]
    {CVE-2018-1068}
    - ext4: add validity checks for bitmap block numbers (Theodore Tso)  [Orabug: 27854370]  {CVE-2018-1093}
    {CVE-2018-1093}
    - USB: core: prevent malicious bNumInterfaces overflow (Alan Stern)  [Orabug: 27898064]  {CVE-2017-17558}
    - RDS: Heap OOB write in rds_message_alloc_sgs() (Mohamed Ghannam)  [Orabug: 27934081]  {CVE-2018-5332}
    - xfs: set format back to extents if xfs_bmap_extents_to_btree (Eric Sandeen)  [Orabug: 27989490]
    {CVE-2018-10323}
    - x86/entry/64: Dont use IST entry for #BP stack (Andy Lutomirski)   {CVE-2018-8897}
    - perf/hwbp: Simplify the perf-hwbp code, fix documentation (Linus Torvalds)  [Orabug: 27947612]
    {CVE-2018-100199}
    - ALSA: usb-audio: Kill stray URB at exiting (Takashi Iwai)  [Orabug: 27148283]  {CVE-2017-16527}
    - uwb: properly check kthread_run return value (Andrey Konovalov)  [Orabug: 27206900]  {CVE-2017-16526}
    - HID: usbhid: fix out-of-bounds bug (Jaejoong Kim)  [Orabug: 27207935]  {CVE-2017-16533}
    - cx231xx-cards: fix NULL-deref on missing association descriptor (Johan Hovold)  [Orabug: 27208080]
    {CVE-2017-16536}
    - net: cdc_ether: fix divide by 0 on bad descriptors (Bjorn Mork)  [Orabug: 27215206]  {CVE-2017-16649}
    - Bluetooth: bnep: bnep_add_connection() should verify that its dealing with l2cap socket (Al Viro)
    [Orabug: 27344787]  {CVE-2017-15868}
    - Bluetooth: hidp: verify l2cap sockets (David Herrmann)  [Orabug: 27344787]  {CVE-2017-15868}
    - ALSA: pcm: prevent UAF in snd_pcm_info (Robb Glasser)  [Orabug: 27344840]  {CVE-2017-0861}
    {CVE-2017-0861}
    - x86/cpufeature: Add X86_FEATURE_IA32_ARCH_CAPS and X86_FEATURE_IBRS_ATT (David Woodhouse)  [Orabug:
    27649498]  {CVE-2017-5715}
    - x86/cpufeatures: Clean up Spectre v2 related CPUID flags (David Woodhouse)  [Orabug: 27649510]
    {CVE-2017-5715}
    - x86/spectre: Now that we expose 'stbibp' make sure it is correct. (Konrad Rzeszutek Wilk)  [Orabug:
    27649631]  {CVE-2017-5715}
    - x86/speculation: Add basic IBPB (Indirect Branch Prediction Barrier) support (KarimAllah Ahmed)
    [Orabug: 27649640]  {CVE-2017-5715}
    - x86: Add STIBP feature enumeration (David Woodhouse)  [Orabug: 27649693]  {CVE-2017-5715}
    - x86/cpu/AMD: Add speculative control support for AMD (Tom Lendacky)  [Orabug: 27649706]  {CVE-2017-5715}
    - x86/spectre_v2: Dont spam the console with these: (Konrad Rzeszutek Wilk)  [Orabug: 27649723]
    {CVE-2017-5715}
    - x86/cpufeature: Blacklist SPEC_CTRL/PRED_CMD on early Spectre v2 microcodes (David Woodhouse)  [Orabug:
    27516441]  {CVE-2017-5715}
    - KEYS: Remove key_type::match in favour of overriding default by match_preparse (Tim Tianyang Chen)
    [Orabug: 25757946]  {CVE-2017-6951}
    - tcp: initialize rcv_mss to TCP_MIN_MSS instead of 0 (Wei Wang)  [Orabug: 26813391]  {CVE-2017-14106}
    - rxrpc: Fix several cases where a padded len isnt checked in ticket decode (David Howells)  [Orabug:
    26880520]  {CVE-2017-7482} {CVE-2017-7482}
    - USB: serial: console: fix use-after-free after failed setup (Johan Hovold)  [Orabug: 27206839]
    {CVE-2017-16525}
    - ALSA: usb-audio: Check out-of-bounds access by corrupted buffer descriptor (Takashi Iwai)  [Orabug:
    27206934]  {CVE-2017-16529}
    - USB: fix out-of-bounds in usb_set_configuration (Greg Kroah-Hartman)  [Orabug: 27207243]
    {CVE-2017-16531}
    - dccp: CVE-2017-8824: use-after-free in DCCP code (Mohamed Ghannam)  [Orabug: 27290308]  {CVE-2017-8824}
    - x86: Use PRED_CMD MSR when ibpb is enabled (Konrad Rzeszutek Wilk)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86/spec: Dont print the Missing arguments for option spectre_v2 (Konrad Rzeszutek Wilk)  [Orabug:
    27369777]  {CVE-2017-5715} {CVE-2017-5753}
    - x86: Move ENABLE_IBRS in the interrupt macro (Konrad Rzeszutek Wilk)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - Add set_ibrs_disabled and set_ibpb_disabled (Konrad Rzeszutek Wilk)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86/boot: Add early cmdline parsing for options with arguments (Tom Lendacky)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - x86, boot: Carve out early cmdline parsing function (Borislav Petkov)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - x86: Fix kABI build breakage (Konrad Rzeszutek Wilk)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86: Add command-line options 'spectre_v2' and 'nospectre_v2' (Kanth Ghatraju)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - x86/mm: Set IBPB upon context switch (Brian Maly)  [Orabug: 27369777]  {CVE-2017-5715} {CVE-2017-5753}
    - x86: Display correct settings for the SPECTRE_V2 bug (Kanth Ghatraju)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - Set CONFIG_GENERIC_CPU_VULNERABILITIES flag (Kanth Ghatraju)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86/cpu: Implement CPU vulnerabilites sysfs functions (Thomas Gleixner)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - sysfs/cpu: Fix typos in vulnerability documentation (David Woodhouse)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - sysfs/cpu: Add vulnerability folder (Thomas Gleixner)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86, cpu: Expand cpufeature facility to include cpu bugs (Borislav Petkov)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - x86/cpufeatures: Add X86_BUG_SPECTRE_V[12] (David Woodhouse)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86/cpufeatures: Add X86_BUG_CPU_MELTDOWN (Kanth Ghatraju)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86/spec: STUFF_RSB _before_ ENABLE_IBRS (Konrad Rzeszutek Wilk)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86: Move STUFF_RSB in to the idt macro (Konrad Rzeszutek Wilk)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86/IBRS/IBPB: Set sysctl_ibrs/ibpb_enabled properly (Boris Ostrovsky)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - x86/IBRS: Make sure we restore MSR_IA32_SPEC_CTRL to a valid value (Boris Ostrovsky)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - x86/spec_ctrl: Add missing 'lfence' when IBRS is not supported (Konrad Rzeszutek Wilk)  [Orabug:
    27369777]  {CVE-2017-5715} {CVE-2017-5753}
    - x86/ia32: Move STUFF_RSB And ENABLE_IBRS (Konrad Rzeszutek Wilk)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86/entry: Stuff RSB for entry to kernel for non-SMEP platform (Tim Chen)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - x86: Use IBRS for firmware update path (David Woodhouse)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86/spec_ctrl: Disable if running as Xen PV guest (Konrad Rzeszutek Wilk)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - x86/microcode: Recheck IBRS features on microcode reload (Tim Chen)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86/idle: Disable IBRS entering idle and enable it on wakeup (Tim Chen)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - x86/spec_ctrl: Add sysctl knobs to enable/disable SPEC_CTRL feature (Tim Chen)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - x86/enter: Use IBRS on syscall and interrupts (Tim Chen)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86/enter: MACROS to set/clear IBRS and set IBPB (Tim Chen)  [Orabug: 27369777]  {CVE-2017-5715}
    {CVE-2017-5753}
    - x86/feature: Detect the x86 IBRS feature to control Speculation (Tim Chen)  [Orabug: 27369777]
    {CVE-2017-5715} {CVE-2017-5753}
    - x86: fix build breakage (Brian Maly)  [Orabug: 27346425]  {CVE-2017-5753}
    - kaiser: rename X86_FEATURE_KAISER to X86_FEATURE_PTI to match upstream (Mike Kravetz)   {CVE-2017-5754}
    - x86/kaiser: Check boottime cmdline params (Mike Kravetz)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/kaiser: Rename and simplify X86_FEATURE_KAISER handling (Borislav Petkov)  [Orabug: 27333761]
    {CVE-2017-5754}
    - KPTI: Report when enabled (Mike Kravetz)  [Orabug: 27333761]  {CVE-2017-5754}
    - PTI: unbreak EFI old_memmap (Jiri Kosina)  [Orabug: 27333761] [Orabug: 27333760]  {CVE-2017-5754}
    - kaiser: Set _PAGE_NX only if supported (Guenter Roeck)  [Orabug: 27333761] [Orabug: 27333760]
    {CVE-2017-5754}
    - KPTI: Rename to PAGE_TABLE_ISOLATION (Kees Cook)  [Orabug: 27333761]  {CVE-2017-5754}
    - kaiser: kaiser_flush_tlb_on_return_to_user() check PCID (Hugh Dickins)  [Orabug: 27333761]
    {CVE-2017-5754}
    - kaiser: asm/tlbflush.h handle noPGE at lower level (Hugh Dickins)  [Orabug: 27333761]  {CVE-2017-5754}
    - kaiser: use ALTERNATIVE instead of x86_cr3_pcid_noflush (Hugh Dickins)  [Orabug: 27333761]
    {CVE-2017-5754}
    - x86/alternatives: add asm ALTERNATIVE macro (Mike Kravetz)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/kaiser: Reenable PARAVIRT, dynamically disable KAISER if PARAVIRT (Borislav Petkov)  [Orabug:
    27333761]  {CVE-2017-5754}
    - kaiser: add 'nokaiser' boot option, using ALTERNATIVE (Hugh Dickins)  [Orabug: 27333761]
    {CVE-2017-5754}
    - x86-32: Fix boot with CONFIG_X86_INVD_BUG (Andy Lutomirski)  [Orabug: 27333761]  {CVE-2017-5754}
    - kaiser: alloc_ldt_struct() use get_zeroed_page() (Hugh Dickins)  [Orabug: 27333761]  {CVE-2017-5754}
    - kaiser: user_map __kprobes_text too (Hugh Dickins)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/mm/kaiser: re-enable vsyscalls (Andrea Arcangeli)  [Orabug: 27333761]  {CVE-2017-5754}
    - KAISER: Kernel Address Isolation (Hugh Dickins)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/mm: fix bad backport to disable PCID on Xen (Borislav Petkov)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/mm/64: Fix reboot interaction with CR4.PCIDE (Andy Lutomirski)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/mm: Enable CR4.PCIDE on supported systems (Andy Lutomirski)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/mm: Add the 'nopcid' boot option to turn off PCID (Andy Lutomirski)  [Orabug: 27333761]
    {CVE-2017-5754}
    - x86/mm: Disable PCID on 32-bit kernels (Andy Lutomirski)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/mm: Remove the UP asm/tlbflush.h code, always use the (formerly) SMP code (Andy Lutomirski)
    [Orabug: 27333761]  {CVE-2017-5754}
    - sched/core: Idle_task_exit() shouldnt use switch_mm_irqs_off() (Andy Lutomirski)  [Orabug: 27333761]
    {CVE-2017-5754}
    - x86/mm, sched/core: Turn off IRQs in switch_mm() (Andy Lutomirski)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/mm, sched/core: Uninline switch_mm() (Andy Lutomirski)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/mm: Build arch/x86/mm/tlb.c even on !SMP (Andy Lutomirski)  [Orabug: 27333761]  {CVE-2017-5754}
    - sched/core: Add switch_mm_irqs_off() and use it in the scheduler (Andy Lutomirski)  [Orabug: 27333761]
    {CVE-2017-5754}
    - mm/mmu_context, sched/core: Fix mmu_context.h assumption (Ingo Molnar)  [Orabug: 27333761]
    {CVE-2017-5754}
    - x86/mm: If INVPCID is available, use it to flush global mappings (Andy Lutomirski)  [Orabug: 27333761]
    {CVE-2017-5754}
    - x86/mm: Add a 'noinvpcid' boot option to turn off INVPCID (Andy Lutomirski)  [Orabug: 27333761]
    {CVE-2017-5754}
    - x86/mm: Fix INVPCID asm constraint (Borislav Petkov)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/mm: Add INVPCID helpers (Andy Lutomirski)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86, cpufeature: Add CPU features from Intel document 319433-012A (H. Peter Anvin)  [Orabug: 27333761]
    {CVE-2017-5754}
    - x86/paravirt: Dont patch flush_tlb_single (Thomas Gleixner)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86-64: Map the HPET NX (Andy Lutomirski)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/ldt: Make modify_ldt synchronous (Andy Lutomirski)  [Orabug: 27333761]  {CVE-2017-5754}
    {CVE-2015-5157}
    - x86, cpu: Add cpufeature flag for PCIDs (Arun Thomas)  [Orabug: 27333761]  {CVE-2017-5754}
    - x86/mm: Disable preemption during CR3 read+write (Sebastian Andrzej Siewior)  [Orabug: 27333761]
    {CVE-2017-5754}
    - locking/barriers: fix compile issue (Brian Maly)  [Orabug: 27346425]  {CVE-2017-5753}
    - x86: Add another set of MSR accessor functions (Borislav Petkov)  [Orabug: 27346425]  {CVE-2017-5753}
    - udf: prevent speculative execution (Elena Reshetova)  [Orabug: 27346425]  {CVE-2017-5753}
    - fs: prevent speculative execution (Elena Reshetova)  [Orabug: 27346425]  {CVE-2017-5753}
    - qla2xxx: prevent speculative execution (Elena Reshetova)  [Orabug: 27346425]  {CVE-2017-5753}
    - p54: prevent speculative execution (Elena Reshetova)  [Orabug: 27346425]  {CVE-2017-5753}
    - carl9170: prevent speculative execution (Elena Reshetova)  [Orabug: 27346425]  {CVE-2017-5753}
    - uvcvideo: prevent speculative execution (Elena Reshetova)  [Orabug: 27346425]  {CVE-2017-5753}
    - locking/barriers: introduce new observable speculation barrier (Elena Reshetova)  [Orabug: 27346425]
    {CVE-2017-5753}
    - x86/cpu/AMD: Remove now unused definition of MFENCE_RDTSC feature (Elena Reshetova)  [Orabug: 27346425]
    {CVE-2017-5753}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-4110.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5332");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5 / 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.39-400.299.1.el5uek', '2.6.39-400.299.1.el6uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-4110');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '2.6';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-2.6.39-400.299.1.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.39'},
    {'reference':'kernel-uek-debug-2.6.39-400.299.1.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.39'},
    {'reference':'kernel-uek-debug-devel-2.6.39-400.299.1.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.39'},
    {'reference':'kernel-uek-devel-2.6.39-400.299.1.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.39'},
    {'reference':'kernel-uek-doc-2.6.39-400.299.1.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.39'},
    {'reference':'kernel-uek-firmware-2.6.39-400.299.1.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.39'},
    {'reference':'kernel-uek-2.6.39-400.299.1.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.39'},
    {'reference':'kernel-uek-debug-2.6.39-400.299.1.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.39'},
    {'reference':'kernel-uek-debug-devel-2.6.39-400.299.1.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.39'},
    {'reference':'kernel-uek-devel-2.6.39-400.299.1.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.39'},
    {'reference':'kernel-uek-doc-2.6.39-400.299.1.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.39'},
    {'reference':'kernel-uek-firmware-2.6.39-400.299.1.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.39'},
    {'reference':'kernel-uek-2.6.39-400.299.1.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.39'},
    {'reference':'kernel-uek-debug-2.6.39-400.299.1.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.39'},
    {'reference':'kernel-uek-debug-devel-2.6.39-400.299.1.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.39'},
    {'reference':'kernel-uek-devel-2.6.39-400.299.1.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.39'},
    {'reference':'kernel-uek-doc-2.6.39-400.299.1.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.39'},
    {'reference':'kernel-uek-firmware-2.6.39-400.299.1.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.39'},
    {'reference':'kernel-uek-2.6.39-400.299.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.39'},
    {'reference':'kernel-uek-debug-2.6.39-400.299.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.39'},
    {'reference':'kernel-uek-debug-devel-2.6.39-400.299.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.39'},
    {'reference':'kernel-uek-devel-2.6.39-400.299.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.39'},
    {'reference':'kernel-uek-doc-2.6.39-400.299.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.39'},
    {'reference':'kernel-uek-firmware-2.6.39-400.299.1.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.39'}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
