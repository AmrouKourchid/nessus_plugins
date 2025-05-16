#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-2394.
##

include('compat.inc');

if (description)
{
  script_id(195036);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2020-26555",
    "CVE-2022-0480",
    "CVE-2022-38096",
    "CVE-2022-45934",
    "CVE-2023-3567",
    "CVE-2023-4133",
    "CVE-2023-6040",
    "CVE-2023-6121",
    "CVE-2023-6176",
    "CVE-2023-6531",
    "CVE-2023-6546",
    "CVE-2023-6622",
    "CVE-2023-6915",
    "CVE-2023-6931",
    "CVE-2023-6932",
    "CVE-2023-24023",
    "CVE-2023-25775",
    "CVE-2023-28464",
    "CVE-2023-28866",
    "CVE-2023-31083",
    "CVE-2023-37453",
    "CVE-2023-39189",
    "CVE-2023-39193",
    "CVE-2023-39194",
    "CVE-2023-39198",
    "CVE-2023-42754",
    "CVE-2023-42756",
    "CVE-2023-45863",
    "CVE-2023-46862",
    "CVE-2023-51043",
    "CVE-2023-51779",
    "CVE-2023-51780",
    "CVE-2023-52434",
    "CVE-2023-52448",
    "CVE-2023-52476",
    "CVE-2023-52489",
    "CVE-2023-52522",
    "CVE-2023-52529",
    "CVE-2023-52574",
    "CVE-2023-52578",
    "CVE-2023-52580",
    "CVE-2023-52581",
    "CVE-2023-52610",
    "CVE-2023-52620",
    "CVE-2024-0565",
    "CVE-2024-0841",
    "CVE-2024-1085",
    "CVE-2024-1086",
    "CVE-2024-26582",
    "CVE-2024-26583",
    "CVE-2024-26584",
    "CVE-2024-26585",
    "CVE-2024-26586",
    "CVE-2024-26593",
    "CVE-2024-26602",
    "CVE-2024-26609",
    "CVE-2024-26633"
  );
  script_xref(name:"IAVA", value:"2023-A-0638-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/20");

  script_name(english:"Oracle Linux 9 : kernel (ELSA-2024-2394)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-2394 advisory.

    - mm/sparsemem: fix race in accessing memory_section->usage (Waiman Long) [RHEL-28877 RHEL-28878]
    {CVE-2023-52489}
    - mlxsw: spectrum_acl_tcam: Fix stack corruption (Ivan Vecera) [RHEL-26463 RHEL-26465] {CVE-2024-26586}
    - i2c: i801: Fix block process call transactions (David Arcari) [RHEL-26479 RHEL-26481] {CVE-2024-26593}
    - sched/membarrier: reduce the ability to hammer on sys_membarrier (Wander Lairson Costa) [RHEL-23428
    RHEL-23429] {CVE-2024-26602}
    - tls: fix use-after-free on failed backlog decryption (Sabrina Dubroca) [RHEL-26410 RHEL-26415]
    {CVE-2024-26584}
    - tls: separate no-async decryption request handling from async (Sabrina Dubroca) [RHEL-26410 RHEL-26415]
    {CVE-2024-26584}
    - tls: decrement decrypt_pending if no async completion will be called (Sabrina Dubroca) [RHEL-26416
    RHEL-26421] {CVE-2024-26583}
    - net: tls: fix use-after-free with partial reads and async decrypt (Sabrina Dubroca) [RHEL-26398
    RHEL-26401] {CVE-2024-26582}
    - net: tls: handle backlogging of crypto requests (Sabrina Dubroca) [RHEL-26410 RHEL-26415]
    {CVE-2024-26584}
    - tls: fix race between tx work scheduling and socket close (Sabrina Dubroca) [RHEL-26361 RHEL-26363]
    {CVE-2024-26585}
    - tls: fix race between async notify and socket close (Sabrina Dubroca) [RHEL-26416 RHEL-26421]
    {CVE-2024-26583}
    - net: tls: factor out tls_*crypt_async_wait() (Sabrina Dubroca) [RHEL-26416 RHEL-26421] {CVE-2024-26583}
    - gfs2: Fix kernel NULL pointer dereference in gfs2_rgrp_dump (Andrew Price) [RHEL-26500 RHEL-26502]
    {CVE-2023-52448}
    - smb: client: fix OOB in receive_encrypted_standard() (Scott Mayhew) [RHEL-21687 RHEL-21688]
    {CVE-2024-0565}
    - fs,hugetlb: fix NULL pointer dereference in hugetlbs_fill_super {CVE-2024-0841} (Audra Mitchell)
    [RHEL-20615 RHEL-20617] {CVE-2024-0841}
    - smb: client: fix parsing of SMB3.1.1 POSIX create context (Paulo Alcantara) [RHEL-26242 RHEL-26244]
    {CVE-2023-52434}
    - smb: client: fix potential OOBs in smb2_parse_contexts() (Paulo Alcantara) [RHEL-26242 RHEL-26244]
    {CVE-2023-52434}
    - tty: n_gsm: initialize more members at gsm_alloc_mux() (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix race condition in gsmld_write() (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix resource allocation order in gsm_activate_mux() (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix race condition in status line change on dead connections (Wander Lairson Costa)
    [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: add sanity check for gsm->receive in gsm_receive_buf() (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix flow control handling in tx path (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: Debug output allocation must use GFP_ATOMIC (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix sometimes uninitialized warning in gsm_dlci_modem_output() (Wander Lairson Costa)
    [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix NULL pointer access due to DLCI release (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: name the debug bits (Wander Lairson Costa) [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: replace use of gsm_read_ea() with gsm_read_ea_val() (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix missing tty wakeup in convergence layer type 2 (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix wrong signal octets encoding in MSC (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix buffer over-read in gsm_dlci_data() (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix wrong modem processing in convergence layer type 2 (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix user open not possible at responder until initiator open (Wander Lairson Costa)
    [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: Delete gsmtty open SABM frame when config requester (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix deadlock and link starvation in outgoing data path (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix non flow control frames during mux flow off (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix reset fifo race condition (Wander Lairson Costa) [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix missing explicit ldisc flush (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix deadlock in gsmtty_open() (Wander Lairson Costa) [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: Modify CR,PF bit printk info when config requester (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix SW flow control encoding/handling (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: add parameters used with parameter negotiation (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix wrong command retry handling (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: introduce macro for minimal unit size (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix insufficient txframe size (Wander Lairson Costa) [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: introduce gsm_control_command() function (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix invalid use of MSC in advanced option (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix wrong command frame length field encoding (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix wrong tty control line for flow control (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix missing timer to handle stalled links (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix wrong queuing behavior in gsm_dlci_data_output() (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix wrong signal octet encoding in convergence layer type 2 (Wander Lairson Costa)
    [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: add parameter negotiation support (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix tty registration before control channel open (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix software flow control handling (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: Fix packet data hex dump output (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: Don't ignore write return value in gsmld_output() (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: name gsm tty device minors (Wander Lairson Costa) [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: stop using alloc_tty_driver (Wander Lairson Costa) [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: don't store semi-state into tty drivers (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - hvsi: don't panic on tty_register_driver failure (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - amiserial: switch rs_table to a single state (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - amiserial: expand 'custom' (Wander Lairson Costa) [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - amiserial: remove serial_* strings (Wander Lairson Costa) [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - amiserial: use memset to zero serial_state (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - Revert 'tty: n_gsm: fix UAF in gsm_cleanup_mux' (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix encoding of command/response bit (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix broken virtual tty handling (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix missing update of modem controls after DLCI open (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix frame reception handling (Wander Lairson Costa) [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: clean up indenting in gsm_queue() (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: Save dlci address open status when config requester (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: Modify CR,PF bit when config requester (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix the UAF caused by race condition in gsm_cleanup_mux (Wander Lairson Costa) [RHEL-19959
    RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix UAF in gsm_cleanup_mux (Wander Lairson Costa) [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix wrong DLCI release order (Wander Lairson Costa) [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix mux cleanup after unregister tty device (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: fix decoupled mux resource (Wander Lairson Costa) [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - tty: n_gsm: fix restart handling via CLD command (Wander Lairson Costa) [RHEL-19959 RHEL-19971]
    {CVE-2023-6546}
    - tty: n_gsm: Modify gsmtty driver register method when config requester (Wander Lairson Costa)
    [RHEL-19959 RHEL-19971] {CVE-2023-6546}
    - netfilter: nf_tables: bail out on mismatching dynset and set expressions (Florian Westphal) [RHEL-19016
    RHEL-19017] {CVE-2023-6622}
    - netfilter: nf_tables: check if catch-all set element is active in next generation (Florian Westphal)
    [RHEL-23505 RHEL-23511] {CVE-2024-1085}
    - netfilter: nf_tables: reject QUEUE/DROP verdict parameters (Florian Westphal) [RHEL-23502 RHEL-23508]
    {CVE-2024-1086}
    - Bluetooth: Add more enc key size check (Bastien Nocera) [RHEL-19668 RHEL-19669] {CVE-2023-24023}
    - ida: Fix crash in ida_free when the bitmap is empty (Wander Lairson Costa) [RHEL-19683 RHEL-19684]
    {CVE-2023-6915}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-2394.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26555");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-25775");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:4:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:4:baseos_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rtla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.14.0-427.13.1.el9_4'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-2394');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-7.3.0-427.13.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-5.14.0-427.13.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-headers-5.14.0-427.13.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-tools-5.14.0-427.13.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-427.13.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-427.13.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'libperf-5.14.0-427.13.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-427.13.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-427.13.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-427.13.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-427.13.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-7.3.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.14.0'},
    {'reference':'kernel-abi-stablelists-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-5.14.0'},
    {'reference':'kernel-core-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-5.14.0'},
    {'reference':'kernel-cross-headers-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-debug-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-5.14.0'},
    {'reference':'kernel-debug-core-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-5.14.0'},
    {'reference':'kernel-debug-devel-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-5.14.0'},
    {'reference':'kernel-debug-devel-matched-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-matched-5.14.0'},
    {'reference':'kernel-debug-modules-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-5.14.0'},
    {'reference':'kernel-debug-modules-core-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-core-5.14.0'},
    {'reference':'kernel-debug-modules-extra-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-5.14.0'},
    {'reference':'kernel-debug-uki-virt-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-uki-virt-5.14.0'},
    {'reference':'kernel-devel-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-5.14.0'},
    {'reference':'kernel-devel-matched-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-matched-5.14.0'},
    {'reference':'kernel-headers-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-modules-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-5.14.0'},
    {'reference':'kernel-modules-core-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-core-5.14.0'},
    {'reference':'kernel-modules-extra-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-5.14.0'},
    {'reference':'kernel-tools-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'kernel-uki-virt-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uki-virt-5.14.0'},
    {'reference':'libperf-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-427.13.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / etc');
}
