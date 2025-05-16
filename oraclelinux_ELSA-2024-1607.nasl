#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-1607.
##

include('compat.inc');

if (description)
{
  script_id(193196);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2021-33631",
    "CVE-2022-38096",
    "CVE-2023-6546",
    "CVE-2023-6931",
    "CVE-2023-51042",
    "CVE-2024-0565",
    "CVE-2024-1086"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/20");

  script_name(english:"Oracle Linux 8 : kernel (ELSA-2024-1607)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-1607 advisory.

    - ext4: fix kernel BUG in 'ext4_write_inline_data_end()' (Carlos Maiolino) [RHEL-26331 RHEL-23386]
    {CVE-2021-33631}
    - serial: core: return early on unsupported ioctls (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - lib/hexdump: make print_hex_dump_bytes() a nop on !DEBUG builds (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix race condition in status line change on dead connections (Wander Lairson Costa)
    [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - Revert 'tty: n_gsm: fix UAF in gsm_cleanup_mux' (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix the UAF caused by race condition in gsm_cleanup_mux (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix UAF in gsm_cleanup_mux (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: add parameter negotiation support (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: add parameters used with parameter negotiation (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: introduce macro for minimal unit size (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: name the debug bits (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: introduce gsm_control_command() function (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: replace use of gsm_read_ea() with gsm_read_ea_val() (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: name gsm tty device minors (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: initialize more members at gsm_alloc_mux() (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: add sanity check for gsm->receive in gsm_receive_buf() (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix flow control handling in tx path (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix resource allocation order in gsm_activate_mux() (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix deadlock and link starvation in outgoing data path (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix race condition in gsmld_write() (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix non flow control frames during mux flow off (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix missing timer to handle stalled links (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix wrong queuing behavior in gsm_dlci_data_output() (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix tty registration before control channel open (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix user open not possible at responder until initiator open (Wander Lairson Costa)
    [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: Debug output allocation must use GFP_ATOMIC (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: Fix packet data hex dump output (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix buffer over-read in gsm_dlci_data() (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix sometimes uninitialized warning in gsm_dlci_modem_output() (Wander Lairson Costa)
    [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix software flow control handling (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix invalid use of MSC in advanced option (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix broken virtual tty handling (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix missing update of modem controls after DLCI open (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix reset fifo race condition (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix missing tty wakeup in convergence layer type 2 (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix wrong signal octets encoding in MSC (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix wrong command frame length field encoding (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix wrong command retry handling (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix missing explicit ldisc flush (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix wrong DLCI release order (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix insufficient txframe size (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix frame reception handling (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix wrong signal octet encoding in convergence layer type 2 (Wander Lairson Costa)
    [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix mux cleanup after unregister tty device (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix decoupled mux resource (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix restart handling via CLD command (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix deadlock in gsmtty_open() (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix wrong modem processing in convergence layer type 2 (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: fix wrong tty control line for flow control (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix NULL pointer access due to DLCI release (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix encoding of command/response bit (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: fix SW flow control encoding/handling (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - mxser: remove tty parameter from mxser_receive_chars_new() (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - mxser: don't throttle manually (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: make mxser_port::ldisc_stop_rx a bool (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: Don't ignore write return value in gsmld_output() (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: clean up indenting in gsm_queue() (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: Save dlci address open status when config requester (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: Modify gsmtty driver register method when config requester (Wander Lairson Costa)
    [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: Delete gsmtty open SABM frame when config requester (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: Modify CR,PF bit printk info when config requester (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: Modify CR,PF bit when config requester (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: stop using alloc_tty_driver (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: don't store semi-state into tty drivers (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - hvsi: don't panic on tty_register_driver failure (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - amiserial: switch rs_table to a single state (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - amiserial: expand 'custom' (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - amiserial: use memset to zero serial_state (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - amiserial: remove serial_* strings (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: drop mxser_port::custom_divisor (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: drop mxser_port::baud_base (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: remove unused mxser_port::stop_rx (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: don't allocate MXSER_PORTS + 1 (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: remove cnt from mxser_receive_chars (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - mxser: remove MOXA_GETMSTATUS ioctl (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: remove MOXA_GETDATACOUNT ioctl (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: remove MOXA_CHKPORTENABLE ioctl (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: remove MOXA_ASPP_LSTATUS ioctl (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: remove MOXA_ASPP_MON and friends (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: remove MOXA_SET_BAUD_METHOD ioctl (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: remove MOXA_GET_MAJOR deprecated ioctl (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - mxser: drop unused MOXA_DIAGNOSE macro (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: drop UART_MCR_AFE and UART_LSR_SPECIAL defines (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - mxser: remove else from LSR bits checks (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: extract mxser_receive_chars_old (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: extract mxser_receive_chars_new (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: simplify mxser_interrupt and drop mxser_board::vector_mask (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - mxser: extract port ISR (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: cleanup LSR handling in mxser_receive_chars (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - mxser: remove nonsense from ISR (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: drop constant board::uart_type (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: introduce enum mxser_must_hwid (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: rename mxser_board::chip_flag to must_hwid (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - mxser: rename CheckIsMoxaMust to mxser_get_must_hwid (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - mxser: cleanup Gpci_uart_info struct (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: integrate mxser.h into .c (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - mxser: drop ISA support (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - n_gsm: use goto-failpaths in gsm_init (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: mxser: drop low-latency workaround (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: check error while registering tty devices (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: mxser: fix TIOCSSERIAL jiffies conversions (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm, remove duplicates of parameters (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: do not check tty_unregister_driver's return value (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: nozomi, remove init/exit messages (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty_port: drop last traces of low_latency (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: Demote obvious abuse of kernel-doc and supply other missing docss (Wander Lairson Costa)
    [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm, eliminate indirection for gsm->{output,error}() (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: Fix bogus i++ in gsm_data_kick (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: Remove unnecessary test in gsm_print_packet() (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: Fix waking up upper tty layer when room available (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: Fix SOF skipping (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: Improve debug output (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - n_gsm: switch constipated to bool (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - n_gsm: switch throttled to bool (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - n_gsm: switch dead to bool (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - n_gsm: introduce enum gsm_dlci_mode (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - n_gsm: introduce enum gsm_dlci_state (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - n_gsm: drop unneeded gsm_dlci->fifo field (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: Replace zero-length array with flexible-array member (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: avoid recursive locking with async port hangup (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - tty: n_gsm: add helpers to convert mux-num to/from tty-base (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - docs: serial: move it to the driver-api (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - docs: serial: convert docs to ReST and rename to *.rst (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: Mark expected switch fall-throughs (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - n_gsm: Constify u8 and unsigned char usage (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - tty: n_gsm: Add copy_config() and gsm_config() to prepare for serdev (Wander Lairson Costa) [RHEL-19954
    RHEL-19955] {CVE-2023-6546}
    - mxser: switch to ->[sg]et_serial() (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - amiserial: switch to ->[sg]et_serial() (Wander Lairson Costa) [RHEL-19954 RHEL-19955] {CVE-2023-6546}
    - tty/serial_core: add ISO7816 infrastructure (Wander Lairson Costa) [RHEL-19954 RHEL-19955]
    {CVE-2023-6546}
    - drm/amdgpu: Fix potential fence use-after-free v2 (Jorge San Emeterio) [RHEL-24479 RHEL-22504]
    {CVE-2023-51042}
    - perf: Fix perf_event_validate_size() lockdep splat (Michael Petlan) [RHEL-22930 RHEL-17968]
    {CVE-2023-6931}
    - perf: Fix perf_event_validate_size() (Michael Petlan) [RHEL-22930 RHEL-17968] {CVE-2023-6931}
    - smb: client: fix OOB in receive_encrypted_standard() (Scott Mayhew) [RHEL-22077 RHEL-21685]
    {CVE-2024-0565}
    - drm/vmwgfx: Fix possible null pointer derefence with invalid contexts (Jocelyn Falempe) [RHEL-22766
    RHEL-3179] {CVE-2022-38096}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-1607.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0565");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-1086");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:23.1.15.0.0::ol8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:24.1.0.0.0::ol8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:24.1.1.0.0::ol8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:9:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.18.0-513.24.1.el8_9'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-1607');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.18';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-4.18.0-513.24.1.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-513.24.1.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-headers-4.18.0-513.24.1.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-tools-4.18.0-513.24.1.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-513.24.1.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-513.24.1.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-513.24.1.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-513.24.1.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-4.18.0'},
    {'reference':'kernel-abi-stablelists-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-4.18.0'},
    {'reference':'kernel-core-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-4.18.0'},
    {'reference':'kernel-cross-headers-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-debug-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-4.18.0'},
    {'reference':'kernel-debug-core-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-4.18.0'},
    {'reference':'kernel-debug-devel-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-4.18.0'},
    {'reference':'kernel-debug-modules-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-4.18.0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-4.18.0'},
    {'reference':'kernel-devel-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-4.18.0'},
    {'reference':'kernel-headers-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-modules-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-4.18.0'},
    {'reference':'kernel-modules-extra-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-4.18.0'},
    {'reference':'kernel-tools-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-513.24.1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / etc');
}
