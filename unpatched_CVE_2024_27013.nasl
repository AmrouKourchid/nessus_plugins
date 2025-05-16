#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227669);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-27013");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-27013");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tun: limit printing rate when illegal
    packet received by tun dev vhost_worker will call tun call backs to receive packets. If too many illegal
    packets arrives, tun_do_read will keep dumping packet contents. When console is enabled, it will costs
    much more cpu time to dump packet and soft lockup will be detected. net_ratelimit mechanism can be used to
    limit the dumping rate. PID: 33036 TASK: ffff949da6f20000 CPU: 23 COMMAND: vhost-32980 #0
    [fffffe00003fce50] crash_nmi_callback at ffffffff89249253 #1 [fffffe00003fce58] nmi_handle at
    ffffffff89225fa3 #2 [fffffe00003fceb0] default_do_nmi at ffffffff8922642e #3 [fffffe00003fced0] do_nmi at
    ffffffff8922660d #4 [fffffe00003fcef0] end_repeat_nmi at ffffffff89c01663 [exception RIP: io_serial_in+20]
    RIP: ffffffff89792594 RSP: ffffa655314979e8 RFLAGS: 00000002 RAX: ffffffff89792500 RBX: ffffffff8af428a0
    RCX: 0000000000000000 RDX: 00000000000003fd RSI: 0000000000000005 RDI: ffffffff8af428a0 RBP:
    0000000000002710 R8: 0000000000000004 R9: 000000000000000f R10: 0000000000000000 R11: ffffffff8acbf64f
    R12: 0000000000000020 R13: ffffffff8acbf698 R14: 0000000000000058 R15: 0000000000000000 ORIG_RAX:
    ffffffffffffffff CS: 0010 SS: 0018 #5 [ffffa655314979e8] io_serial_in at ffffffff89792594 #6
    [ffffa655314979e8] wait_for_xmitr at ffffffff89793470 #7 [ffffa65531497a08] serial8250_console_putchar at
    ffffffff897934f6 #8 [ffffa65531497a20] uart_console_write at ffffffff8978b605 #9 [ffffa65531497a48]
    serial8250_console_write at ffffffff89796558 #10 [ffffa65531497ac8] console_unlock at ffffffff89316124 #11
    [ffffa65531497b10] vprintk_emit at ffffffff89317c07 #12 [ffffa65531497b68] printk at ffffffff89318306 #13
    [ffffa65531497bc8] print_hex_dump at ffffffff89650765 #14 [ffffa65531497ca8] tun_do_read at
    ffffffffc0b06c27 [tun] #15 [ffffa65531497d38] tun_recvmsg at ffffffffc0b06e34 [tun] #16 [ffffa65531497d68]
    handle_rx at ffffffffc0c5d682 [vhost_net] #17 [ffffa65531497ed0] vhost_worker at ffffffffc0c644dc [vhost]
    #18 [ffffa65531497f10] kthread at ffffffff892d2e72 #19 [ffffa65531497f50] ret_from_fork at
    ffffffff89c0022f (CVE-2024-27013)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27013");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": "kernel-rt",
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "9"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
