#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228014);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26861");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26861");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: wireguard: receive: annotate data-race
    around receiving_counter.counter Syzkaller with KCSAN identified a data-race issue when accessing
    keypair->receiving_counter.counter. Use READ_ONCE() and WRITE_ONCE() annotations to mark the data race as
    intentional. BUG: KCSAN: data-race in wg_packet_decrypt_worker / wg_packet_rx_poll write to
    0xffff888107765888 of 8 bytes by interrupt on cpu 0: counter_validate drivers/net/wireguard/receive.c:321
    [inline] wg_packet_rx_poll+0x3ac/0xf00 drivers/net/wireguard/receive.c:461 __napi_poll+0x60/0x3b0
    net/core/dev.c:6536 napi_poll net/core/dev.c:6605 [inline] net_rx_action+0x32b/0x750 net/core/dev.c:6738
    __do_softirq+0xc4/0x279 kernel/softirq.c:553 do_softirq+0x5e/0x90 kernel/softirq.c:454
    __local_bh_enable_ip+0x64/0x70 kernel/softirq.c:381 __raw_spin_unlock_bh
    include/linux/spinlock_api_smp.h:167 [inline] _raw_spin_unlock_bh+0x36/0x40 kernel/locking/spinlock.c:210
    spin_unlock_bh include/linux/spinlock.h:396 [inline] ptr_ring_consume_bh include/linux/ptr_ring.h:367
    [inline] wg_packet_decrypt_worker+0x6c5/0x700 drivers/net/wireguard/receive.c:499 process_one_work
    kernel/workqueue.c:2633 [inline] ... read to 0xffff888107765888 of 8 bytes by task 3196 on cpu 1:
    decrypt_packet drivers/net/wireguard/receive.c:252 [inline] wg_packet_decrypt_worker+0x220/0x700
    drivers/net/wireguard/receive.c:501 process_one_work kernel/workqueue.c:2633 [inline]
    process_scheduled_works+0x5b8/0xa30 kernel/workqueue.c:2706 worker_thread+0x525/0x730
    kernel/workqueue.c:2787 ... (CVE-2024-26861)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26861");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
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
