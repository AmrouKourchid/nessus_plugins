#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226839);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52587");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52587");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: IB/ipoib: Fix mcast list locking
    Releasing the `priv->lock` while iterating the `priv->multicast_list` in `ipoib_mcast_join_task()` opens a
    window for `ipoib_mcast_dev_flush()` to remove the items while in the middle of iteration. If the mcast is
    removed while the lock was dropped, the for loop spins forever resulting in a hard lockup (as was reported
    on RHEL 4.18.0-372.75.1.el8_6 kernel): Task A (kworker/u72:2 below) | Task B (kworker/u72:0 below)
    -----------------------------------+----------------------------------- ipoib_mcast_join_task(work) |
    ipoib_ib_dev_flush_light(work) spin_lock_irq(&priv->lock) | __ipoib_ib_dev_flush(priv, ...)
    list_for_each_entry(mcast, | ipoib_mcast_dev_flush(dev = priv->dev) &priv->multicast_list, list) |
    ipoib_mcast_join(dev, mcast) | spin_unlock_irq(&priv->lock) | | spin_lock_irqsave(&priv->lock, flags) |
    list_for_each_entry_safe(mcast, tmcast, | &priv->multicast_list, list) | list_del(&mcast->list); |
    list_add_tail(&mcast->list, &remove_list) | spin_unlock_irqrestore(&priv->lock, flags)
    spin_lock_irq(&priv->lock) | | ipoib_mcast_remove_list(&remove_list) (Here, `mcast` is no longer on the |
    list_for_each_entry_safe(mcast, tmcast, `priv->multicast_list` and we keep | remove_list, list) spinning
    on the `remove_list` of | >>> wait_for_completion(&mcast->done) the other thread which is blocked | and
    the list is still valid on | it's stack.) Fix this by keeping the lock held and changing to GFP_ATOMIC to
    prevent eventual sleeps. Unfortunately we could not reproduce the lockup and confirm this fix but based on
    the code review I think this fix should address such lockups. crash> bc 31 PID: 747 TASK: ff1c6a1a007e8000
    CPU: 31 COMMAND: kworker/u72:2 -- [exception RIP: ipoib_mcast_join_task+0x1b1] RIP: ffffffffc0944ac1
    RSP: ff646f199a8c7e00 RFLAGS: 00000002 RAX: 0000000000000000 RBX: ff1c6a1a04dc82f8 RCX: 0000000000000000
    work (&priv->mcast_task{,.work}) RDX: ff1c6a192d60ac68 RSI: 0000000000000286 RDI: ff1c6a1a04dc8000
    &mcast->list RBP: ff646f199a8c7e90 R8: ff1c699980019420 R9: ff1c6a1920c9a000 R10: ff646f199a8c7e00 R11:
    ff1c6a191a7d9800 R12: ff1c6a192d60ac00 mcast R13: ff1c6a1d82200000 R14: ff1c6a1a04dc8000 R15:
    ff1c6a1a04dc82d8 dev priv (&priv->lock) &priv->multicast_list (aka head) ORIG_RAX: ffffffffffffffff CS:
    0010 SS: 0018 --- <NMI exception stack> --- #5 [ff646f199a8c7e00] ipoib_mcast_join_task+0x1b1 at
    ffffffffc0944ac1 [ib_ipoib] #6 [ff646f199a8c7e98] process_one_work+0x1a7 at ffffffff9bf10967 crash> rx
    ff646f199a8c7e68 ff646f199a8c7e68: ff1c6a1a04dc82f8 <<< work = &priv->mcast_task.work crash> list -hO
    ipoib_dev_priv.multicast_list ff1c6a1a04dc8000 (empty) crash>
    ipoib_dev_priv.mcast_task.work.func,mcast_mutex.owner.counter ff1c6a1a04dc8000 mcast_task.work.func =
    0xffffffffc0944910 <ipoib_mcast_join_task>, mcast_mutex.owner.counter = 0xff1c69998efec000 crash> b 8 PID:
    8 TASK: ff1c69998efec000 CPU: 33 COMMAND: kworker/u72:0 -- #3 [ff646f1980153d50]
    wait_for_completion+0x96 at ffffffff9c7d7646 #4 [ff646f1980153d90] ipoib_mcast_remove_list+0x56 at
    ffffffffc0944dc6 [ib_ipoib] #5 [ff646f1980153de8] ipoib_mcast_dev_flush+0x1a7 at ffffffffc09455a7
    [ib_ipoib] #6 [ff646f1980153e58] __ipoib_ib_dev_flush+0x1a4 at ffffffffc09431a4 [ib_ipoib] #7 [ff
    ---truncated--- (CVE-2023-52587)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52587");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
    "name": [
     "kernel",
     "kernel-rt"
    ],
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
        "os_version": "8"
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
