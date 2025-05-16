#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228723);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-47696");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-47696");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: RDMA/iwcm: Fix
    WARNING:at_kernel/workqueue.c:#check_flush_dependency In the commit aee2424246f9 (RDMA/iwcm: Fix a use-
    after-free related to destroying CM IDs), the function flush_workqueue is invoked to flush the work queue
    iwcm_wq. But at that time, the work queue iwcm_wq was created via the function alloc_ordered_workqueue
    without the flag WQ_MEM_RECLAIM. Because the current process is trying to flush the whole iwcm_wq, if
    iwcm_wq doesn't have the flag WQ_MEM_RECLAIM, verify that the current process is not reclaiming memory or
    running on a workqueue which doesn't have the flag WQ_MEM_RECLAIM as that can break forward-progress
    guarantee leading to a deadlock. The call trace is as below: [ 125.350876][ T1430] Call Trace: [
    125.356281][ T1430] <TASK> [ 125.361285][ T1430] ? __warn (kernel/panic.c:693) [ 125.367640][ T1430] ?
    check_flush_dependency (kernel/workqueue.c:3706 (discriminator 9)) [ 125.375689][ T1430] ? report_bug
    (lib/bug.c:180 lib/bug.c:219) [ 125.382505][ T1430] ? handle_bug (arch/x86/kernel/traps.c:239) [
    125.388987][ T1430] ? exc_invalid_op (arch/x86/kernel/traps.c:260 (discriminator 1)) [ 125.395831][ T1430]
    ? asm_exc_invalid_op (arch/x86/include/asm/idtentry.h:621) [ 125.403125][ T1430] ? check_flush_dependency
    (kernel/workqueue.c:3706 (discriminator 9)) [ 125.410984][ T1430] ? check_flush_dependency
    (kernel/workqueue.c:3706 (discriminator 9)) [ 125.418764][ T1430] __flush_workqueue
    (kernel/workqueue.c:3970) [ 125.426021][ T1430] ? __pfx___might_resched (kernel/sched/core.c:10151) [
    125.433431][ T1430] ? destroy_cm_id (drivers/infiniband/core/iwcm.c:375) iw_cm [ 125.441209][ T1430] ?
    __pfx___flush_workqueue (kernel/workqueue.c:3910) [ 125.473900][ T1430] ? _raw_spin_lock_irqsave
    (arch/x86/include/asm/atomic.h:107 include/linux/atomic/atomic-arch-fallback.h:2170
    include/linux/atomic/atomic-instrumented.h:1302 include/asm-generic/qspinlock.h:111
    include/linux/spinlock.h:187 include/linux/spinlock_api_smp.h:111 kernel/locking/spinlock.c:162) [
    125.473909][ T1430] ? __pfx__raw_spin_lock_irqsave (kernel/locking/spinlock.c:161) [ 125.482537][ T1430]
    _destroy_id (drivers/infiniband/core/cma.c:2044) rdma_cm [ 125.495072][ T1430] nvme_rdma_free_queue
    (drivers/nvme/host/rdma.c:656 drivers/nvme/host/rdma.c:650) nvme_rdma [ 125.505827][ T1430]
    nvme_rdma_reset_ctrl_work (drivers/nvme/host/rdma.c:2180) nvme_rdma [ 125.505831][ T1430] process_one_work
    (kernel/workqueue.c:3231) [ 125.515122][ T1430] worker_thread (kernel/workqueue.c:3306
    kernel/workqueue.c:3393) [ 125.515127][ T1430] ? __pfx_worker_thread (kernel/workqueue.c:3339) [
    125.531837][ T1430] kthread (kernel/kthread.c:389) [ 125.539864][ T1430] ? __pfx_kthread
    (kernel/kthread.c:342) [ 125.550628][ T1430] ret_from_fork (arch/x86/kernel/process.c:147) [ 125.558840][
    T1430] ? __pfx_kthread (kernel/kthread.c:342) [ 125.558844][ T1430] ret_from_fork_asm
    (arch/x86/entry/entry_64.S:257) [ 125.566487][ T1430] </TASK> [ 125.566488][ T1430] ---[ end trace
    0000000000000000 ]--- (CVE-2024-47696)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
     "linux-aws-5.4",
     "linux-oracle-5.4",
     "linux-raspi-5.4"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "18.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-fips",
     "linux-azure-fips",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-fips",
     "linux-gcp-fips",
     "linux-headers-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-iot",
     "linux-modules-5.4.0-1008-raspi",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-tools-5.4.0-1008-raspi"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "20.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-azure-cloud-tools-6.8.0-1007",
     "linux-azure-headers-6.8.0-1007",
     "linux-azure-tools-6.8.0-1007",
     "linux-buildinfo-6.8.0-1005-ibm",
     "linux-buildinfo-6.8.0-1005-oem",
     "linux-buildinfo-6.8.0-1007-azure",
     "linux-cloud-tools-6.8.0-1005-ibm",
     "linux-cloud-tools-6.8.0-1005-oem",
     "linux-cloud-tools-6.8.0-1007-azure",
     "linux-headers-6.8.0-1005-ibm",
     "linux-headers-6.8.0-1005-oem",
     "linux-headers-6.8.0-1007-azure",
     "linux-ibm-cloud-tools-6.8.0-1005",
     "linux-ibm-cloud-tools-common",
     "linux-ibm-headers-6.8.0-1005",
     "linux-ibm-source-6.8.0",
     "linux-ibm-tools-6.8.0-1005",
     "linux-ibm-tools-common",
     "linux-image-unsigned-6.8.0-1005-ibm",
     "linux-image-unsigned-6.8.0-1005-ibm-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oem",
     "linux-image-unsigned-6.8.0-1005-oem-dbgsym",
     "linux-image-unsigned-6.8.0-1007-azure",
     "linux-image-unsigned-6.8.0-1007-azure-dbgsym",
     "linux-lowlatency-hwe-6.11",
     "linux-modules-6.8.0-1005-ibm",
     "linux-modules-6.8.0-1005-oem",
     "linux-modules-6.8.0-1007-azure",
     "linux-modules-extra-6.8.0-1005-ibm",
     "linux-modules-extra-6.8.0-1005-oem",
     "linux-modules-extra-6.8.0-1007-azure",
     "linux-modules-ipu6-6.8.0-1005-oem",
     "linux-modules-iwlwifi-6.8.0-1005-ibm",
     "linux-modules-iwlwifi-6.8.0-1005-oem",
     "linux-modules-iwlwifi-6.8.0-1007-azure",
     "linux-oem-6.8-headers-6.8.0-1005",
     "linux-oem-6.8-lib-rust-6.8.0-1005-oem",
     "linux-oem-6.8-tools-6.8.0-1005",
     "linux-raspi-realtime",
     "linux-realtime",
     "linux-tools-6.8.0-1005-ibm",
     "linux-tools-6.8.0-1005-oem",
     "linux-tools-6.8.0-1007-azure",
     "linux-udebs-azure"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "24.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-azure-6.8",
     "linux-azure-fde",
     "linux-hwe-6.8"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
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
