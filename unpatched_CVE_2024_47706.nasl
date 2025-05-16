#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228469);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-47706");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-47706");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: block, bfq: fix possible UAF for
    bfqq->bic with merge chain 1) initial state, three tasks: Process 1 Process 2 Process 3 (BIC1) (BIC2)
    (BIC3) |  |  |  | | | | | | V | V | V | bfqq1 bfqq2 bfqq3 process ref: 1 1 1 2) bfqq1 merged to bfqq2:
    Process 1 Process 2 Process 3 (BIC1) (BIC2) (BIC3) | | |  \--------------\| | | V V |
    bfqq1--------->bfqq2 bfqq3 process ref: 0 2 1 3) bfqq2 merged to bfqq3: Process 1 Process 2 Process 3
    (BIC1) (BIC2) (BIC3) here ->  | | \--------------\ \-------------\| V V
    bfqq1--------->bfqq2---------->bfqq3 process ref: 0 1 3 In this case, IO from Process 1 will get bfqq2
    from BIC1 first, and then get bfqq3 through merge chain, and finially handle IO by bfqq3. Howerver,
    current code will think bfqq2 is owned by BIC1, like initial state, and set bfqq2->bic to BIC1.
    bfq_insert_request -> by Process 1 bfqq = bfq_init_rq(rq) bfqq = bfq_get_bfqq_handle_split bfqq =
    bic_to_bfqq -> get bfqq2 from BIC1 bfqq->ref++ rq->elv.priv[0] = bic rq->elv.priv[1] = bfqq if
    (bfqq_process_refs(bfqq) == 1) bfqq->bic = bic -> record BIC1 to bfqq2 __bfq_insert_request new_bfqq =
    bfq_setup_cooperator -> get bfqq3 from bfqq2->new_bfqq bfqq_request_freed(bfqq) new_bfqq->ref++
    rq->elv.priv[1] = new_bfqq -> handle IO by bfqq3 Fix the problem by checking bfqq is from merge chain
    fist. And this might fix a following problem reported by our syzkaller(unreproducible):
    ================================================================== BUG: KASAN: slab-use-after-free in
    bfq_do_early_stable_merge block/bfq-iosched.c:5692 [inline] BUG: KASAN: slab-use-after-free in
    bfq_do_or_sched_stable_merge block/bfq-iosched.c:5805 [inline] BUG: KASAN: slab-use-after-free in
    bfq_get_queue+0x25b0/0x2610 block/bfq-iosched.c:5889 Write of size 1 at addr ffff888123839eb8 by task
    kworker/0:1H/18595 CPU: 0 PID: 18595 Comm: kworker/0:1H Tainted: G L 6.6.0-07439-gba2303cacfda #6 Hardware
    name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014
    Workqueue: kblockd blk_mq_requeue_work Call Trace: <TASK> __dump_stack lib/dump_stack.c:88 [inline]
    dump_stack_lvl+0x91/0xf0 lib/dump_stack.c:106 print_address_description mm/kasan/report.c:364 [inline]
    print_report+0x10d/0x610 mm/kasan/report.c:475 kasan_report+0x8e/0xc0 mm/kasan/report.c:588
    bfq_do_early_stable_merge block/bfq-iosched.c:5692 [inline] bfq_do_or_sched_stable_merge block/bfq-
    iosched.c:5805 [inline] bfq_get_queue+0x25b0/0x2610 block/bfq-iosched.c:5889
    bfq_get_bfqq_handle_split+0x169/0x5d0 block/bfq-iosched.c:6757 bfq_init_rq block/bfq-iosched.c:6876
    [inline] bfq_insert_request block/bfq-iosched.c:6254 [inline] bfq_insert_requests+0x1112/0x5cf0 block/bfq-
    iosched.c:6304 blk_mq_insert_request+0x290/0x8d0 block/blk-mq.c:2593 blk_mq_requeue_work+0x6bc/0xa70
    block/blk-mq.c:1502 process_one_work kernel/workqueue.c:2627 [inline] process_scheduled_works+0x432/0x13f0
    kernel/workqueue.c:2700 worker_thread+0x6f2/0x1160 kernel/workqueue.c:2781 kthread+0x33c/0x440
    kernel/kthread.c:388 ret_from_fork+0x4d/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1b/0x30
    arch/x86/entry/entry_64.S:305 </TASK> Allocated by task 20776: kasan_save_stack+0x20/0x40
    mm/kasan/common.c:45 kasan_set_track+0x25/0x30 mm/kasan/common.c:52 __kasan_slab_alloc+0x87/0x90
    mm/kasan/common.c:328 kasan_slab_alloc include/linux/kasan.h:188 [inline] slab_post_alloc_hook
    mm/slab.h:763 [inline] slab_alloc_node mm/slub.c:3458 [inline] kmem_cache_alloc_node+0x1a4/0x6f0
    mm/slub.c:3503 ioc_create_icq block/blk-ioc.c:370 [inline] ---truncated--- (CVE-2024-47706)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47706");

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
     "linux-azure-fde-5.15",
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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
