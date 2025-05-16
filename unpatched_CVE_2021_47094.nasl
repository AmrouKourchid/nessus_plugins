#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224446);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47094");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47094");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: x86/mmu: Don't advance iterator
    after restart due to yielding After dropping mmu_lock in the TDP MMU, restart the iterator during
    tdp_iter_next() and do not advance the iterator. Advancing the iterator results in skipping the top-level
    SPTE and all its children, which is fatal if any of the skipped SPTEs were not visited before yielding.
    When zapping all SPTEs, i.e. when min_level == root_level, restarting the iter and then invoking
    tdp_iter_next() is always fatal if the current gfn has as a valid SPTE, as advancing the iterator results
    in try_step_side() skipping the current gfn, which wasn't visited before yielding. Sprinkle WARNs on
    iter->yielded being true in various helpers that are often used in conjunction with yielding, and tag the
    helper with __must_check to reduce the probabily of improper usage. Failing to zap a top-level SPTE
    manifests in one of two ways. If a valid SPTE is skipped by both kvm_tdp_mmu_zap_all() and
    kvm_tdp_mmu_put_root(), the shadow page will be leaked and KVM will WARN accordingly. WARNING: CPU: 1 PID:
    3509 at arch/x86/kvm/mmu/tdp_mmu.c:46 [kvm] RIP: 0010:kvm_mmu_uninit_tdp_mmu+0x3e/0x50 [kvm] Call Trace:
    <TASK> kvm_arch_destroy_vm+0x130/0x1b0 [kvm] kvm_destroy_vm+0x162/0x2a0 [kvm] kvm_vcpu_release+0x34/0x60
    [kvm] __fput+0x82/0x240 task_work_run+0x5c/0x90 do_exit+0x364/0xa10 ? futex_unqueue+0x38/0x60
    do_group_exit+0x33/0xa0 get_signal+0x155/0x850 arch_do_signal_or_restart+0xed/0x750
    exit_to_user_mode_prepare+0xc5/0x120 syscall_exit_to_user_mode+0x1d/0x40 do_syscall_64+0x48/0xc0
    entry_SYSCALL_64_after_hwframe+0x44/0xae If kvm_tdp_mmu_zap_all() skips a gfn/SPTE but that SPTE is then
    zapped by kvm_tdp_mmu_put_root(), KVM triggers a use-after-free in the form of marking a struct page as
    dirty/accessed after it has been put back on the free list. This directly triggers a WARN due to
    encountering a page with page_count() == 0, but it can also lead to data corruption and additional errors
    in the kernel. WARNING: CPU: 7 PID: 1995658 at arch/x86/kvm/../../../virt/kvm/kvm_main.c:171 RIP:
    0010:kvm_is_zone_device_pfn.part.0+0x9e/0xd0 [kvm] Call Trace: <TASK> kvm_set_pfn_dirty+0x120/0x1d0 [kvm]
    __handle_changed_spte+0x92e/0xca0 [kvm] __handle_changed_spte+0x63c/0xca0 [kvm]
    __handle_changed_spte+0x63c/0xca0 [kvm] __handle_changed_spte+0x63c/0xca0 [kvm] zap_gfn_range+0x549/0x620
    [kvm] kvm_tdp_mmu_put_root+0x1b6/0x270 [kvm] mmu_free_root_page+0x219/0x2c0 [kvm]
    kvm_mmu_free_roots+0x1b4/0x4e0 [kvm] kvm_mmu_unload+0x1c/0xa0 [kvm] kvm_arch_destroy_vm+0x1f2/0x5c0 [kvm]
    kvm_put_kvm+0x3b1/0x8b0 [kvm] kvm_vcpu_release+0x4e/0x70 [kvm] __fput+0x1f7/0x8c0 task_work_run+0xf8/0x1a0
    do_exit+0x97b/0x2230 do_group_exit+0xda/0x2a0 get_signal+0x3be/0x1e50
    arch_do_signal_or_restart+0x244/0x17f0 exit_to_user_mode_prepare+0xcb/0x120
    syscall_exit_to_user_mode+0x1d/0x40 do_syscall_64+0x4d/0x90 entry_SYSCALL_64_after_hwframe+0x44/0xae Note,
    the underlying bug existed even before commit 1af4a96025b3 (KVM: x86/mmu: Yield in TDU MMU iter even if
    no SPTES changed) moved calls to tdp_mmu_iter_cond_resched() to the beginning of loops, as KVM could
    still incorrectly advance past a top-level entry when yielding on a lower-level entry. But with respect to
    leaking shadow pages, the bug was introduced by yielding before processing the current gfn. Alternatively,
    tdp_mmu_iter_cond_resched() could simply fall through, or callers could jump to their retry label. The
    downside of that approach is that tdp_mmu_iter_cond_resched() _must_ be called before anything else in the
    loop, and there's no easy way to enfornce that requirement. Ideally, KVM would handling the cond_resched()
    fully within the iterator macro (the code is actually quite clean) and avoid this entire class of bugs,
    but that is extremely difficult do wh ---truncated--- (CVE-2021-47094)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47094");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
     "bpftool",
     "btrfs-modules-5.10.0-32-alpha-generic-di",
     "cdrom-core-modules-5.10.0-32-alpha-generic-di",
     "hyperv-daemons",
     "kernel-image-5.10.0-32-alpha-generic-di",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bootwrapper-5.10.0-32",
     "linux-config-5.10",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-5.10",
     "linux-headers-5.10.0-32-common",
     "linux-headers-5.10.0-32-common-rt",
     "linux-kbuild-5.10",
     "linux-libc-dev",
     "linux-perf",
     "linux-perf-5.10",
     "linux-source",
     "linux-source-5.10",
     "linux-support-5.10.0-32",
     "loop-modules-5.10.0-32-alpha-generic-di",
     "nic-modules-5.10.0-32-alpha-generic-di",
     "nic-shared-modules-5.10.0-32-alpha-generic-di",
     "nic-wireless-modules-5.10.0-32-alpha-generic-di",
     "pata-modules-5.10.0-32-alpha-generic-di",
     "ppp-modules-5.10.0-32-alpha-generic-di",
     "scsi-core-modules-5.10.0-32-alpha-generic-di",
     "scsi-modules-5.10.0-32-alpha-generic-di",
     "scsi-nic-modules-5.10.0-32-alpha-generic-di",
     "serial-modules-5.10.0-32-alpha-generic-di",
     "usb-serial-modules-5.10.0-32-alpha-generic-di",
     "usbip"
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
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
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
