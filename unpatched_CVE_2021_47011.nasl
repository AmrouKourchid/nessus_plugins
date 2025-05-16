#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230211);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47011");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47011");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm: memcontrol: slab: fix obtain a
    reference to a freeing memcg Patch series Use obj_cgroup APIs to charge kmem pages, v5. Since Roman's
    series The new cgroup slab memory controller applied. All slab objects are charged with the new APIs of
    obj_cgroup. The new APIs introduce a struct obj_cgroup to charge slab objects. It prevents long-living
    objects from pinning the original memory cgroup in the memory. But there are still some corner objects
    (e.g. allocations larger than order-1 page on SLUB) which are not charged with the new APIs. Those objects
    (include the pages which are allocated from buddy allocator directly) are charged as kmem pages which
    still hold a reference to the memory cgroup. E.g. We know that the kernel stack is charged as kmem pages
    because the size of the kernel stack can be greater than 2 pages (e.g. 16KB on x86_64 or arm64). If we
    create a thread (suppose the thread stack is charged to memory cgroup A) and then move it from memory
    cgroup A to memory cgroup B. Because the kernel stack of the thread hold a reference to the memory cgroup
    A. The thread can pin the memory cgroup A in the memory even if we remove the cgroup A. If we want to see
    this scenario by using the following script. We can see that the system has added 500 dying cgroups (This
    is not a real world issue, just a script to show that the large kmallocs are charged as kmem pages which
    can pin the memory cgroup in the memory). #!/bin/bash cat /proc/cgroups | grep memory cd
    /sys/fs/cgroup/memory echo 1 > memory.move_charge_at_immigrate for i in range{1..500} do mkdir kmem_test
    echo $$ > kmem_test/cgroup.procs sleep 3600 & echo $$ > cgroup.procs echo `cat kmem_test/cgroup.procs` >
    cgroup.procs rmdir kmem_test done cat /proc/cgroups | grep memory This patchset aims to make those kmem
    pages to drop the reference to memory cgroup by using the APIs of obj_cgroup. Finally, we can see that the
    number of the dying cgroups will not increase if we run the above test script. This patch (of 7): The
    rcu_read_lock/unlock only can guarantee that the memcg will not be freed, but it cannot guarantee the
    success of css_get (which is in the refill_stock when cached memcg changed) to memcg. rcu_read_lock()
    memcg = obj_cgroup_memcg(old) __memcg_kmem_uncharge(memcg) refill_stock(memcg) if (stock->cached != memcg)
    // css_get can change the ref counter from 0 back to 1. css_get(&memcg->css) rcu_read_unlock() This fix is
    very like the commit: eefbfa7fd678 (mm: memcg/slab: fix use after free in obj_cgroup_charge) Fix this by
    holding a reference to the memcg which is passed to the __memcg_kmem_uncharge() before calling
    __memcg_kmem_uncharge(). (CVE-2021-47011)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47011");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
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
