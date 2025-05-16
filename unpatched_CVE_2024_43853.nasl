#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228912);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-43853");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-43853");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: cgroup/cpuset: Prevent UAF in
    proc_cpuset_show() An UAF can happen when /proc/cpuset is read as reported in [1]. This can be reproduced
    by the following methods: 1.add an mdelay(1000) before acquiring the cgroup_lock In the cgroup_path_ns
    function. 2.$cat /proc/<pid>/cpuset repeatly. 3.$mount -t cgroup -o cpuset cpuset /sys/fs/cgroup/cpuset/
    $umount /sys/fs/cgroup/cpuset/ repeatly. The race that cause this bug can be shown as below: (umount) |
    (cat /proc/<pid>/cpuset) css_release | proc_cpuset_show css_release_work_fn | css = task_get_css(tsk,
    cpuset_cgrp_id); css_free_rwork_fn | cgroup_path_ns(css->cgroup, ...); cgroup_destroy_root |
    mutex_lock(&cgroup_mutex); rebind_subsystems | cgroup_free_root | | // cgrp was freed, UAF |
    cgroup_path_ns_locked(cgrp,..); When the cpuset is initialized, the root node top_cpuset.css.cgrp will
    point to &cgrp_dfl_root.cgrp. In cgroup v1, the mount operation will allocate cgroup_root, and
    top_cpuset.css.cgrp will point to the allocated &cgroup_root.cgrp. When the umount operation is executed,
    top_cpuset.css.cgrp will be rebound to &cgrp_dfl_root.cgrp. The problem is that when rebinding to
    cgrp_dfl_root, there are cases where the cgroup_root allocated by setting up the root for cgroup v1 is
    cached. This could lead to a Use-After-Free (UAF) if it is subsequently freed. The descendant cgroups of
    cgroup v1 can only be freed after the css is released. However, the css of the root will never be
    released, yet the cgroup_root should be freed when it is unmounted. This means that obtaining a reference
    to the css of the root does not guarantee that css.cgrp->root will not be freed. Fix this problem by using
    rcu_read_lock in proc_cpuset_show(). As cgroup_root is kfree_rcu after commit d23b5c577715 (cgroup: Make
    operations on the cgroup root_list RCU safe), css->cgroup won't be freed during the critical section. To
    call cgroup_path_ns_locked, css_set_lock is needed, so it is safe to replace task_get_css with task_css.
    [1] https://syzkaller.appspot.com/bug?extid=9b1ff7be974a403aa4cd (CVE-2024-43853)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43853");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/17");
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
    "name": "linux-azure-fde",
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
    "name": "linux-azure-fde-5.15",
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
