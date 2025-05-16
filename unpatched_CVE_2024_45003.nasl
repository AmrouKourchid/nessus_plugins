#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229526);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-45003");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-45003");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: vfs: Don't evict inode under the inode
    lru traversing context The inode reclaiming process(See function prune_icache_sb) collects all reclaimable
    inodes and mark them with I_FREEING flag at first, at that time, other processes will be stuck if they try
    getting these inodes (See function find_inode_fast), then the reclaiming process destroy the inodes by
    function dispose_list(). Some filesystems(eg. ext4 with ea_inode feature, ubifs with xattr) may do inode
    lookup in the inode evicting callback function, if the inode lookup is operated under the inode lru
    traversing context, deadlock problems may happen. Case 1: In function ext4_evict_inode(), the ea inode
    lookup could happen if ea_inode feature is enabled, the lookup process will be stuck under the evicting
    context like this: 1. File A has inode i_reg and an ea inode i_ea 2. getfattr(A, xattr_buf) // i_ea is
    added into lru // lru->i_ea 3. Then, following three processes running like this: PA PB echo 2 >
    /proc/sys/vm/drop_caches shrink_slab prune_dcache_sb // i_reg is added into lru, lru->i_ea->i_reg
    prune_icache_sb list_lru_walk_one inode_lru_isolate i_ea->i_state |= I_FREEING // set inode state
    inode_lru_isolate __iget(i_reg) spin_unlock(&i_reg->i_lock) spin_unlock(lru_lock) rm file A i_reg->nlink =
    0 iput(i_reg) // i_reg->nlink is 0, do evict ext4_evict_inode ext4_xattr_delete_inode
    ext4_xattr_inode_dec_ref_all ext4_xattr_inode_iget ext4_iget(i_ea->i_ino) iget_locked find_inode_fast
    __wait_on_freeing_inode(i_ea) ---- AA deadlock dispose_list // cannot be executed by prune_icache_sb
    wake_up_bit(&i_ea->i_state) Case 2: In deleted inode writing function ubifs_jnl_write_inode(), file
    deleting process holds BASEHD's wbuf->io_mutex while getting the xattr inode, which could race with inode
    reclaiming process(The reclaiming process could try locking BASEHD's wbuf->io_mutex in inode evicting
    function), then an ABBA deadlock problem would happen as following: 1. File A has inode ia and a
    xattr(with inode ixa), regular file B has inode ib and a xattr. 2. getfattr(A, xattr_buf) // ixa is added
    into lru // lru->ixa 3. Then, following three processes running like this: PA PB PC echo 2 >
    /proc/sys/vm/drop_caches shrink_slab prune_dcache_sb // ib and ia are added into lru, lru->ixa->ib->ia
    prune_icache_sb list_lru_walk_one inode_lru_isolate ixa->i_state |= I_FREEING // set inode state
    inode_lru_isolate __iget(ib) spin_unlock(&ib->i_lock) spin_unlock(lru_lock) rm file B ib->nlink = 0 rm
    file A iput(ia) ubifs_evict_inode(ia) ubifs_jnl_delete_inode(ia) ubifs_jnl_write_inode(ia)
    make_reservation(BASEHD) // Lock wbuf->io_mutex ubifs_iget(ixa->i_ino) iget_locked find_inode_fast
    __wait_on_freeing_inode(ixa) | iput(ib) // ib->nlink is 0, do evict | ubifs_evict_inode |
    ubifs_jnl_delete_inode(ib)  ubifs_jnl_write_inode ABBA deadlock -----make_reservation(BASEHD)
    dispose_list // cannot be executed by prune_icache_sb wake_up_bit(&ixa->i_state) Fix the possible deadlock
    by using new inode state flag I_LRU_ISOLATING to pin the inode in memory while inode_lru_isolate(
    ---truncated--- (CVE-2024-45003)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45003");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
