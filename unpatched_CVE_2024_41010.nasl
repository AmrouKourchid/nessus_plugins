#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228635);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41010");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41010");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Fix too early release of
    tcx_entry Pedro Pinto and later independently also Hyunwoo Kim and Wongi Lee reported an issue that the
    tcx_entry can be released too early leading to a use after free (UAF) when an active old-style ingress or
    clsact qdisc with a shared tc block is later replaced by another ingress or clsact instance. Essentially,
    the sequence to trigger the UAF (one example) can be as follows: 1. A network namespace is created 2. An
    ingress qdisc is created. This allocates a tcx_entry, and &tcx_entry->miniq is stored in the qdisc's
    miniqp->p_miniq. At the same time, a tcf block with index 1 is created. 3. chain0 is attached to the tcf
    block. chain0 must be connected to the block linked to the ingress qdisc to later reach the function
    tcf_chain0_head_change_cb_del() which triggers the UAF. 4. Create and graft a clsact qdisc. This causes
    the ingress qdisc created in step 1 to be removed, thus freeing the previously linked tcx_entry:
    rtnetlink_rcv_msg() => tc_modify_qdisc() => qdisc_create() => clsact_init() [a] => qdisc_graft() =>
    qdisc_destroy() => __qdisc_destroy() => ingress_destroy() [b] => tcx_entry_free() => kfree_rcu() //
    tcx_entry freed 5. Finally, the network namespace is closed. This registers the cleanup_net worker, and
    during the process of releasing the remaining clsact qdisc, it accesses the tcx_entry that was already
    freed in step 4, causing the UAF to occur: cleanup_net() => ops_exit_list() => default_device_exit_batch()
    => unregister_netdevice_many() => unregister_netdevice_many_notify() => dev_shutdown() => qdisc_put() =>
    clsact_destroy() [c] => tcf_block_put_ext() => tcf_chain0_head_change_cb_del() =>
    tcf_chain_head_change_item() => clsact_chain_head_change() => mini_qdisc_pair_swap() // UAF There are also
    other variants, the gist is to add an ingress (or clsact) qdisc with a specific shared block, then to
    replace that qdisc, waiting for the tcx_entry kfree_rcu() to be executed and subsequently accessing the
    current active qdisc's miniq one way or another. The correct fix is to turn the miniq_active boolean into
    a counter. What can be observed, at step 2 above, the counter transitions from 0->1, at step [a] from 1->2
    (in order for the miniq object to remain active during the replacement), then in [b] from 2->1 and finally
    [c] 1->0 with the eventual release. The reference counter in general ranges from [0,2] and it does not
    need to be atomic since all access to the counter is protected by the rtnl mutex. With this in place,
    there is no longer a UAF happening and the tcx_entry is freed at the correct time. (CVE-2024-41010)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41010");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/17");
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
