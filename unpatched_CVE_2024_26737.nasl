#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227873);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26737");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26737");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Fix racing between
    bpf_timer_cancel_and_free and bpf_timer_cancel The following race is possible between
    bpf_timer_cancel_and_free and bpf_timer_cancel. It will lead a UAF on the timer->timer.
    bpf_timer_cancel(); spin_lock(); t = timer->time; spin_unlock(); bpf_timer_cancel_and_free(); spin_lock();
    t = timer->timer; timer->timer = NULL; spin_unlock(); hrtimer_cancel(&t->timer); kfree(t); /* UAF on t */
    hrtimer_cancel(&t->timer); In bpf_timer_cancel_and_free, this patch frees the timer->timer after a rcu
    grace period. This requires a rcu_head addition to the struct bpf_hrtimer. Another kfree(t) happens in
    bpf_timer_init, this does not need a kfree_rcu because it is still under the spin_lock and timer->timer
    has not been visible by others yet. In bpf_timer_cancel, rcu_read_lock() is added because this helper can
    be used in a non rcu critical section context (e.g. from a sleepable bpf prog). Other timer->timer usages
    in helpers.c have been audited, bpf_timer_cancel() is the only place where timer->timer is used outside of
    the spin_lock. Another solution considered is to mark a t->flag in bpf_timer_cancel and clear it after
    hrtimer_cancel() is done. In bpf_timer_cancel_and_free, it busy waits for the flag to be cleared before
    kfree(t). This patch goes with a straight forward solution and frees timer->timer after a rcu grace
    period. (CVE-2024-26737)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
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
