#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227139);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52813");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52813");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: crypto: pcrypt - Fix hungtask for
    PADATA_RESET We found a hungtask bug in test_aead_vec_cfg as follows: INFO: task cryptomgr_test:391009
    blocked for more than 120 seconds. echo 0 > /proc/sys/kernel/hung_task_timeout_secs disables this
    message. Call trace: __switch_to+0x98/0xe0 __schedule+0x6c4/0xf40 schedule+0xd8/0x1b4
    schedule_timeout+0x474/0x560 wait_for_common+0x368/0x4e0 wait_for_completion+0x20/0x30
    wait_for_completion+0x20/0x30 test_aead_vec_cfg+0xab4/0xd50 test_aead+0x144/0x1f0 alg_test_aead+0xd8/0x1e0
    alg_test+0x634/0x890 cryptomgr_test+0x40/0x70 kthread+0x1e0/0x220 ret_from_fork+0x10/0x18 Kernel panic -
    not syncing: hung_task: blocked tasks For padata_do_parallel, when the return err is 0 or -EBUSY, it will
    call wait_for_completion(&wait->completion) in test_aead_vec_cfg. In normal case, aead_request_complete()
    will be called in pcrypt_aead_serial and the return err is 0 for padata_do_parallel. But, when
    pinst->flags is PADATA_RESET, the return err is -EBUSY for padata_do_parallel, and it won't call
    aead_request_complete(). Therefore, test_aead_vec_cfg will hung at wait_for_completion(&wait->completion),
    which will cause hungtask. The problem comes as following: (padata_do_parallel) | rcu_read_lock_bh(); |
    err = -EINVAL; | (padata_replace) | pinst->flags |= PADATA_RESET; err = -EBUSY | if (pinst->flags &
    PADATA_RESET) | rcu_read_unlock_bh() | return err In order to resolve the problem, we replace the return
    err -EBUSY with -EAGAIN, which means parallel_data is changing, and the caller should call it again. v3:
    remove retry and just change the return err. v2: introduce padata_try_do_parallel() in pcrypt_aead_encrypt
    and pcrypt_aead_decrypt to solve the hungtask. (CVE-2023-52813)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52813");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/13");
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
