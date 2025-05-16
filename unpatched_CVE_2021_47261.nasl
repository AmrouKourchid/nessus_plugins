#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224460);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47261");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47261");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: IB/mlx5: Fix initializing CQ fragments
    buffer The function init_cq_frag_buf() can be called to initialize the current CQ fragments buffer
    cq->buf, or the temporary cq->resize_buf that is filled during CQ resize operation. However, the offending
    commit started to use function get_cqe() for getting the CQEs, the issue with this change is that
    get_cqe() always returns CQEs from cq->buf, which leads us to initialize the wrong buffer, and in case of
    enlarging the CQ we try to access elements beyond the size of the current cq->buf and eventually hit a
    kernel panic. [exception RIP: init_cq_frag_buf+103] [ffff9f799ddcbcd8] mlx5_ib_resize_cq at
    ffffffffc0835d60 [mlx5_ib] [ffff9f799ddcbdb0] ib_resize_cq at ffffffffc05270df [ib_core]
    [ffff9f799ddcbdc0] llt_rdma_setup_qp at ffffffffc0a6a712 [llt] [ffff9f799ddcbe10] llt_rdma_cc_event_action
    at ffffffffc0a6b411 [llt] [ffff9f799ddcbe98] llt_rdma_client_conn_thread at ffffffffc0a6bb75 [llt]
    [ffff9f799ddcbec8] kthread at ffffffffa66c5da1 [ffff9f799ddcbf50] ret_from_fork_nospec_begin at
    ffffffffa6d95ddd Fix it by getting the needed CQE by calling mlx5_frag_buf_get_wqe() that takes the
    correct source buffer as a parameter. (CVE-2021-47261)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47261");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
