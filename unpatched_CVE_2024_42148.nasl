#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228676);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42148");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42148");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bnx2x: Fix multiple UBSAN array-index-
    out-of-bounds Fix UBSAN warnings that occur when using a system with 32 physical cpu cores or more, or
    when the user defines a number of Ethernet queues greater than or equal to FP_SB_MAX_E1x using the
    num_queues module parameter. Currently there is a read/write out of bounds that occurs on the array
    struct stats_query_entry query present inside the bnx2x_fw_stats_req struct in
    drivers/net/ethernet/broadcom/bnx2x/bnx2x.h. Looking at the definition of the struct stats_query_entry
    query array: struct stats_query_entry query[FP_SB_MAX_E1x+ BNX2X_FIRST_QUEUE_QUERY_IDX]; FP_SB_MAX_E1x is
    defined as the maximum number of fast path interrupts and has a value of 16, while
    BNX2X_FIRST_QUEUE_QUERY_IDX has a value of 3 meaning the array has a total size of 19. Since accesses to
    struct stats_query_entry query are offset-ted by BNX2X_FIRST_QUEUE_QUERY_IDX, that means that the total
    number of Ethernet queues should not exceed FP_SB_MAX_E1x (16). However one of these queues is reserved
    for FCOE and thus the number of Ethernet queues should be set to [FP_SB_MAX_E1x -1] (15) if FCOE is
    enabled or [FP_SB_MAX_E1x] (16) if it is not. This is also described in a comment in the source code in
    drivers/net/ethernet/broadcom/bnx2x/bnx2x.h just above the Macro definition of FP_SB_MAX_E1x. Below is the
    part of this explanation that it important for this patch /* * The total number of L2 queues, MSIX vectors
    and HW contexts (CIDs) is * control by the number of fast-path status blocks supported by the * device
    (HW/FW). Each fast-path status block (FP-SB) aka non-default * status block represents an independent
    interrupts context that can * serve a regular L2 networking queue. However special L2 queues such * as the
    FCoE queue do not require a FP-SB and other components like * the CNIC may consume FP-SB reducing the
    number of possible L2 queues * * If the maximum number of FP-SB available is X then: * a. If CNIC is
    supported it consumes 1 FP-SB thus the max number of * regular L2 queues is Y=X-1 * b. In MF mode the
    actual number of L2 queues is Y= (X-1/MF_factor) * c. If the FCoE L2 queue is supported the actual number
    of L2 queues * is Y+1 * d. The number of irqs (MSIX vectors) is either Y+1 (one extra for * slow-path
    interrupts) or Y+2 if CNIC is supported (one additional * FP interrupt context for the CNIC). * e. The
    number of HW context (CID count) is always X or X+1 if FCoE * L2 queue is supported. The cid for the FCoE
    L2 queue is always X. */ However this driver also supports NICs that use the E2 controller which can
    handle more queues due to having more FP-SB represented by FP_SB_MAX_E2. Looking at the commits when the
    E2 support was added, it was originally using the E1x parameters: commit f2e0899f0f27 (bnx2x: Add 57712
    support). Back then FP_SB_MAX_E2 was set to 16 the same as E1x. However the driver was later updated to
    take full advantage of the E2 instead of having it be limited to the capabilities of the E1x. But as far
    as we can tell, the array stats_query_entry query was still limited to using the FP-SB available to the
    E1x cards as part of an oversignt when the driver was updated to take full advantage of the E2, and now
    with the driver being aware of the greater queue size supported by E2 NICs, it causes the UBSAN warnings
    seen in the stack traces below. This patch increases the size of the stats_query_entry query array by
    replacing FP_SB_MAX_E1x with FP_SB_MAX_E2 to be large enough to handle both types of NICs. Stack traces:
    UBSAN: array-index-out-of-bounds in drivers/net/ethernet/broadcom/bnx2x/bnx2x_stats.c:1529:11 index 20 is
    out of range for type 'stats_query_entry [19]' CPU: 12 PID: 858 Comm: systemd-network Not tainted
    6.9.0-060900rc7-generic #202405052133 Hardware name: HP ProLiant DL360 Gen9/ProLiant DL360 ---truncated---
    (CVE-2024-42148)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42148");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/30");
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
