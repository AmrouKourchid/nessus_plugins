#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228524);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41009");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41009");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Fix overrunning reservations in
    ringbuf The BPF ring buffer internally is implemented as a power-of-2 sized circular buffer, with two
    logical and ever-increasing counters: consumer_pos is the consumer counter to show which logical position
    the consumer consumed the data, and producer_pos which is the producer counter denoting the amount of data
    reserved by all producers. Each time a record is reserved, the producer that owns the record will
    successfully advance producer counter. In user space each time a record is read, the consumer of the data
    advanced the consumer counter once it finished processing. Both counters are stored in separate pages so
    that from user space, the producer counter is read-only and the consumer counter is read-write. One aspect
    that simplifies and thus speeds up the implementation of both producers and consumers is how the data area
    is mapped twice contiguously back-to-back in the virtual memory, allowing to not take any special measures
    for samples that have to wrap around at the end of the circular buffer data area, because the next page
    after the last data page would be first data page again, and thus the sample will still appear completely
    contiguous in virtual memory. Each record has a struct bpf_ringbuf_hdr { u32 len; u32 pg_off; } header for
    book-keeping the length and offset, and is inaccessible to the BPF program. Helpers like
    bpf_ringbuf_reserve() return `(void *)hdr + BPF_RINGBUF_HDR_SZ` for the BPF program to use. Bing-Jhong and
    Muhammad reported that it is however possible to make a second allocated memory chunk overlapping with the
    first chunk and as a result, the BPF program is now able to edit first chunk's header. For example,
    consider the creation of a BPF_MAP_TYPE_RINGBUF map with size of 0x4000. Next, the consumer_pos is
    modified to 0x3000 /before/ a call to bpf_ringbuf_reserve() is made. This will allocate a chunk A, which
    is in [0x0,0x3008], and the BPF program is able to edit [0x8,0x3008]. Now, lets allocate a chunk B with
    size 0x3000. This will succeed because consumer_pos was edited ahead of time to pass the `new_prod_pos -
    cons_pos > rb->mask` check. Chunk B will be in range [0x3008,0x6010], and the BPF program is able to edit
    [0x3010,0x6010]. Due to the ring buffer memory layout mentioned earlier, the ranges [0x0,0x4000] and
    [0x4000,0x8000] point to the same data pages. This means that chunk B at [0x4000,0x4008] is chunk A's
    header. bpf_ringbuf_submit() / bpf_ringbuf_discard() use the header's pg_off to then locate the
    bpf_ringbuf itself via bpf_ringbuf_restore_from_rec(). Once chunk B modified chunk A's header, then
    bpf_ringbuf_commit() refers to the wrong page and could cause a crash. Fix it by calculating the oldest
    pending_pos and check whether the range from the oldest outstanding record to the newest would span beyond
    the ring buffer size. If that is the case, then reject the request. We've tested with the ring buffer
    benchmark in BPF selftests (./benchs/run_bench_ringbufs.sh) before/after the fix and while it seems a bit
    slower on some benchmarks, it is still not significantly enough to matter. (CVE-2024-41009)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41009");

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
