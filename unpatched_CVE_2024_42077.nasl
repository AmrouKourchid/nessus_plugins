#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229519);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42077");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42077");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ocfs2: fix DIO failure due to
    insufficient transaction credits The code in ocfs2_dio_end_io_write() estimates number of necessary
    transaction credits using ocfs2_calc_extend_credits(). This however does not take into account that the IO
    could be arbitrarily large and can contain arbitrary number of extents. Extent tree manipulations do often
    extend the current transaction but not in all of the cases. For example if we have only single block
    extents in the tree, ocfs2_mark_extent_written() will end up calling ocfs2_replace_extent_rec() all the
    time and we will never extend the current transaction and eventually exhaust all the transaction credits
    if the IO contains many single block extents. Once that happens a
    WARN_ON(jbd2_handle_buffer_credits(handle) <= 0) is triggered in jbd2_journal_dirty_metadata() and
    subsequently OCFS2 aborts in response to this error. This was actually triggered by one of our customers
    on a heavily fragmented OCFS2 filesystem. To fix the issue make sure the transaction always has enough
    credits for one extent insert before each call of ocfs2_mark_extent_written(). Heming Zhao said: ------
    PANIC: Kernel panic - not syncing: OCFS2: (device dm-1): panic forced after error PID: xxx TASK: xxxx
    CPU: 5 COMMAND: SubmitThread-CA #0 machine_kexec at ffffffff8c069932 #1 __crash_kexec at
    ffffffff8c1338fa #2 panic at ffffffff8c1d69b9 #3 ocfs2_handle_error at ffffffffc0c86c0c [ocfs2] #4
    __ocfs2_abort at ffffffffc0c88387 [ocfs2] #5 ocfs2_journal_dirty at ffffffffc0c51e98 [ocfs2] #6
    ocfs2_split_extent at ffffffffc0c27ea3 [ocfs2] #7 ocfs2_change_extent_flag at ffffffffc0c28053 [ocfs2] #8
    ocfs2_mark_extent_written at ffffffffc0c28347 [ocfs2] #9 ocfs2_dio_end_io_write at ffffffffc0c2bef9
    [ocfs2] #10 ocfs2_dio_end_io at ffffffffc0c2c0f5 [ocfs2] #11 dio_complete at ffffffff8c2b9fa7 #12
    do_blockdev_direct_IO at ffffffff8c2bc09f #13 ocfs2_direct_IO at ffffffffc0c2b653 [ocfs2] #14
    generic_file_direct_write at ffffffff8c1dcf14 #15 __generic_file_write_iter at ffffffff8c1dd07b #16
    ocfs2_file_write_iter at ffffffffc0c49f1f [ocfs2] #17 aio_write at ffffffff8c2cc72e #18 kmem_cache_alloc
    at ffffffff8c248dde #19 do_io_submit at ffffffff8c2ccada #20 do_syscall_64 at ffffffff8c004984 #21
    entry_SYSCALL_64_after_hwframe at ffffffff8c8000ba (CVE-2024-42077)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42077");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-gkeop",
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
