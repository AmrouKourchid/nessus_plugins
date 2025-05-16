#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227724);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26868");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26868");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: nfs: fix panic when
    nfs4_ff_layout_prepare_ds() fails We've been seeing the following panic in production BUG: kernel NULL
    pointer dereference, address: 0000000000000065 PGD 2f485f067 P4D 2f485f067 PUD 2cc5d8067 PMD 0 RIP:
    0010:ff_layout_cancel_io+0x3a/0x90 [nfs_layout_flexfiles] Call Trace: <TASK> ? __die+0x78/0xc0 ?
    page_fault_oops+0x286/0x380 ? __rpc_execute+0x2c3/0x470 [sunrpc] ? rpc_new_task+0x42/0x1c0 [sunrpc] ?
    exc_page_fault+0x5d/0x110 ? asm_exc_page_fault+0x22/0x30 ? ff_layout_free_layoutreturn+0x110/0x110
    [nfs_layout_flexfiles] ? ff_layout_cancel_io+0x3a/0x90 [nfs_layout_flexfiles] ?
    ff_layout_cancel_io+0x6f/0x90 [nfs_layout_flexfiles] pnfs_mark_matching_lsegs_return+0x1b0/0x360 [nfsv4]
    pnfs_error_mark_layout_for_return+0x9e/0x110 [nfsv4] ? ff_layout_send_layouterror+0x50/0x160
    [nfs_layout_flexfiles] nfs4_ff_layout_prepare_ds+0x11f/0x290 [nfs_layout_flexfiles]
    ff_layout_pg_init_write+0xf0/0x1f0 [nfs_layout_flexfiles] __nfs_pageio_add_request+0x154/0x6c0 [nfs]
    nfs_pageio_add_request+0x26b/0x380 [nfs] nfs_do_writepage+0x111/0x1e0 [nfs]
    nfs_writepages_callback+0xf/0x30 [nfs] write_cache_pages+0x17f/0x380 ? nfs_pageio_init_write+0x50/0x50
    [nfs] ? nfs_writepages+0x6d/0x210 [nfs] ? nfs_writepages+0x6d/0x210 [nfs] nfs_writepages+0x125/0x210 [nfs]
    do_writepages+0x67/0x220 ? generic_perform_write+0x14b/0x210 filemap_fdatawrite_wbc+0x5b/0x80
    file_write_and_wait_range+0x6d/0xc0 nfs_file_fsync+0x81/0x170 [nfs] ? nfs_file_mmap+0x60/0x60 [nfs]
    __x64_sys_fsync+0x53/0x90 do_syscall_64+0x3d/0x90 entry_SYSCALL_64_after_hwframe+0x46/0xb0 Inspecting the
    core with drgn I was able to pull this >>> prog.crashed_thread().stack_trace()[0] #0 at 0xffffffffa079657a
    (ff_layout_cancel_io+0x3a/0x84) in ff_layout_cancel_io at fs/nfs/flexfilelayout/flexfilelayout.c:2021:27
    >>> prog.crashed_thread().stack_trace()[0]['idx'] (u32)1 >>>
    prog.crashed_thread().stack_trace()[0]['flseg'].mirror_array[1].mirror_ds (struct nfs4_ff_layout_ds
    *)0xffffffffffffffed This is clear from the stack trace, we call nfs4_ff_layout_prepare_ds() which could
    error out initializing the mirror_ds, and then we go to clean it all up and our check is only for if
    (!mirror->mirror_ds). This is inconsistent with the rest of the users of mirror_ds, which have if
    (IS_ERR_OR_NULL(mirror_ds)) to keep from tripping over this exact scenario. Fix this up in
    ff_layout_cancel_io() to make sure we don't panic when we get an error. I also spot checked all the other
    instances of checking mirror_ds and we appear to be doing the correct checks everywhere, only
    unconditionally dereferencing mirror_ds when we know it would be valid. (CVE-2024-26868)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26868");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
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
