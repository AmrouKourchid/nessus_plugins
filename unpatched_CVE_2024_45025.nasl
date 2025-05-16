#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228672);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-45025");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-45025");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: fix bitmap corruption on close_range()
    with CLOSE_RANGE_UNSHARE copy_fd_bitmaps(new, old, count) is expected to copy the first
    count/BITS_PER_LONG bits from old->full_fds_bits[] and fill the rest with zeroes. What it does is copying
    enough words (BITS_TO_LONGS(count/BITS_PER_LONG)), then memsets the rest. That works fine, *if* all bits
    past the cutoff point are clear. Otherwise we are risking garbage from the last word we'd copied. For most
    of the callers that is true - expand_fdtable() has count equal to old->max_fds, so there's no open
    descriptors past count, let alone fully occupied words in ->open_fds[], which is what bits in
    ->full_fds_bits[] correspond to. The other caller (dup_fd()) passes sane_fdtable_size(old_fdt, max_fds),
    which is the smallest multiple of BITS_PER_LONG that covers all opened descriptors below max_fds. In the
    common case (copying on fork()) max_fds is ~0U, so all opened descriptors will be below it and we are
    fine, by the same reasons why the call in expand_fdtable() is safe. Unfortunately, there is a case where
    max_fds is less than that and where we might, indeed, end up with junk in ->full_fds_bits[] -
    close_range(from, to, CLOSE_RANGE_UNSHARE) with * descriptor table being currently shared * 'to' being
    above the current capacity of descriptor table * 'from' being just under some chunk of opened descriptors.
    In that case we end up with observably wrong behaviour - e.g. spawn a child with CLONE_FILES, get all
    descriptors in range 0..127 open, then close_range(64, ~0U, CLOSE_RANGE_UNSHARE) and watch dup(0) ending
    up with descriptor #128, despite #64 being observably not open. The minimally invasive fix would be to
    deal with that in dup_fd(). If this proves to add measurable overhead, we can go that way, but let's try
    to fix copy_fd_bitmaps() first. * new helper: bitmap_copy_and_expand(to, from, bits_to_copy, size). * make
    copy_fd_bitmaps() take the bitmap size in words, rather than bits; it's 'count' argument is always a
    multiple of BITS_PER_LONG, so we are not losing any information, and that way we can use the same helper
    for all three bitmaps - compiler will see that count is a multiple of BITS_PER_LONG for the large ones, so
    it'll generate plain memcpy()+memset(). Reproducer added to
    tools/testing/selftests/core/close_range_test.c (CVE-2024-45025)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45025");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/11");
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
