#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234192);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2025-22015");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2025-22015");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - mm/migrate: fix shmem xarray update during migration A shmem folio can be either in page cache or in swap
    cache, but not at the same time. Namely, once it is in swap cache, folio->mapping should be NULL, and the
    folio is no longer in a shmem mapping. In __folio_migrate_mapping(), to determine the number of xarray
    entries to update, folio_test_swapbacked() is used, but that conflates shmem in page cache case and shmem
    in swap cache case. It leads to xarray multi-index entry corruption, since it turns a sibling entry to a
    normal entry during xas_store() (see [1] for a userspace reproduction). Fix it by only using
    folio_test_swapcache() to determine whether xarray is storing swap cache entries or not to choose the
    right number of xarray entries to update. [1] https://lore.kernel.org/linux-
    mm/Z8idPCkaJW1IChjT@casper.infradead.org/ Note: In __split_huge_page(), folio_test_anon() &&
    folio_test_swapcache() is used to get swap_cache address space, but that ignores the shmem folio in swap
    cache case. It could lead to NULL pointer dereferencing when a in-swap-cache shmem folio is split at
    __xa_store(), since !folio_test_anon() is true and folio->mapping is NULL. But fortunately, its caller
    split_huge_page_to_list_to_order() bails out early with EBUSY when folio->mapping is NULL. So no need to
    take care of it here. (CVE-2025-22015)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-22015");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22015");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

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
     "btrfs-modules-6.1.0-32-alpha-generic-di",
     "cdrom-core-modules-6.1.0-32-alpha-generic-di",
     "ext4-modules-6.1.0-32-alpha-generic-di",
     "fat-modules-6.1.0-32-alpha-generic-di",
     "isofs-modules-6.1.0-32-alpha-generic-di",
     "jfs-modules-6.1.0-32-alpha-generic-di",
     "kernel-image-6.1.0-32-alpha-generic-di",
     "linux-doc",
     "linux-doc-6.1",
     "linux-headers-6.1.0-32-common",
     "linux-headers-6.1.0-32-common-rt",
     "linux-source",
     "linux-source-6.1",
     "linux-support-6.1.0-32",
     "loop-modules-6.1.0-32-alpha-generic-di",
     "nic-modules-6.1.0-32-alpha-generic-di",
     "nic-shared-modules-6.1.0-32-alpha-generic-di",
     "nic-wireless-modules-6.1.0-32-alpha-generic-di",
     "pata-modules-6.1.0-32-alpha-generic-di",
     "ppp-modules-6.1.0-32-alpha-generic-di",
     "scsi-core-modules-6.1.0-32-alpha-generic-di",
     "scsi-modules-6.1.0-32-alpha-generic-di",
     "scsi-nic-modules-6.1.0-32-alpha-generic-di",
     "serial-modules-6.1.0-32-alpha-generic-di",
     "usb-serial-modules-6.1.0-32-alpha-generic-di",
     "xfs-modules-6.1.0-32-alpha-generic-di"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "12"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
