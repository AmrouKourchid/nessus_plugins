#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224478);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2021-47506");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47506");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - nfsd: fix use-after-free due to delegation race A delegation break could arrive as soon as we've called
    vfs_setlease. A delegation break runs a callback which immediately (in nfsd4_cb_recall_prepare) adds the
    delegation to del_recall_lru. If we then exit nfs4_set_delegation without hashing the delegation, it will
    be freed as soon as the callback is done with it, without ever being removed from del_recall_lru. Symptoms
    show up later as use-after-free or list corruption warnings, usually in the laundromat thread. I suspect
    aba2072f4523 nfsd: grant read delegations to clients holding writes made this bug easier to hit, but I
    looked as far back as v3.0 and it looks to me it already had the same problem. So I'm not sure where the
    bug was introduced; it may have been there from the beginning. (CVE-2021-47506)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2021-47506");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/CVE-2021-47506");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47506");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
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
    "name": [
     "linux-aws",
     "linux-cloud-tools-3.13.0-24",
     "linux-cloud-tools-3.13.0-24-generic",
     "linux-cloud-tools-3.13.0-24-generic-lpae",
     "linux-cloud-tools-3.13.0-24-lowlatency",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-headers-3.13.0-24",
     "linux-headers-3.13.0-24-generic",
     "linux-headers-3.13.0-24-generic-lpae",
     "linux-headers-3.13.0-24-lowlatency",
     "linux-image-3.13.0-24-generic",
     "linux-image-3.13.0-24-generic-dbgsym",
     "linux-image-3.13.0-24-generic-lpae",
     "linux-image-3.13.0-24-generic-lpae-dbgsym",
     "linux-image-3.13.0-24-lowlatency",
     "linux-image-3.13.0-24-lowlatency-dbgsym",
     "linux-image-3.13.0-24-powerpc64-emb",
     "linux-image-extra-3.13.0-24-generic",
     "linux-image-extra-3.13.0-24-generic-lpae",
     "linux-image-extra-3.13.0-24-lowlatency",
     "linux-libc-dev",
     "linux-lts-xenial",
     "linux-source-3.13.0",
     "linux-tools-3.13.0-24",
     "linux-tools-3.13.0-24-generic",
     "linux-tools-3.13.0-24-generic-lpae",
     "linux-tools-3.13.0-24-lowlatency",
     "linux-tools-common",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-lowlatency"
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
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "14.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws",
     "linux-cloud-tools-4.4.0-21",
     "linux-cloud-tools-4.4.0-21-generic",
     "linux-cloud-tools-4.4.0-21-generic-lpae",
     "linux-cloud-tools-4.4.0-21-lowlatency",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-fips",
     "linux-headers-4.4.0-21",
     "linux-headers-4.4.0-21-generic",
     "linux-headers-4.4.0-21-generic-lpae",
     "linux-headers-4.4.0-21-lowlatency",
     "linux-image-4.4.0-21-generic",
     "linux-image-4.4.0-21-generic-dbgsym",
     "linux-image-4.4.0-21-generic-lpae",
     "linux-image-4.4.0-21-generic-lpae-dbgsym",
     "linux-image-4.4.0-21-lowlatency",
     "linux-image-4.4.0-21-lowlatency-dbgsym",
     "linux-image-4.4.0-21-powerpc-e500mc",
     "linux-image-extra-4.4.0-21-generic",
     "linux-image-extra-4.4.0-21-generic-lpae",
     "linux-image-extra-4.4.0-21-lowlatency",
     "linux-image-extra-4.4.0-21-powerpc-e500mc",
     "linux-kvm",
     "linux-libc-dev",
     "linux-source-4.4.0",
     "linux-tools-4.4.0-21",
     "linux-tools-4.4.0-21-generic",
     "linux-tools-4.4.0-21-generic-lpae",
     "linux-tools-4.4.0-21-lowlatency",
     "linux-tools-common",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-lowlatency"
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
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "16.04"
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
       "match": {
        "os_version": "8"
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
