#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:028
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14600);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");
  script_bugtraq_id(11081);

  script_name(english:"SUSE-SA:2004:028: kernel");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2004:028 (kernel).

Various signedness issues and integer overflows have been fixed within
kNFSd and the XDR decode functions of kernel 2.6.
These bugs can be triggered remotely by sending a package with a trusted
source IP address and a write request with a size greater then 2^31.
The result will be a kernel Oops, it is unknown if this bug is otherwise
exploitable yet.
Kernel 2.4 nfsd code is different but may suffer from the same
vulnerability.
Additionally a local denial-of-service condition via /dev/ptmx, which
affects kernel 2.6 only has been fixed. Thanks to Jan Engelhardt for
reporting this issue to us.");
  script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_28_kernel.html");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2004-2025 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/SuSE/rpm-list");

  exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-default-2.6.5-7.108", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.5-7.108", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.5-7.108", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.5-7.108", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.5-7.108", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
