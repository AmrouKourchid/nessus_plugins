#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('compat.inc');

if (description)
{
  script_id(206690);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/26");

  script_cve_id("CVE-2024-8178", "CVE-2024-42416", "CVE-2024-43110");
  script_xref(name:"IAVA", value:"2024-A-0545-S");

  script_name(english:"FreeBSD : FreeBSD -- Multiple issues in ctl(4) CAM Target Layer (9bd5e47b-6b50-11ef-9a62-002590c1f29c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 9bd5e47b-6b50-11ef-9a62-002590c1f29c advisory.

    Several vulnerabilities were found in the ctl subsystem.
    The function ctl_write_buffer incorrectly set a flag which resulted
            in a kernel Use-After-Free when a command finished processing
            (CVE-2024-45063).  The ctl_write_buffer and ctl_read_buffer functions
            allocated memory to be returned to userspace, without initializing
            it (CVE-2024-8178).  The ctl_report_supported_opcodes function did
            not sufficiently validate a field provided by userspace, allowing
            an arbitrary write to a limited amount of kernel help memory
            (CVE-2024-42416).  The ctl_request_sense function could expose up
            to three bytes of the kernel heap to userspace (CVE-2024-43110).
    Guest virtual machines in the bhyve hypervisor can send SCSI commands
            to the corresponding kernel driver via the virtio_scsi interface.
            This provides guests with direct access to the vulnerabilities
            covered by this advisory.
    The CAM Target Layer iSCSI target daemon ctld(8) accepts incoming
            iSCSI connections, performs authentication and passes connections
            to the kernel ctl(4) target layer.
    Malicious software running in a guest VM that exposes virtio_scsi
            can exploit the vulnerabilities to achieve code execution on the
            host in the bhyve userspace process, which typically runs as root.
            Note that bhyve runs in a Capsicum sandbox, so malicious code is
            constrained by the capabilities available to the bhyve process.
    A malicious iSCSI initiator could achieve remote code execution on
            the iSCSI target host.

Tenable has extracted the preceding description block directly from the FreeBSD security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://vuxml.freebsd.org/freebsd/9bd5e47b-6b50-11ef-9a62-002590c1f29c.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52cebf51");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8178");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:FreeBSD-kernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Settings/ParanoidReport", "Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var flag = 0;

var packages = [
    'FreeBSD>=13.3<13.3_6',
    'FreeBSD>=14.0<14.0_10',
    'FreeBSD>=14.1<14.1_4'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
