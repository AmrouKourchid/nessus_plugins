#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
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
  script_id(136942);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2020-10030", "CVE-2020-10995", "CVE-2020-12244");

  script_name(english:"FreeBSD : powerdns-recursor -- multiple vulnerabilities (f9c5a410-9b4e-11ea-ac3f-6805ca2fa271)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"PowerDNS Team reports :

CVE-2020-10995: An issue in the DNS protocol has been found that allow
malicious parties to use recursive DNS services to attack third party
authoritative name servers. The attack uses a crafted reply by an
authoritative name server to amplify the resulting traffic between the
recursive and other authoritative name servers. Both types of service
can suffer degraded performance as an effect.

CVE-2020-12244: An issue has been found in PowerDNS Recursor 4.1.0
through 4.3.0 where records in the answer section of a NXDOMAIN
response lacking an SOA were not properly validated in
SyncRes::processAnswer. This would allow an attacker in position of
man-in-the-middle to send a NXDOMAIN answer for a name that does
exist, bypassing DNSSEC validation.

CVE-2020-10030: An issue has been found in PowerDNS Authoritative
Server allowing an attacker with enough privileges to change the
system's hostname to cause disclosure of uninitialized memory content
via a stack-based out-of-bounds read. It only occurs on systems where
gethostname() does not null-terminate the returned string if the
hostname is larger than the supplied buffer. Linux systems are not
affected because the buffer is always large enough. OpenBSD systems
are not affected because the returned hostname is always
null-terminated. Under some conditions this issue can lead to the
writing of one null-byte out-of-bounds on the stack, causing a denial
of service or possibly arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://doc.powerdns.com/recursor/security-advisories/index.html");
  # https://vuxml.freebsd.org/freebsd/f9c5a410-9b4e-11ea-ac3f-6805ca2fa271.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72d79f2a");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10030");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:powerdns-recursor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"powerdns-recursor>=4.3.0<4.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"powerdns-recursor>=4.2.0<4.2.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"powerdns-recursor>=4.1.0<4.1.16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
