#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2018 Jacques Vidrine and contributors
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88817);
  script_version("2.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id("CVE-2015-7547");
  script_xref(name:"TRA", value:"TRA-2017-08");
  script_xref(name:"IAVA", value:"2016-A-0053-S");

  script_name(english:"FreeBSD : glibc -- getaddrinfo stack-based buffer overflow (2dd7e97e-d5e8-11e5-bcbd-bc5ff45d0f28)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"Fabio Olive Leite reports :

A stack-based buffer overflow was found in libresolv when invoked from
nss_dns, allowing specially crafted DNS responses to seize control of
EIP in the DNS client. The buffer overflow occurs in the functions
send_dg (send datagram) and send_vc (send TCP) for the NSS module
libnss_dns.so.2 when calling getaddrinfo with AF_UNSPEC family, or in
some cases AF_INET6 family. The use of AF_UNSPEC (or AF_INET6 in some
cases) triggers the low-level resolver code to send out two parallel
queries for A and AAAA. A mismanagement of the buffers used for those
queries could result in the response of a query writing beyond the
alloca allocated buffer created by __res_nquery.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=207272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2015-7547");
  script_set_attribute(attribute:"see_also", value:"https://blog.des.no/2016/02/freebsd-and-cve-2015-7547/");
  # https://security.googleblog.com/2016/02/cve-2015-7547-glibc-getaddrinfo-stack.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94dd3376");
  script_set_attribute(attribute:"see_also", value:"https://sourceware.org/ml/libc-alpha/2016-02/msg00416.html");
  # https://vuxml.freebsd.org/freebsd/2dd7e97e-d5e8-11e5-bcbd-bc5ff45d0f28.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a76ef5e");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2017-08");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux_base-c6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux_base-c6_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux_base-f10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"linux_base-c6<6.7_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux_base-c6_64<6.7_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux_base-f10>=0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
