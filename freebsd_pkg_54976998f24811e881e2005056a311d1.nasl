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
  script_id(119246);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/24");

  script_cve_id(
    "CVE-2018-14629",
    "CVE-2018-16841",
    "CVE-2018-16851",
    "CVE-2018-16852",
    "CVE-2018-16853",
    "CVE-2018-16857"
  );

  script_name(english:"FreeBSD : samba -- multiple vulnerabilities (54976998-f248-11e8-81e2-005056a311d1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"The samba project reports :

All versions of Samba from 4.0.0 onwards are vulnerable to infinite
query recursion caused by CNAME loops. Any dns record can be added via
ldap by an unprivileged user using the ldbadd tool, so this is a
security issue.

When configured to accept smart-card authentication, Samba's KDC will
call talloc_free() twice on the same memory if the principal in a
validly signed certificate does not match the principal in the AS-REQ.

During the processing of an LDAP search before Samba's AD DC returns
the LDAP entries to the client, the entries are cached in a single
memory object with a maximum size of 256MB. When this size is reached,
the Samba process providing the LDAP service will follow the NULL
pointer, terminating the process.

During the processing of an DNS zone in the DNS management DCE/RPC
server, the internal DNS server or the Samba DLZ plugin for BIND9, if
the DSPROPERTY_ZONE_MASTER_SERVERS property or
DSPROPERTY_ZONE_SCAVENGING_SERVERS property is set, the server will
follow a NULL pointer and terminate

A user in a Samba AD domain can crash the KDC when Samba is built in
the non-default MIT Kerberos configuration.

AD DC Configurations watching for bad passwords (to restrict brute
forcing of passwords) in a window of more than 3 minutes may not watch
for bad passwords at all.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-14629.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-16841.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-16851.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-16852.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-16853.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-16857.html");
  # https://vuxml.freebsd.org/freebsd/54976998-f248-11e8-81e2-005056a311d1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec8b9b49");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16857");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba46");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba47");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba49");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"samba46<=4.6.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba47<4.7.12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba48<4.8.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba49<4.9.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
