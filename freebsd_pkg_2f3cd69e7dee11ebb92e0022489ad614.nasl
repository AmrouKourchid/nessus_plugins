#
# (C) Tenable Network Security, Inc.
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
  script_id(147558);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/10");

  script_cve_id("CVE-2021-22883", "CVE-2021-22884", "CVE-2021-23840");
  script_xref(name:"IAVB", value:"2021-B-0012-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"FreeBSD : Node.js -- February 2021 Security Releases (2f3cd69e-7dee-11eb-b92e-0022489ad614)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"Node.js reports : HTTP2 'unknownProtocol' cause Denial of Service by
resource exhaustion (Critical) (CVE-2021-22883) Affected Node.js
versions are vulnerable to denial of service attacks when too many
connection attempts with an 'unknownProtocol' are established. This
leads to a leak of file descriptors. If a file descriptor limit is
configured on the system, then the server is unable to accept new
connections and prevent the process also from opening, e.g. a file. If
no file descriptor limit is configured, then this lead to an excessive
memory usage and cause the system to run out of memory. DNS rebinding
in --inspect (CVE-2021-22884) Affected Node.js versions are vulnerable
to a DNS rebinding attack when the whitelist includes 'localhost6'.
When 'localhost6' is not present in /etc/hosts, it is just an ordinary
domain that is resolved via DNS, i.e., over network. If the attacker
controls the victim's DNS server or can spoof its responses, the DNS
rebinding protection can be bypassed by using the 'localhost6' domain.
As long as the attacker uses the 'localhost6' domain, they can still
apply the attack described in CVE-2018-7160. OpenSSL - Integer
overflow in CipherUpdate (CVE-2021-23840) This is a vulnerability in
OpenSSL which may be exploited through Node.js. You can read more
about it in https://www.openssl.org/news/secadv/20210216.txt");
  # https://nodejs.org/en/blog/vulnerability/february-2021-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bac8db3");
  # https://vuxml.freebsd.org/freebsd/2f3cd69e-7dee-11eb-b92e-0022489ad614.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e8b2f72");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22884");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node14");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"node10<10.24.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node12<12.21.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node14<14.16.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node<15.10.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
