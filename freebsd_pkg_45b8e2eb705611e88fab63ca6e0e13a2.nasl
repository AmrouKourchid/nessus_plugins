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

include('compat.inc');

if (description)
{
  script_id(110539);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/20");

  script_cve_id(
    "CVE-2018-1000168",
    "CVE-2018-7161",
    "CVE-2018-7162",
    "CVE-2018-7164",
    "CVE-2018-7167"
  );

  script_name(english:"FreeBSD : node.js -- multiple vulnerabilities (45b8e2eb-7056-11e8-8fab-63ca6e0e13a2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"Node.js reports : Denial of Service Vulnerability in HTTP/2
(CVE-2018-7161) All versions of 8.x and later are vulnerable and the
severity is HIGH. An attacker can cause a denial of service (DoS) by
causing a node server providing an http2 server to crash. This can be
accomplished by interacting with the http2 server in a manner that
triggers a cleanup bug where objects are used in native code after
they are no longer available. This has been addressed by updating the
http2 implementation. Thanks to Jordan Zebor at F5 Networks for
reporting this issue. Denial of Service, nghttp2 dependency
(CVE-2018-1000168) All versions of 9.x and later are vulnerable and
the severity is HIGH. Under certain conditions, a malicious client can
trigger an uninitialized read (and a subsequent segfault) by sending a
malformed ALTSVC frame. This has been addressed through an by updating
nghttp2. Denial of Service Vulnerability in TLS (CVE-2018-7162) All
versions of 9.x and later are vulnerable and the severity is HIGH. An
attacker can cause a denial of service (DoS) by causing a node process
which provides an http server supporting TLS server to crash. This can
be accomplished by sending duplicate/unexpected messages during the
handshake. This vulnerability has been addressed by updating the TLS
implementation. Thanks to Jordan Zebor at F5 Networks all of his help
investigating this issue with the Node.js team. Memory exhaustion DoS
on v9.x (CVE-2018-7164) Versions 9.7.0 and later are vulnerable and
the severity is MEDIUM. A bug introduced in 9.7.0 increases the memory
consumed when reading from the network into JavaScript using the
net.Socket object directly as a stream. An attacker could use this
cause a denial of service by sending tiny chunks of data in short
succession. This vulnerability was restored by reverting to the prior
behaviour. Calls to Buffer.fill() and/or Buffer.alloc() may hang
(CVE-2018-7167) Calling Buffer.fill() or Buffer.alloc() with some
parameters can lead to a hang which could result in a Denial of
Service. In order to address this vulnerability, the implementations
of Buffer.alloc() and Buffer.fill() were updated so that they zero
fill instead of hanging in these cases.");
  script_set_attribute(attribute:"see_also", value:"https://nodejs.org/en/blog/vulnerability/june-2018-security-releases/");
  script_set_attribute(attribute:"see_also", value:"https://nghttp2.org/blog/2018/04/12/nghttp2-v1-31-1/");
  # https://vuxml.freebsd.org/freebsd/45b8e2eb-7056-11e8-8fab-63ca6e0e13a2.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f75c71a");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7162");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-7167");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"node6<6.14.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node8<8.11.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node<10.4.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
