#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2022 Jacques Vidrine and contributors
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
  script_id(128135);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/01");

  script_cve_id("CVE-2019-9512", "CVE-2019-9514", "CVE-2019-9515");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"FreeBSD : h2o -- multiple HTTP/2 vulnerabilities (72a5579e-c765-11e9-8052-0028f8d09152) (Ping Flood) (Reset Flood) (Settings Flood)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Jonathon Loomey of Netflix reports :

HTTP/2 implementations do not robustly handle abnormal traffic and
resource exhaustion

Recently, a series of DoS attack vulnerabilities have been reported on
a broad range of HTTP/2 stacks. Among the vulnerabilities, H2O is
exposed to the following :

- CVE-2019-9512 'Ping Flood': The attacker sends continual pings to an
HTTP/2 peer, causing the peer to build an internal queue of responses.
Depending on how efficiently this data is queued, this can consume
excess CPU, memory, or both, potentially leading to a denial of
service.

- CVE-2019-9514 'Reset Flood': The attacker opens a number of streams
and sends an invalid request over each stream that should solicit a
stream of RST_STREAM frames from the peer. Depending on how the peer
queues the RST_STREAM frames, this can consume excess memory, CPU, or
both, potentially leading to a denial of service.

- CVE-2019-9515 'Settings Flood': The attacker sends a stream of
SETTINGS frames to the peer. Since the RFC requires that the peer
reply with one acknowledgement per SETTINGS frame, an empty SETTINGS
frame is almost equivalent in behavior to a ping. Depending on how
efficiently this data is queued, this can consume excess CPU, memory,
or both, potentially leading to a denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/h2o/h2o/issues/2090");
  script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/605641/");
  # https://vuxml.freebsd.org/freebsd/72a5579e-c765-11e9-8052-0028f8d09152.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d11da2f");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9515");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:h2o-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"h2o-devel<2.3.0.b2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
