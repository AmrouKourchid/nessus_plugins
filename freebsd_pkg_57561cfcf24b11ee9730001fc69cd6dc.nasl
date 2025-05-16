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
  script_id(192924);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/11");

  script_cve_id("CVE-2024-31080", "CVE-2024-31081", "CVE-2024-31083");

  script_name(english:"FreeBSD : xorg server -- Multiple vulnerabilities (57561cfc-f24b-11ee-9730-001fc69cd6dc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 57561cfc-f24b-11ee-9730-001fc69cd6dc advisory.

  - A heap-based buffer over-read vulnerability was found in the X.org server's ProcXIGetSelectedEvents()
    function. This issue occurs when byte-swapped length values are used in replies, potentially leading to
    memory leakage and segmentation faults, particularly when triggered by a client with a different
    endianness. This vulnerability could be exploited by an attacker to cause the X server to read heap memory
    values and then transmit them back to the client until encountering an unmapped page, resulting in a
    crash. Despite the attacker's inability to control the specific memory copied into the replies, the small
    length values typically stored in a 32-bit integer can result in significant attempted out-of-bounds
    reads. (CVE-2024-31080)

  - A heap-based buffer over-read vulnerability was found in the X.org server's ProcXIPassiveGrabDevice()
    function. This issue occurs when byte-swapped length values are used in replies, potentially leading to
    memory leakage and segmentation faults, particularly when triggered by a client with a different
    endianness. This vulnerability could be exploited by an attacker to cause the X server to read heap memory
    values and then transmit them back to the client until encountering an unmapped page, resulting in a
    crash. Despite the attacker's inability to control the specific memory copied into the replies, the small
    length values typically stored in a 32-bit integer can result in significant attempted out-of-bounds
    reads. (CVE-2024-31081)

  - A use-after-free vulnerability was found in the ProcRenderAddGlyphs() function of Xorg servers. This issue
    occurs when AllocateGlyph() is called to store new glyphs sent by the client to the X server, potentially
    resulting in multiple entries pointing to the same non-refcounted glyphs. Consequently,
    ProcRenderAddGlyphs() may free a glyph, leading to a use-after-free scenario when the same glyph pointer
    is subsequently accessed. This flaw allows an authenticated attacker to execute arbitrary code on the
    system by sending a specially crafted request. (CVE-2024-31083)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.x.org/archives/xorg-announce/2024-April/003497.html");
  # https://vuxml.freebsd.org/freebsd/57561cfc-f24b-11ee-9730-001fc69cd6dc.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ca14604");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-31083");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xorg-nextserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xorg-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xorg-vfbserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xwayland-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'xephyr<21.1.12,1',
    'xorg-nextserver<21.1.12,2',
    'xorg-server<21.1.12,1',
    'xorg-vfbserver<21.1.12,1',
    'xwayland-devel<21.0.99.1.671_1',
    'xwayland-devel>=21.0.99.1.672<21.0.99.1.841_1',
    'xwayland<23.2.5'
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
