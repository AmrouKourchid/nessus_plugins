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
  script_id(232323);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id(
    "CVE-2025-26594",
    "CVE-2025-26595",
    "CVE-2025-26596",
    "CVE-2025-26597",
    "CVE-2025-26598",
    "CVE-2025-26599",
    "CVE-2025-26600",
    "CVE-2025-26601"
  );
  script_xref(name:"IAVA", value:"2025-A-0135");

  script_name(english:"FreeBSD : xorg server -- Multiple vulnerabilities (f4297478-fa62-11ef-b597-001fc69cd6dc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the f4297478-fa62-11ef-b597-001fc69cd6dc advisory.

    The X.Org project reports:
    The root cursor is referenced in the xserver as a global variable. If
                  a client manages to free the root cursor, the internal reference points
                  to freed memory and causes a use-after-free.
    The code in XkbVModMaskText() allocates a fixed sized buffer on the
                  stack and copies the names of the virtual modifiers to that buffer.
                  The code however fails to check the bounds of the buffer correctly and
                  would copy the data regardless of the size, which may lead to a buffer
                  overflow.
    The computation of the length in XkbSizeKeySyms() differs from what is
                  actually written in XkbWriteKeySyms(), which may lead to a heap based
                  buffer overflow.
    If XkbChangeTypesOfKey() is called with 0 group, it will resize the key
                  symbols table to 0 but leave the key actions unchanged.
                  If later, the same function is called with a non-zero value of groups,
                  this will cause a buffer overflow because the key actions are of the wrong
                  size.
    The function GetBarrierDevice() searches for the pointer device based on
                  its device id and returns the matching value, or supposedly NULL if no
                  match was found.
                  However the code will return the last element of the list if no matching
                  device id was found which can lead to out of bounds memory access.
    The function compCheckRedirect() may fail if it cannot allocate the backing
                  pixmap. In that case, compRedirectWindow() will return a BadAlloc error
                  without the validation of the window tree marked just before, which leaves
                  the validate data partly initialized, and the use of an uninitialized pointer
                  later.
    When a device is removed while still frozen, the events queued for that
                  device remain while the device itself is freed and replaying the events
                  will cause a use after free.
    When changing an alarm, the values of the change mask are evaluated one
                  after the other, changing the trigger values as requested and eventually,
                  SyncInitTrigger() is called.
                  If one of the changes triggers an error, the function will return early,
                  not adding the new sync object.
                  This can be used to cause a use after free when the alarm eventually
                  triggers.

Tenable has extracted the preceding description block directly from the FreeBSD security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.x.org/archives/xorg-announce/2025-February/003584.html");
  # https://vuxml.freebsd.org/freebsd/f4297478-fa62-11ef-b597-001fc69cd6dc.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c099d62b");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26601");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xorg-nextserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xorg-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xorg-vfbserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xwayland");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'xephyr<21.1.16,1',
    'xorg-nextserver<21.1.16,2',
    'xorg-server<21.1.16,1',
    'xorg-vfbserver<21.1.16,1',
    'xwayland<24.1.6'
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
