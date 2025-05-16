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
  script_id(189105);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/29");

  script_cve_id(
    "CVE-2023-6816",
    "CVE-2024-0229",
    "CVE-2024-21885",
    "CVE-2024-21886"
  );

  script_name(english:"FreeBSD : xorg server -- Multiple vulnerabilities (7467c611-b490-11ee-b903-001fc69cd6dc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 7467c611-b490-11ee-b903-001fc69cd6dc advisory.

  - The X.Org project reports: Both DeviceFocusEvent and the XIQueryPointer reply contain a bit
    for each logical button currently down. Buttons can be arbitrarily             mapped to any value up to
    255 but the X.Org Server was only             allocating space for the device's number of buttons,
    leading to a heap overflow if a bigger value was used. If a device has both a button class and a key class
    and             numButtons is zero, we can get an out-of-bounds write due             to event under-
    allocation in the DeliverStateNotifyEvent             function. The XISendDeviceHierarchyEvent() function
    allocates space to             store up to MAXDEVICES (256) xXIHierarchyInfo structures in info.
    If a device with a given ID was removed and a new device with             the same ID added both in the
    same operation,             the single device ID will lead to two info structures being
    written to info.             Since this case can occur for every device ID at once,             a total of
    two times MAXDEVICES info structures might be written             to the allocation, leading to a heap
    buffer overflow. The DisableDevice() function is called whenever an enabled device             is disabled
    and it moves the device from the inputInfo.devices             linked list to the inputInfo.off_devices
    linked list.             However, its link/unlink operation has an issue during the recursive
    call to DisableDevice() due to the prev pointer pointing to a             removed device.             This
    issue leads to a length mismatch between the total number of             devices and the number of device
    in the list, leading to a heap             overflow and, possibly, to local privilege escalation.
    (CVE-2023-6816, CVE-2024-0229, CVE-2024-21885, CVE-2024-21886)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.x.org/archives/xorg/2024-January/061525.html");
  # https://vuxml.freebsd.org/freebsd/7467c611-b490-11ee-b903-001fc69cd6dc.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3eaf1fee");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6816");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/17");

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
    'xephyr<21.1.11,1',
    'xorg-nextserver<21.1.11,2',
    'xorg-server<21.1.11,1',
    'xorg-vfbserver<21.1.11,1',
    'xwayland-devel<21.0.99.1.653',
    'xwayland<23.2.4'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
