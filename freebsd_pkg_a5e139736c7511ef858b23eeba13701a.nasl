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
  script_id(206743);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/07");

  script_cve_id("CVE-2024-43788");

  script_name(english:"FreeBSD : forgejo -- multiple vulnerabilities (a5e13973-6c75-11ef-858b-23eeba13701a)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the a5e13973-6c75-11ef-858b-23eeba13701a advisory.

  - Webpack is a module bundler. Its main purpose is to bundle JavaScript files for usage in a browser, yet it
    is also capable of transforming, bundling, or packaging just about any resource or asset. The webpack
    developers have discovered a DOM Clobbering vulnerability in Webpack's `AutoPublicPathRuntimeModule`. The
    DOM Clobbering gadget in the module can lead to cross-site scripting (XSS) in web pages where scriptless
    attacker-controlled HTML elements (e.g., an `img` tag with an unsanitized `name` attribute) are present.
    Real-world exploitation of this gadget has been observed in the Canvas LMS which allows a XSS attack to
    happen through a javascript code compiled by Webpack (the vulnerable part is from Webpack). DOM Clobbering
    is a type of code-reuse attack where the attacker first embeds a piece of non-script, seemingly benign
    HTML markups in the webpage (e.g. through a post or comment) and leverages the gadgets (pieces of js code)
    living in the existing javascript code to transform it into executable code. This vulnerability can lead
    to cross-site scripting (XSS) on websites that include Webpack-generated files and allow users to inject
    certain scriptless HTML tags with improperly sanitized name or id attributes. This issue has been
    addressed in release version 5.94.0. All users are advised to upgrade. There are no known workarounds for
    this issue. (CVE-2024-43788)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://codeberg.org/forgejo/forgejo/milestone/8231");
  # https://vuxml.freebsd.org/freebsd/a5e13973-6c75-11ef-858b-23eeba13701a.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d8e6dc2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:forgejo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:forgejo7");
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
    'forgejo7<7.0.9',
    'forgejo<8.0.3'
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
