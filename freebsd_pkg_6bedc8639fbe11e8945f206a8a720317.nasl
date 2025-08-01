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
  script_id(111720);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/21");

  script_cve_id("CVE-2018-14526");

  script_name(english:"FreeBSD : wpa_supplicant -- unauthenticated encrypted EAPOL-Key data (6bedc863-9fbe-11e8-945f-206a8a720317)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"SO-AND-SO reports :

A vulnerability was found in how wpa_supplicant processes EAPOL-Key
frames. It is possible for an attacker to modify the frame in a way
that makes wpa_supplicant decrypt the Key Data field without requiring
a valid MIC value in the frame, i.e., without the frame being
authenticated. This has a potential issue in the case where WPA2/RSN
style of EAPOL-Key construction is used with TKIP negotiated as the
pairwise cipher. It should be noted that WPA2 is not supposed to be
used with TKIP as the pairwise cipher. Instead, CCMP is expected to be
used and with that pairwise cipher, this vulnerability is not
applicable in practice.

When TKIP is negotiated as the pairwise cipher, the EAPOL-Key Key Data
field is encrypted using RC4. This vulnerability allows
unauthenticated EAPOL-Key frames to be processed and due to the RC4
design, this makes it possible for an attacker to modify the plaintext
version of the Key Data field with bitwise XOR operations without
knowing the contents. This can be used to cause a denial of service
attack by modifying GTK/IGTK on the station (without the attacker
learning any of the keys) which would prevent the station from
accepting received group-addressed frames. Furthermore, this might be
abused by making wpa_supplicant act as a decryption oracle to try to
recover some of the Key Data payload (GTK/IGTK) to get knowledge of
the group encryption keys.

Full recovery of the group encryption keys requires multiple attempts
(128 connection attempts per octet) and each attempt results in
disconnection due to a failure to complete the 4-way handshake. These
failures can result in the AP/network getting disabled temporarily or
even permanently (requiring user action to re-enable) which may make
it impractical to perform the attack to recover the keys before the AP
has already changes the group keys. By default, wpa_supplicant is
enforcing at minimum a ten second wait time between each failed
connection attempt, i.e., over 20 minutes waiting to recover each
octet while hostapd AP implementation uses 10 minute default for GTK
rekeying when using TKIP. With such timing behavior, practical attack
would need large number of impacted stations to be trying to connect
to the same AP to be able to recover sufficient information from the
GTK to be able to determine the key before it gets changed.");
  script_set_attribute(attribute:"see_also", value:"https://w1.fi/security/2018-1/unauthenticated-eapol-key-decryption.txt");
  # http://www.freebsd.org/ports/portaudit/6bedc863-9fbe-11e8-945f-206a8a720317.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1eb1fc72");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14526");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wpa_supplicant");
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

if (pkg_test(save_report:TRUE, pkg:"wpa_supplicant<2.6_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:pkg_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
