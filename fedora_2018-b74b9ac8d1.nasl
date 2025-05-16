#%NASL_MIN_LEVEL 70300
##
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-b74b9ac8d1.
#
# @DEPRECATED@
#
# Disabled on 2025/04/23. The only referenced CVE is listed as rejected in NVD
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120729);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/30");

  script_cve_id("CVE-2018-19387");
  script_xref(name:"FEDORA", value:"2018-b74b9ac8d1");

  script_name(english:"Fedora 28 : tmux (2018-b74b9ac8d1) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"- fixes rhbz #1652128 and #1652127 - CVE-2018-19387

  - tmux: NULL pointer Dereference in format_cb_pane_tabs in
    format.c

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.

This plugin has been deprecated. The only referenced CVE is listed as rejected in NVD.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-b74b9ac8d1");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tmux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}

exit(0, 'This plugin has been deprecated. The only referenced CVE is listed as rejected in NVD.');
