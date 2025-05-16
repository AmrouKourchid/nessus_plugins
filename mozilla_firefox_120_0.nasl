#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-49.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(186030);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/22");

  script_cve_id(
    "CVE-2023-6204",
    "CVE-2023-6205",
    "CVE-2023-6206",
    "CVE-2023-6207",
    "CVE-2023-6208",
    "CVE-2023-6209",
    "CVE-2023-6210",
    "CVE-2023-6211",
    "CVE-2023-6212",
    "CVE-2023-6213"
  );
  script_xref(name:"IAVA", value:"2023-A-0654-S");

  script_name(english:"Mozilla Firefox < 120.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 120.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2023-49 advisory.

  - On some systemsdepending on the graphics settings and driversit was possible to force an out-of-bounds
    read and leak memory data into the images created on the canvas element. (CVE-2023-6204)

  - It was possible to cause the use of a MessagePort after it had already been freed, which could potentially
    have led to an exploitable crash. (CVE-2023-6205)

  - The black fade animation when exiting fullscreen is roughly the length of the anti-clickjacking delay on
    permission prompts. It was possible to use this fact to surprise users by luring them to click where the
    permission grant button would be about to appear. (CVE-2023-6206)

  - Ownership mismanagement led to a use-after-free in ReadableByteStreams (CVE-2023-6207)

  - When using X11, text selected by the page using the Selection API was erroneously copied into the primary
    selection, a temporary storage not unlike the clipboard. This bug only affects Firefox on X11. Other
    systems are unaffected. (CVE-2023-6208)

  - Relative URLs starting with three slashes were incorrectly parsed, and a path-traversal /../ part in the
    path could be used to override the specified host. This could contribute to security problems in web
    sites. (CVE-2023-6209)

  - When an https: web page created a pop-up from a javascript: URL, that pop-up was incorrectly allowed to
    load blockable content such as iframes from insecure http: URLs (CVE-2023-6210)

  - If an attacker needed a user to load an insecure http: page and knew that user had enabled HTTPS-only
    mode, the attacker could have tricked the user into clicking to grant an HTTPS-only exception if they
    could get the user to participate in a clicking game. (CVE-2023-6211)

  - Memory safety bugs present in Firefox 119, Firefox ESR 115.4, and Thunderbird 115.4. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2023-6212)

  - Memory safety bugs present in Firefox 119. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2023-6213)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-49/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 120.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'120.0', severity:SECURITY_HOLE);
