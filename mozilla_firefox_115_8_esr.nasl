#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-06.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(190766);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2024-1546",
    "CVE-2024-1547",
    "CVE-2024-1548",
    "CVE-2024-1549",
    "CVE-2024-1550",
    "CVE-2024-1551",
    "CVE-2024-1552",
    "CVE-2024-1553"
  );
  script_xref(name:"IAVA", value:"2024-A-0108-S");

  script_name(english:"Mozilla Firefox ESR < 115.8");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 115.8. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2024-06 advisory.

  - When storing and re-accessing data on a networking channel, the length of buffers may have been confused,
    resulting in an out-of-bounds memory read. (CVE-2024-1546)

  - Through a series of API calls and redirects, an attacker-controlled alert dialog could have been displayed
    on another website (with the victim website's URL shown). (CVE-2024-1547)

  - A website could have obscured the fullscreen notification by using a dropdown select input element. This
    could have led to user confusion and possible spoofing attacks. (CVE-2024-1548)

  - If a website set a large custom cursor, portions of the cursor could have overlapped with the permission
    dialog, potentially resulting in user confusion and unexpected granted permissions. (CVE-2024-1549)

  - A malicious website could have used a combination of exiting fullscreen mode and
    <code>requestPointerLock</code> to cause the user's mouse to be re-positioned unexpectedly, which could
    have led to user confusion and inadvertently granting permissions they did not intend to grant.
    (CVE-2024-1550)

  - Set-Cookie response headers were being incorrectly honored in multipart HTTP responses. If an attacker
    could control the Content-Type response header, as well as control part of the response body, they could
    inject Set-Cookie response headers that would have been honored by the browser. (CVE-2024-1551)

  - Incorrect code generation could have led to unexpected numeric conversions and potential undefined
    behavior.Note: This issue only affects 32-bit ARM devices. (CVE-2024-1552)

  - Memory safety bugs present in Firefox 122, Firefox ESR 115.7, and Thunderbird 115.7. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2024-1553)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-06/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 115.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1552");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'115.8', min:'115.0.0', severity:SECURITY_HOLE);
