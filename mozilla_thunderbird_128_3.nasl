#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-49.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(207985);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/14");

  script_cve_id(
    "CVE-2024-8900",
    "CVE-2024-9392",
    "CVE-2024-9393",
    "CVE-2024-9394",
    "CVE-2024-9396",
    "CVE-2024-9397",
    "CVE-2024-9398",
    "CVE-2024-9399",
    "CVE-2024-9400",
    "CVE-2024-9401",
    "CVE-2024-9402"
  );

  script_name(english:"Mozilla Thunderbird < 128.3");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 128.3. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2024-49 advisory.

  - A compromised content process could have allowed for the arbitrary loading of cross-origin pages.
    (CVE-2024-9392)

  - An attacker could, via a specially crafted multipart response, execute arbitrary JavaScript under the
    `resource://pdf.js` origin.  This could allow them to access cross-origin PDF content. This access is
    limited to same site documents by the Site Isolation feature on desktop clients, but full cross-origin
    access is possible on Android versions. (CVE-2024-9393)

  - An attacker could, via a specially crafted multipart response, execute arbitrary JavaScript under the
    `resource://devtools` origin.  This could allow them to access cross-origin JSON content. This access is
    limited to same site documents by the Site Isolation feature on desktop clients, but full cross-origin
    access is possible on Android versions. (CVE-2024-9394)

  - An attacker could write data to the user's clipboard, bypassing the user prompt, during a certain sequence
    of navigational events. (CVE-2024-8900)

  - It is currently unknown if this issue is exploitable but a condition may arise where the structured clone
    of certain objects could lead to memory corruption. (CVE-2024-9396)

  - A missing delay in directory upload UI could have made it possible for an attacker to trick a user into
    granting permission via clickjacking. (CVE-2024-9397)

  - By checking the result of calls to `window.open` with specifically set protocol handlers, an attacker
    could determine if the application which implements that protocol handler is installed. (CVE-2024-9398)

  - A website configured to initiate a specially crafted WebTransport session could crash the Thunderbird
    process leading to a denial of service condition. (CVE-2024-9399)

  - A potential memory corruption vulnerability could be triggered if an attacker had the ability to trigger
    an OOM at a specific moment during JIT compilation. (CVE-2024-9400)

  - Memory safety bugs present in Firefox 130, Firefox ESR 115.15, Firefox ESR 128.2, and Thunderbird 128.2.
    Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of
    these could have been exploited to run arbitrary code. (CVE-2024-9401)

  - Memory safety bugs present in Firefox 130, Firefox ESR 128.2, and Thunderbird 128.2. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2024-9402)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-49/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 128.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9394");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'128.3', severity:SECURITY_HOLE);
