#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-02.
# The text itself is copyright (C) Mozilla Foundation.

include('compat.inc');

if (description)
{
  script_id(132711);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/01");

  script_cve_id(
    "CVE-2019-17015",
    "CVE-2019-17016",
    "CVE-2019-17017",
    "CVE-2019-17021",
    "CVE-2019-17022",
    "CVE-2019-17024"
  );
  script_xref(name:"MFSA", value:"2020-02");

  script_name(english:"Mozilla Firefox ESR < 68.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 68.4. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2020-02 advisory.

  - During the initialization of a new content process, a
    pointer offset can be manipulated leading to memory
    corruption and a potentially exploitable crash in the
    parent process. Note: this issue only occurs on
    Windows. Other operating systems are unaffected.
    (CVE-2019-17015)

  - When pasting a <style> tag from the
    clipboard into a rich text editor, the CSS sanitizer
    incorrectly rewrites a @namespace rule. This could allow
    for injection into certain types of websites resulting
    in data exfiltration. (CVE-2019-17016)

  - Due to a missing case handling object types, a type
    confusion vulnerability could occur, resulting in a
    crash. We presume that with enough effort that it could
    be exploited to run arbitrary code. (CVE-2019-17017)

  - During the initialization of a new content process, a
    race condition occurs that can allow a content process
    to disclose heap addresses from the parent process.
    Note: this issue only occurs on Windows. Other
    operating systems are unaffected. (CVE-2019-17021)

  - When pasting a <style> tag from the
    clipboard into a rich text editor, the CSS sanitizer
    does not escape < and > characters. Because the
    resulting string is pasted directly into the text node
    of the element this does not result in a direct
    injection into the webpage; however, if a webpage
    subsequently copies the node's innerHTML, assigning it
    to another innerHTML, this would result in an XSS
    vulnerability. Two WYSIWYG editors were identified with
    this behavior, more may exist. (CVE-2019-17022)

  - Mozilla developers Jason Kratzer, Christian Holler, and
    Bob Clary reported memory safety bugs present in Firefox
    71 and Firefox ESR 68.3. Some of these bugs showed
    evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to
    run arbitrary code. (CVE-2019-17024)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-02/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 68.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17024");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'68.4', min:'68.0.0', xss:TRUE, severity:SECURITY_WARNING);


