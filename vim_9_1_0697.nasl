#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206346);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/06");

  script_cve_id("CVE-2024-43802");
  script_xref(name:"IAVA", value:"2024-A-0526-S");

  script_name(english:"Vim < 9.1.0697 Heap Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"A text editor installed on the remote Windows host is affected by a heap buffer overflow vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Vim installed on the remote Windows host is prior to 9.1.0697. It is, therefore, affected by a heap
buffer overflow vulnerability. When flushing the typeahead buffer, Vim moves the current position in the typeahead
buffer but does not check whether there is enough space left in the buffer to handle the next characters. So this may
lead to the tb_off position within the typebuf variable to point outside of the valid buffer size, which can then later
lead to a heap-buffer overflow in e.g. ins_typebuf(). Therefore, when flushing the typeahead buffer, check if there is 
enough space left before advancing the off position. If not, fall back to flush current typebuf contents. It's not quite
clear yet, what can lead to this situation. It seems to happen when error messages occur (which will cause Vim to flush
the typeahead buffer) in comnination with several long mappgins and so it may eventually move the off position out of a
valid buffer size. Impact is low since it is not easily reproducible and requires to have several mappings active and
run into some error condition. But when this happens, this will cause a crash. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vim/vim/security/advisories/GHSA-4ghr-c62x-cqfh");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vim version 9.1.0697 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43802");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vim:vim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vim_win_installed.nbin");
  script_require_keys("installed_sw/Vim", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app = 'Vim';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'fixed_version':'9.1.0697'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
