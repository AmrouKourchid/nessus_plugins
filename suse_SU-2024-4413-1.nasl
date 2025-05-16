#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4413-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213380);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/24");

  script_cve_id("CVE-2022-48064");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4413-1");

  script_name(english:"SUSE SLES15 Security Update : gdb (SUSE-SU-2024:4413-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by a vulnerability as referenced
in the SUSE-SU-2024:4413-1 advisory.

    Mention changes in GDB 14:

    * GDB now supports the AArch64 Scalable Matrix Extension 2
      (SME2), which includes a new 512 bit lookup table register
      named ZT0.
    * GDB now supports the AArch64 Scalable Matrix Extension (SME),
      which includes a new matrix register named ZA, a new thread
      register TPIDR2 and a new vector length register SVG
      (streaming vector granule).  GDB also supports tracking ZA
      state across signal frames.  Some features are still under
      development or are dependent on ABI specs that are still in
      alpha stage.  For example, manual function calls with ZA state
      don't have any special handling, and tracking of SVG changes
      based on DWARF information is still not implemented, but there
      are plans to do so in the future.
    * GDB now recognizes the NO_COLOR environment variable and
      disables styling according to the spec.  See
      https://no-color.org/.  Styling can be re-enabled with
      'set style enabled on'.
    * The AArch64 'org.gnu.gdb.aarch64.pauth' Pointer Authentication
      feature string has been deprecated in favor of the
      'org.gnu.gdb.aarch64.pauth_v2' feature string.
    * GDB now has some support for integer types larger than 64 bits.
    * Multi-target feature configuration.
      GDB now supports the individual configuration of remote
      targets' feature sets.  Based on the current selection of a
      target, the commands 'set remote <name>-packet (on|off|auto)'
      and 'show remote <name>-packet' can be used to configure a
      target's feature packet and to display its configuration,
      respectively.
    * GDB has initial built-in support for the Debugger Adapter
      Protocol.
    * For the break command, multiple uses of the 'thread' or 'task'
      keywords will now give an error instead of just using the
      thread or task id from the last instance of the keyword.  E.g.:
        break foo thread 1 thread 2
      will now give an error rather than using 'thread 2'.
    * For the watch command, multiple uses of the 'task' keyword will
      now give an error instead of just using the task id from the
      last instance of the keyword.  E.g.:
        watch my_var task 1 task 2
      will now give an error rather than using 'task 2'.  The
      'thread' keyword already gave an error when used multiple times
      with the watch command, this remains unchanged.
    * The 'set print elements' setting now helps when printing large
      arrays.  If an array would otherwise exceed max-value-size, but
      'print elements' is set such that the size of elements to print
      is less than or equal to 'max-value-size', GDB will now still
      print the array, however only 'max-value-size' worth of data
      will be added into the value history.
    * For both the break and watch commands, it is now invalid to use
      both the 'thread' and 'task' keywords within the same command.
      For example the following commnds will now give an error:
        break foo thread 1 task 1
        watch var thread 2 task 3
    * The printf command now accepts a '%V' output format which will
      format an expression just as the 'print' command would.  Print
      options can be placed withing '[...]' after the '%V' to modify
      how the value is printed.  E.g:
        printf '%V', some_array
        printf '%V[-array-indexes on]', some_array
      will print the array without, or with array indexes included,
      just as the array would be printed by the 'print' command.
      This functionality is also available for dprintf when
      dprintf-style is 'gdb'.
    * When the printf command requires a string to be fetched from
      the   inferior, GDB now uses the existing 'max-value-size'
      setting to the limit the memory allocated within GDB.  The
      default 'max-value-size' is 64k.  To print longer strings you
      should increase 'max-value-size'.
    * The Ada 2022 Enum_Rep and Enum_Val attributes are now
      supported.
    * The Ada 2022 target name symbol ('@') is now supported by the
      Ada expression parser.
    * The 'list' command now accepts '.' as an argument, which tells
      GDB to print the location around the point of execution within
      the current frame.  If the inferior hasn't started yet, the
      command will print around the beginning of the 'main' function.
    * Using the 'list' command with no arguments in a situation where
      the command would attempt to list past the end of the file now
      warns the user that the end of file has been reached, refers
      the user to the newly added '.' argument
    * Breakpoints can now be inferior-specific.  This is similar to
      the   existing thread-specific breakpoint support.  Breakpoint
      conditions can include the 'inferior' keyword followed by an
      inferior id (as displayed in the 'info inferiors' output).
      It is invalid to use the 'inferior' keyword with either the
      'thread' or 'task' keywords when creating a breakpoint.
    * New convenience function '$_shell', to execute a shell command
      and return the result.  This lets you run shell commands in
      expressions.  Some examples:
       (gdb) p $_shell('true')
       $1 = 0
       (gdb) p $_shell('false')
       $2 = 1
       (gdb) break func if $_shell('some command') == 0
    * New commands:

      * set debug breakpoint on|off
        show debug breakpoint
        Print additional debug messages about breakpoint insertion
        and removal.
      * maintenance print record-instruction [ N ]
        Print the recorded information for a given instruction.  If N
        is not given prints how GDB would undo the last instruction
        executed.  If N is negative, prints how GDB would undo the
        N-th previous instruction, and if N is positive, it prints
        how GDB will redo the N-th following instruction.
      * maintenance info frame-unwinders
        List the frame unwinders currently in effect, starting with
        the highest priority.
      * maintenance wait-for-index-cache
        Wait until all pending writes to the index cache have
        completed.
      * set always-read-ctf on|off
        show always-read-ctf
        When off, CTF is only read if DWARF is not present.  When on,
        CTF is read regardless of whether DWARF is present.  Off by
        default.
      * info main
        Get main symbol to identify entry point into program.
      * set tui mouse-events [on|off]
        show tui mouse-events
        When on (default), mouse clicks control the TUI and can be
        accessed by Python extensions.  When off, mouse clicks are
        handled by the terminal, enabling terminal-native text
        selection.

    * MI changes:

      * MI version 1 has been removed.
      * mi now reports 'no-history' as a stop reason when hitting the
        end of the reverse execution history.
      * When creating a thread-specific breakpoint using the '-p'
        option, the -break-insert command would report the 'thread'
        field twice in the reply.  The content of both fields was
        always identical.  This has now been fixed; the 'thread'
        field will be reported just once for thread-specific
        breakpoints, or not at all for breakpoints without a thread
        restriction.  The same is also true for the 'task' field of
        an Ada task-specific breakpoint.
        * It is no longer possible to create a thread-specific
        breakpoint for a thread that doesn't exist using
        '-break-insert -p ID'.  Creating breakpoints for
        non-existent threads is not allowed when using the CLI, that
        the MI allowed it was a long standing bug, which has now
        been fixed.
      * The '--simple-values' argument to the
        '-stack-list-arguments','-stack-list-locals',
        '-stack-list-variables', and '-var-list-children' commands now
        takes reference types into account: that is, a value is now
        considered simple if it is neither an array, structure, or
        union, nor a reference to an array, structure, or union.
        (Previously all references were considered simple.)  Support
        for this feature can be verified by using the
        '-list-features' command, which should contain
        'simple-values-ref-types'.
      * The -break-insert command now accepts a '-g thread-group-id'
        option to allow for the creation of inferior-specific
        breakpoints.
      * The bkpt tuple, which appears in breakpoint-created
        notifications, and in the result of the -break-insert
        command can now include an optional 'inferior' field for both
        the main breakpoint, and each location, when the breakpoint
        is inferior-specific.

    * Python API:

      * gdb.ThreadExitedEvent added.  Emits a ThreadEvent.
      * The gdb.unwinder.Unwinder.name attribute is now read-only.
      * The name argument passed to gdb.unwinder.Unwinder.__init__
        must now be of type 'str' otherwise a TypeError will be
        raised.
      * The gdb.unwinder.Unwinder.enabled attribute can now only
        accept values of type 'bool'.  Changing this attribute will
        now invalidate GDB's frame-cache, which means GDB will need
        to rebuild its frame-cache when next required - either with,
        or without the particular unwinder, depending on how
        'enabled' was changed.
      * New methods added to the gdb.PendingFrame class.  These
        methods have the same behaviour as the corresponding
        methods on gdb.Frame.  The new methods are:
        * gdb.PendingFrame.name: Return the name for the frame's
          function, or None.
        * gdb.PendingFrame.is_valid: Return True if the pending
          frame object is valid.
        * gdb.PendingFrame.pc: Return the $pc register value for
          this frame.
        * gdb.PendingFrame.language: Return a string containing the
          language for this frame, or None.
        * gdb.PendingFrame.find_sal: Return a gdb.Symtab_and_line
          object for the current location within the pending frame,
          or None.
        * gdb.PendingFrame.block: Return a gdb.Block for the current
          pending frame, or None.
        * gdb.PendingFrame.function: Return a gdb.Symbol for the
          current pending frame, or None.
      * The frame-id passed to gdb.PendingFrame.create_unwind_info
        can now use either an integer or a gdb.Value object for each
        of its 'sp', 'pc', and 'special' attributes.
      * A new class gdb.unwinder.FrameId has been added.  Instances
        of this class are constructed with 'sp' (stack-pointer) and
        'pc' (program-counter) values, and can be used as the
        frame-id when calling gdb.PendingFrame.create_unwind_info.
      * It is now no longer possible to sub-class the
        gdb.disassembler.DisassemblerResult type.
      * The Disassembler API from the gdb.disassembler module has
        been extended to include styling support:
        * The DisassemblerResult class can now be initialized with a
          list of parts.  Each part represents part of the
          disassembled instruction along with the associated style
          information.  This list of parts can be accessed with the
          new DisassemblerResult.parts property.
        * New constants gdb.disassembler.STYLE_* representing all the
          different styles part of an instruction might have.
        * New methods DisassembleInfo.text_part and
          DisassembleInfo.address_part which are used to create the
          new styled parts of a disassembled instruction.
        * Changes are backwards compatible, the older API can still
          be used to disassemble instructions without styling.
      * New function gdb.execute_mi(COMMAND, [ARG]...), that invokes
        a GDB/MI command and returns the output as a Python
        dictionary.
      * New function gdb.block_signals().  This returns a context
        manager that blocks any signals that GDB needs to handle
        itself.
      * New class gdb.Thread.  This is a subclass of threading.Thread
        that calls gdb.block_signals in its 'start' method.
      * gdb.parse_and_eval now has a new 'global_context' parameter.
        This can be used to request that the parse only examine
        global symbols.
      * gdb.Inferior now has a new 'arguments' attribute.  This holds
        the command-line arguments to the inferior, if known.
      * gdb.Inferior now has a new 'main_name' attribute.  This holds
        the name of the inferior's 'main', if known.
      * gdb.Inferior now has new methods 'clear_env', 'set_env', and
        'unset_env'.  These can be used to modify the inferior's
        environment before it is started.
      * gdb.Value now has the 'assign' method.
      * gdb.Value now has the 'to_array' method.  This converts an
        array-like Value to an array.
      * gdb.Progspace now has the new method 'objfile_for_address'.
        This returns the gdb.Objfile, if any, that covers a given
        address.
      * gdb.Breakpoint now has an 'inferior' attribute.  If the
        Breakpoint object is inferior specific then this attribute
        holds the inferior-id (an integer).  If the Breakpoint
        object is not inferior specific, then this field contains
        None.  This field can be written too.
      * gdb.Type now has the 'is_array_like' and 'is_string_like'
        methods.  These reflect GDB's internal idea of whether a
        type might be array- or string-like, even if they do not
        have the corresponding type code.
      * gdb.ValuePrinter is a new class that can be used as the base
        class for the result of applying a pretty-printer.  As a
        base class, it signals to gdb that the printer may implement
        new pretty-printer methods.
      * New attribute Progspace.symbol_file.  This attribute holds
        the gdb.Objfile that corresponds to Progspace.filename (when
        Progspace.filename is not None), otherwise, this attribute is
        itself None.
      * New attribute Progspace.executable_filename.  This attribute
        holds a string containing a file name set by the 'exec-file'
        or 'file' commands, or None if no executable file is set.
        This isn't the exact string passed by the user to these
        commands; the file name will have been partially resolved to
        an absolute file name.
      * A new executable_changed event registry is available.  This
        event emits ExecutableChangedEvent objects, which have
        'progspace' (a gdb.Progspace) and 'reload' (a Boolean)
        attributes.  This event is emitted when
        gdb.Progspace.executable_filename changes.
      * New event registries gdb.events.new_progspace and
        gdb.events.free_progspace, these emit NewProgspaceEvent and
         FreeProgspaceEvent event types respectively.  Both of these
         event types have a single 'progspace' attribute, which is
         the gdb.Progspace that is either being added to GDB, or
         removed from GDB.
      * gdb.LazyString now implements the __str__ method.
      * New method gdb.Frame.static_link that returns the outer
       frame of a nested function frame.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220490");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-December/020048.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2885010f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48064");
  script_set_attribute(attribute:"solution", value:
"Update the affected gdb and / or gdbserver packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48064");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gdbserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP2/3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'gdb-14.2-150100.8.45.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'gdbserver-14.2-150100.8.45.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'gdb-14.2-150100.8.45.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'gdbserver-14.2-150100.8.45.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'gdb-14.2-150100.8.45.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'gdb-14.2-150100.8.45.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'gdbserver-14.2-150100.8.45.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'gdbserver-14.2-150100.8.45.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'gdb-14.2-150100.8.45.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'gdb-14.2-150100.8.45.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'gdbserver-14.2-150100.8.45.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'gdbserver-14.2-150100.8.45.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'gdb-14.2-150100.8.45.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'gdbserver-14.2-150100.8.45.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'gdb-14.2-150100.8.45.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'gdbserver-14.2-150100.8.45.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gdb / gdbserver');
}
