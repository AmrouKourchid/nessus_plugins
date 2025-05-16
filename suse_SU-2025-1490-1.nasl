#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1490-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(235649);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1490-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : java-17-openjdk (SUSE-SU-2025:1490-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2025:1490-1 advisory.

    Update to upstream tag jdk-17.0.15+6 (April 2025 CPU)

    CVEs:

    + CVE-2025-21587: Fixed JSSE unauthorized access, deletion or modification of critical data (bsc#1241274)
    + CVE-2025-30691: Fixed Oracle Java SE Compiler Unauthorized Data Access (bsc#1241275)
    + CVE-2025-30698: Fixed Oracle Java 2D unauthorized data access and DoS (bsc#1241276)

    Changes:

        - JDK-6355567: AdobeMarkerSegment causes failure to read
          valid JPEG
        - JDK-8065099: [macos] javax/swing/PopupFactory/6276087/
          /NonOpaquePopupMenuTest.java fails: no background shine
          through
        - JDK-8179502: Enhance OCSP, CRL and Certificate Fetch
          Timeouts
        - JDK-8198237: [macos] Test java/awt/Frame/
          /ExceptionOnSetExtendedStateTest/
          /ExceptionOnSetExtendedStateTest.java fails
        - JDK-8198666: Many java/awt/Modal/OnTop/ test fails on mac
        - JDK-8208565: [TEST_BUG] javax/swing/PopupFactory/6276087/
          /NonOpaquePopupMenuTest.java throws NPE
        - JDK-8226933: [TEST_BUG]GTK L&F: There is no swatches or
          RGB tab in JColorChooser
        - JDK-8226938: [TEST_BUG]GTK L&F: There is no Details
          button in FileChooser Dialog
        - JDK-8266435: WBMPImageReader.read() should not truncate
          the input stream
        - JDK-8267893: Improve jtreg test failure handler do get
          native/mixed stack traces for cores and live processes
        - JDK-8270961: [TESTBUG] Move GotWrongOOMEException into
          vm.share.gc package
        - JDK-8274893: Update java.desktop classes to use
          try-with-resources
        - JDK-8276202: LogFileOutput.invalid_file_vm asserts when
          being executed from a read only working directory
        - JDK-8277240: java/awt/Graphics2D/ScaledTransform/
          /ScaledTransform.java dialog does not get disposed
        - JDK-8281234: The -protected option is not always checked
          in keytool and jarsigner
        - JDK-8282314: nsk/jvmti/SuspendThread/suspendthrd003 may
          leak memory
        - JDK-8283387: [macos] a11y : Screen magnifier does not
          show selected Tab
        - JDK-8283404: [macos] a11y : Screen magnifier does not
          show JMenu name
        - JDK-8283664: Remove jtreg tag manual=yesno for
          java/awt/print/PrinterJob/PrintTextTest.java
        - JDK-8286779: javax.crypto.CryptoPolicyParser#isConsistent
          always returns 'true'
        - JDK-8286875: ProgrammableUpcallHandler::on_entry/on_exit
          access thread fields from native
        - JDK-8290400: Must run exe installers in jpackage jtreg
          tests without UI
        - JDK-8292588: [macos] Multiscreen/MultiScreenLocationTest/
          /MultiScreenLocationTest.java: Robot.mouseMove test failed on
          Screen #0
        - JDK-8292704: sun/security/tools/jarsigner/compatibility/
          /Compatibility.java use wrong key size for EC
        + JDK-8292848: AWT_Mixing and TrayIcon tests fail on el8
          with hard-coded isOel7
        + JDK-8293345: SunPKCS11 provider checks on PKCS11
          Mechanism are problematic
        + JDK-8293412: Remove unnecessary java.security.egd
          overrides
        + JDK-8294067: [macOS] javax/swing/JComboBox/6559152/
          /bug6559152.java Cannot select an item from popup with the
          ENTER key.
        + JDK-8294316: SA core file support is broken on macosx-x64
          starting with macOS 12.x
        + JDK-8295087: Manual Test to Automated Test Conversion
        + JDK-8295176: some langtools test pollutes source tree
        + JDK-8296591: Signature benchmark
        + JDK-8296818: Enhance JMH tests
          java/security/Signatures.java
        + JDK-8299077: [REDO] JDK-4512626 Non-editable JTextArea
          provides no visual indication of keyboard focus
        + JDK-8299127: [REDO] JDK-8194048 Regression automated test
          '/open/test/jdk/javax/swing/text/DefaultCaret/HidingSelection/
          /HidingSelectionTest.java' fails
        + JDK-8299128: [REDO] JDK-8213562 Test javax/swing/text/
          /DefaultCaret/HidingSelection/MultiSelectionTest.java fails
        + JDK-8299739: HashedPasswordFileTest.java and ExceptionTest.java
          can fail with java.lang.NullPointerException
        + JDK-8299994: java/security/Policy/Root/Root.java fails
          when home directory is read-only
        + JDK-8301989: new
          javax.swing.text.DefaultCaret().setBlinkRate(N) results in NPE
        + JDK-8302111: Serialization considerations
        + JDK-8305853: java/text/Format/DateFormat/
          /DateFormatRegression.java fails with 'Uncaught exception
          thrown in test method Test4089106'
        + JDK-8306711: Improve diagnosis of `IntlTest` framework
        + JDK-8308341: JNI_GetCreatedJavaVMs returns a partially
          initialized JVM
        + JDK-8309171: Test vmTestbase/nsk/jvmti/scenarios/
          /jni_interception/JI05/ji05t001/TestDescription.java fails
          after JDK-8308341
        + JDK-8309231: ProblemList vmTestbase/nsk/jvmti/scenarios/
          /jni_interception/JI05/ji05t001/TestDescription.java
        + JDK-8309740: Expand timeout windows for tests in
          JDK-8179502
        + JDK-8309841: Jarsigner should print a warning if an entry
          is removed
        + JDK-8310234: Refactor Locale tests to use JUnit
        + JDK-8310629: java/security/cert/CertPathValidator/OCSP/
          /OCSPTimeout.java fails with RuntimeException: Server not ready
        + JDK-8311306: Test com/sun/management/ThreadMXBean/
          /ThreadCpuTimeArray.java failed: out of expected range
        + JDK-8311546: Certificate name constraints improperly
          validated with leading period
        + JDK-8311663: Additional refactoring of Locale tests to
          JUnit
        + JDK-8312416: Tests in Locale should have more descriptive
          names
        + JDK-8312518: [macos13] setFullScreenWindow() shows black
          screen on macOS 13 & above
        + JDK-8313633: [macOS] java/awt/dnd/NextDropActionTest/
          /NextDropActionTest.java fails with
          java.lang.RuntimeException: wrong next drop action!
        + JDK-8313710: jcmd: typo in the documentation of JFR.start
          and JFR.dump
        + JDK-8314225: SIGSEGV in JavaThread::is_lock_owned
        + JDK-8314610: hotspot can't compile with the latest of
          gtest because of <iomanip>
        + JDK-8314752: Use google test string comparison macros
        + JDK-8314909: tools/jpackage/windows/Win8282351Test.java
          fails with java.lang.AssertionError: Expected [0]. Actual
          [1618]:
        + JDK-8314975: JavadocTester should set source path if not
          specified
        + JDK-8315486: vmTestbase/nsk/jdwp/ThreadReference/
          /ForceEarlyReturn/forceEarlyReturn002/forceEarlyReturn002.java
          timed out
        + JDK-8315825: Open some swing tests
        + JDK-8315882: Open some swing tests 2
        + JDK-8315883: Open source several Swing JToolbar tests
        + JDK-8315952: Open source several Swing JToolbar JTooltip
          JTree tests
        + JDK-8316056: Open source several Swing JTree tests
        + JDK-8316146: Open some swing tests 4
        + JDK-8316149: Open source several Swing JTree JViewport
          KeyboardManager tests
        + JDK-8316218: Open some swing tests 5
        + JDK-8316371: Open some swing tests 6
        + JDK-8316559: Refactor some util/Calendar tests to JUnit
        + JDK-8316627: JViewport Test headless failure
        + JDK-8316696: Remove the testing base classes: IntlTest
          and CollatorTest
        + JDK-8317631: Refactor ChoiceFormat tests to use JUnit
        + JDK-8317636: Improve heap walking API tests to verify
          correctness of field indexes
        + JDK-8318442: java/net/httpclient/ManyRequests2.java fails
          intermittently on Linux
        + JDK-8319567: Update java/lang/invoke tests to support vm
          flags
        + JDK-8319568: Update java/lang/reflect/exeCallerAccessTest/
          /CallerAccessTest.java to accept vm flags
        + JDK-8319569: Several java/util tests should be updated to
          accept VM flags
        + JDK-8319647: Few java/lang/System/LoggerFinder/modules
          tests ignore vm flags
        + JDK-8319648: java/lang/SecurityManager tests ignore vm
          flags
        + JDK-8319672: Several classloader tests ignore VM flags
        + JDK-8319673: Few security tests ignore VM flags
        + JDK-8319676: A couple of jdk/modules/incubator/ tests
          ignore VM flags
        + JDK-8319677: Test jdk/internal/misc/VM/RuntimeArguments.java
          should be marked as flagless
        + JDK-8319818: Address GCC 13.2.0 warnings
          (stringop-overflow and dangling-pointer)
        + JDK-8320372: test/jdk/sun/security/x509/DNSName/
          /LeadingPeriod.java validity check failed
        + JDK-8320676: Manual printer tests have no Pass/Fail
          buttons, instructions close set 1
        + JDK-8320691: Timeout handler on Windows takes 2 hours to
          complete
        + JDK-8320714: java/util/Locale/LocaleProvidersRun.java and
          java/util/ResourceBundle/modules/visibility/
          /VisibilityTest.java timeout after passing
        + JDK-8320916: jdk/jfr/event/gc/stacktrace/
          /TestParallelMarkSweepAllocationPendingStackTrace.java failed
          with 'OutOfMemoryError: GC overhead limit exceeded'
        + JDK-8321818: vmTestbase/nsk/stress/strace/strace015.java
          failed with 'Cannot read the array length because '<local4>'
          is null'
        + JDK-8323196: jdk/jfr/api/consumer/filestream/TestOrdered.java
          failed with 'Events are not ordered! Reuse = false'
        + JDK-8324672: Update jdk/java/time/tck/java/time/TCKInstant.java
          now() to be more robust
        + JDK-8324807: Manual printer tests have no Pass/Fail
          buttons, instructions close set 2
        + JDK-8325024: java/security/cert/CertPathValidator/OCSP(
          /OCSPTimeout.java incorrect comment information
        + JDK-8325042: Remove unused JVMDITools test files
        + JDK-8325529: Remove unused imports from `ModuleGenerator`
          test file
        + JDK-8325659: Normalize Random usage by incubator vector
          tests
        + JDK-8325906: Problemlist vmTestbase/vm/mlvm/meth/stress/
          /compiler/deoptimize/Test.java#id1 until JDK-8320865 is fixed
        + JDK-8325908: Finish removal of IntlTest and CollatorTest
        + JDK-8325937: runtime/handshake/HandshakeDirectTest.java
          causes 'monitor end should be strictly below the frame pointer'
          assertion failure on AArch64
        + JDK-8326421: Add jtreg test for large arrayCopy disjoint
          case.
        + JDK-8326525: com/sun/tools/attach/BasicTests.java does
          not verify AgentLoadException case
        + JDK-8327098: GTest needs larger combination limit
        + JDK-8327476: Upgrade JLine to 3.26.1
        + JDK-8327505: Test com/sun/jmx/remote/
          /NotificationMarshalVersions/TestSerializationMismatch.java
          fails
        + JDK-8327857: Remove applet usage from JColorChooser tests
          Test4222508
        + JDK-8327859: Remove applet usage from JColorChooser tests
          Test4319113
        + JDK-8327986: ASAN reports use-after-free in
          DirectivesParserTest.empty_object_vm
        + JDK-8328005: Convert java/awt/im/JTextFieldTest.java
          applet test to main
        + JDK-8328085: C2: Use after free in
          PhaseChaitin::Register_Allocate()
        + JDK-8328121: Remove applet usage from JColorChooser tests
          Test4759306
        + JDK-8328130: Remove applet usage from JColorChooser tests
          Test4759934
        + JDK-8328185: Convert java/awt/image/MemoryLeakTest/
          /MemoryLeakTest.java applet test to main
        + JDK-8328227: Remove applet usage from JColorChooser tests
          Test4887836
        + JDK-8328368: Convert java/awt/image/multiresolution/
          /MultiDisplayTest/MultiDisplayTest.java applet test to main
        + JDK-8328370: Convert java/awt/print/Dialog/PrintApplet.java
          applet test to main
        + JDK-8328380: Remove applet usage from JColorChooser tests
          Test6348456
        + JDK-8328387: Convert java/awt/Frame/FrameStateTest/
          /FrameStateTest.html applet test to main
        + JDK-8328403: Remove applet usage from JColorChooser tests
          Test6977726
        + JDK-8328553: Get rid of JApplet in
          test/jdk/sanity/client/lib/SwingSet2/src/DemoModule.java
        + JDK-8328558: Convert javax/swing/JCheckBox/8032667/
          /bug8032667.java applet test to main
        + JDK-8328717: Convert javax/swing/JColorChooser/8065098/
          /bug8065098.java applet test to main
        + JDK-8328719: Convert java/awt/print/PageFormat/SetOrient.html
          applet test to main
        + JDK-8328730: Convert java/awt/print/bug8023392/bug8023392.html
          applet test to main
        + JDK-8328753: Open source few Undecorated Frame tests
        + JDK-8328819: Remove applet usage from JFileChooser tests
          bug6698013
        + JDK-8328827: Convert java/awt/print/PrinterJob/
          /PrinterDialogsModalityTest/PrinterDialogsModalityTest.html
          applet test to main
        + JDK-8329210: Delete Redundant Printer Dialog Modality Test
        + JDK-8329320: Simplify awt/print/PageFormat/NullPaper.java
          test
        + JDK-8329322: Convert PageFormat/Orient.java to use
          PassFailJFrame
        + JDK-8329692: Add more details to FrameStateTest.java test
          instructions
        + JDK-8330702: Update failure handler to don't generate
          Error message if cores actions are empty
        + JDK-8331153: JFR: Improve logging of
          jdk/jfr/api/consumer/filestream/TestOrdered.java
        + JDK-8331735: UpcallLinker::on_exit races with GC when
          copying frame anchor
        + JDK-8331959: Update PKCS#11 Cryptographic Token Interface
          to v3.1
        + JDK-8332158: [XWayland] test/jdk/java/awt/Mouse/
          /EnterExitEvents/ResizingFrameTest.java
        + JDK-8332917: failure_handler should execute gdb 'info
          threads' command on linux
        + JDK-8333360: PrintNullString.java doesn't use float
          arguments
        + JDK-8333391: Test com/sun/jdi/InterruptHangTest.java
          failed: Thread was never interrupted during sleep
        + JDK-8333403: Write a test to check various components
          events are triggered properly
        + JDK-8333427: langtools/tools/javac/newlines/NewLineTest.java
          is failing on Japanese Windows
        + JDK-8334305: Remove all code for  nsk.share.Log verbose
          mode
        + JDK-8334490: Normalize string with locale invariant
          `toLowerCase()`
        + JDK-8334777: Test javax/management/remote/mandatory/notif/
          /NotifReconnectDeadlockTest.java failed with
          NullPointerException
        + JDK-8335150: Test LogGeneratedClassesTest.java fails on
          rpmbuild mock enviroment
        + JDK-8335172: Add manual steps to run security/auth/callback/
          /TextCallbackHandler/Password.java test
        + JDK-8335789: [TESTBUG] XparColor.java test fails with
          Error. Parse Exception: Invalid or unrecognized bugid: @
        + JDK-8336012: Fix usages of jtreg-reserved properties
        + JDK-8336498: [macos] [build]: install-file macro may run
          into permission denied error
        + JDK-8336692: Redo fix for JDK-8284620
        + JDK-8336942: Improve test coverage for class loading
          elements with annotations of different retentions
        + JDK-8337222: gc/TestDisableExplicitGC.java fails due to
          unexpected CodeCache GC
        + JDK-8337494: Clarify JarInputStream behavior
        + JDK-8337692: Better TLS connection support
        + JDK-8337826: Improve logging in OCSPTimeout and
          SimpleOCSPResponder to help diagnose JDK-8309754
        + JDK-8337886: java/awt/Frame/MaximizeUndecoratedTest.java
          fails in OEL due to a slight color difference
        + JDK-8337951: Test sun/security/validator/samedn.sh
          CertificateNotYetValidException: NotBefore validation
        + JDK-8338100: C2: assert(!n_loop->is_member(get_loop(lca)))
          failed: control must not be back in the loop
        + JDK-8338426: Test java/nio/channels/Selector/WakeupNow.java
          failed
        + JDK-8338430: Improve compiler transformations
        + JDK-8338571: [TestBug] DefaultCloseOperation.java test
          not working as expected wrt instruction after JDK-8325851 fix
        + JDK-8338595: Add more linesize for MIME decoder in macro
          bench test Base64Decode
        + JDK-8338668: Test javax/swing/JFileChooser/8080628/
          /bug8080628.java doesn't test for GTK L&F
        + JDK-8339154: Cleanups and JUnit conversion of
          test/jdk/java/util/zip/Available.java
        + JDK-8339261: Logs truncated in test
          javax/net/ssl/DTLS/DTLSRehandshakeTest.java
        + JDK-8339356: Test javax/net/ssl/SSLSocket/Tls13PacketSize.java
          failed with java.net.SocketException: An established
          connection was aborted by the software in your host machine
        + JDK-8339524: Clean up a few ExtendedRobot tests
        + JDK-8339687: Rearrange reachabilityFence()s in
          jdk.test.lib.util.ForceGC
        + JDK-8339728: [Accessibility,Windows,JAWS] Bug in the
          getKeyChar method of the AccessBridge class
        + JDK-8339810: Clean up the code in sun.tools.jar.Main to
          properly close resources and use ZipFile during extract
        + JDK-8339883: Open source several AWT/2D related tests
        + JDK-8339902: Open source couple TextField related tests
        + JDK-8339943: Frame not disposed in
          java/awt/dnd/DropActionChangeTest.java
        + JDK-8340078: Open source several 2D tests
        + JDK-8340116: test/jdk/sun/security/tools/jarsigner/
          /PreserveRawManifestEntryAndDigest.java can fail due to regex
        + JDK-8340411: open source several 2D imaging tests
        + JDK-8340480: Bad copyright notices in changes from
          JDK-8339902
        + JDK-8340687: Open source closed frame tests #1
        + JDK-8340719: Open source AWT List tests
        + JDK-8340969: jdk/jfr/startupargs/TestStartDuration.java
          should be marked as flagless
        + JDK-8341037: Use standard layouts in
          DefaultFrameIconTest.java and MenuCrash.java
        + JDK-8341111: open source several AWT tests including menu
          shortcut tests
        + JDK-8341316: [macos] javax/swing/ProgressMonitor/
          /ProgressMonitorEscapeKeyPress.java fails sometimes in macos
        + JDK-8341412: Various test failures after JDK-8334305
        + JDK-8341424: GHA: Collect hs_errs from build time failures
        + JDK-8341453: java/awt/a11y/AccessibleJTableTest.java
          fails in some cases where the test tables are not visible
        + JDK-8341722: Fix some warnings as errors when building on
          Linux with toolchain clang
        + JDK-8341881: [REDO] java/nio/file/attribute/
          /BasicFileAttributeView/CreationTime.java#tmp fails on alinux3
        + JDK-8341978: Improve JButton/bug4490179.java
        + JDK-8341982: Simplify JButton/bug4323121.java
        + JDK-8342098: Write a test to compare the images
        + JDK-8342145: File libCreationTimeHelper.c compile fails
          on Alpine
        + JDK-8342270: Test sun/security/pkcs11/Provider/
          /RequiredMechCheck.java needs write access to src tree
        + JDK-8342498: Add test for Allocation elimination after
          use as alignment reference by SuperWord
        + JDK-8342508: Use latch in BasicMenuUI/bug4983388.java
          instead of delay
        + JDK-8342541: Exclude List/KeyEventsTest/KeyEventsTest.java
          from running on macOS
        + JDK-8342562: Enhance Deflater operations
        + JDK-8342602: Remove JButton/PressedButtonRightClickTest
          test
        + JDK-8342607: Enhance register printing on x86_64 platforms
        + JDK-8342609: jpackage test helper function incorrectly
          removes a directory instead of its contents only
        + JDK-8342634: javax/imageio/plugins/wbmp/
          /WBMPStreamTruncateTest.java creates temp file in src dir
        + JDK-8342635: javax/swing/JFileChooser/FileSystemView/
          /WindowsDefaultIconSizeTest.java creates tmp file in src dir
        + JDK-8342704: GHA: Report truncation is broken after
          JDK-8341424
        + JDK-8342811: java/net/httpclient/PlainProxyConnectionTest.java
          failed: Unexpected connection count: 5
        + JDK-8342858: Make target mac-jdk-bundle fails on chmod
          command
        + JDK-8342988: GHA: Build JTReg in single step
        + JDK-8343007: Enhance Buffered Image handling
        + JDK-8343100: Consolidate EmptyFolderTest and
          EmptyFolderPackageTest jpackage tests into single java file
        + JDK-8343101: Rework BasicTest.testTemp test cases
        + JDK-8343118: [TESTBUG] java/awt/PrintJob/PrintCheckboxTest/
          /PrintCheckboxManualTest.java fails with Error. Can't find
          HTML file PrintCheckboxManualTest.html
        + JDK-8343128: PassFailJFrame.java test result: Error. Bad
          action for script: build}
        + JDK-8343129: Disable unstable check of
          ThreadsListHandle.sanity_vm ThreadList values
        + JDK-8343178: Test BasicTest.java javac compile fails
          cannot find symbol
        + JDK-8343378: Exceptions in javax/management
          DeadLockTest.java do not cause test failure
        + JDK-8343491: javax/management/remote/mandatory/connection/
          /DeadLockTest.java failing with NoSuchObjectException: no such
          object in table
        + JDK-8343599: Kmem limit and max values swapped when
          printing container information
        + JDK-8343724: [PPC64] Disallow OptoScheduling
        + JDK-8343882: BasicAnnoTests doesn't handle multiple
          annotations at the same position
        + JDK-8344581: [TESTBUG] java/awt/Robot/
          /ScreenCaptureRobotTest.java failing on macOS
        + JDK-8344589: Update IANA Language Subtag Registry to
          Version 2024-11-19
        + JDK-8344646: The libjsig deprecation warning should go to
          stderr not stdout
        + JDK-8345296: AArch64: VM crashes with SIGILL when prctl
          is disallowed
        + JDK-8345368: java/io/File/createTempFile/SpecialTempFile.java
          fails on Windows Server 2025
        + JDK-8345371: Bump update version for OpenJDK: jdk-17.0.15
        + JDK-8345375: Improve debuggability of
          test/jdk/java/net/Socket/CloseAvailable.java
        + JDK-8345414: Google CAInterop test failures
        + JDK-8345468: test/jdk/javax/swing/JScrollBar/4865918/
          /bug4865918.java fails in ubuntu22.04
        + JDK-8346055: javax/swing/text/StyledEditorKit/4506788/
          /bug4506788.java fails in ubuntu22.04
        + JDK-8346324: javax/swing/JScrollBar/4865918/bug4865918.java
          fails in CI
        + JDK-8346587: Distrust TLS server certificates anchored by
          Camerfirma Root CAs
        + JDK-8346671: java/nio/file/Files/probeContentType/Basic.java
          fails on Windows 2025
        + JDK-8346828: javax/swing/JScrollBar/4865918/bug4865918.java
          still fails in CI
        + JDK-8346887: DrawFocusRect() may cause an assertion failure
        + JDK-8346908: Update JDK 17 javadoc man page
        + JDK-8346972: Test java/nio/channels/FileChannel/
          /LoopingTruncate.java fails sometimes with IOException: There
          is not enough space on the disk
        + JDK-8347424: Fix and rewrite
          sun/security/x509/DNSName/LeadingPeriod.java test
        + JDK-8347427: JTabbedPane/8134116/Bug8134116.java has no
          license header
        + JDK-8347740: java/io/File/createTempFile/SpecialTempFile.java
          failing
        + JDK-8347847: Enhance jar file support
        + JDK-8347965: (tz) Update Timezone Data to 2025a
        + JDK-8348625: [21u, 17u] Revert JDK-8185862 to restore old
          java.awt.headless behavior on Windows
        + JDK-8348675: TrayIcon tests fail in Ubuntu 24.10 Wayland
        + JDK-8349603: [21u, 17u, 11u] Update GHA JDKs after Jan/25
          updates
        + JDK-8352097: (tz) zone.tab update missed in 2025a backport
        + JDK-8353905: [17u] Remove designator
          DEFAULT_PROMOTED_VERSION_PRE=ea for release 17.0.15

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241276");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-May/020782.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49e4d75d");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-30691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-30698");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21587");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-17-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-17-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-17-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-17-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4/5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-legacy-release-15.6', 'sles-release-15.6']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-17-openjdk-javadoc-17.0.15.0-150400.3.54.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-17-openjdk-jmods-17.0.15.0-150400.3.54.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-17-openjdk-src-17.0.15.0-150400.3.54.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'java-17-openjdk-17.0.15.0-150400.3.54.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'java-17-openjdk-demo-17.0.15.0-150400.3.54.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'java-17-openjdk-devel-17.0.15.0-150400.3.54.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'java-17-openjdk-headless-17.0.15.0-150400.3.54.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-17-openjdk / java-17-openjdk-demo / java-17-openjdk-devel / etc');
}
