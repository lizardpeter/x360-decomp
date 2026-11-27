import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from aot_diagnostics import summarize

class DiagnosticsTests(unittest.TestCase):
    def test_grouped_report(self):
        r=summarize("""error === ANALYSIS ERRORS ===
error UnresolvedCall (1):
error 0x92345678 from 0x92456780: b target not in any function
error Millicode (1):
error 0x92345678 from 0x92456788: another error
error Total: 2 errors
Validation failed: 1 unresolved calls, 1 millicode errors
""")
        self.assertEqual(r["unresolved_branches"],[{"target":"92345678","site":"92456780"}])
        self.assertEqual(r["validation_totals"],[{"unresolved_calls":1,"millicode_errors":1}])
    def test_colored_compiler_and_linker_diagnostics(self):
        r=summarize("\x1b[1mC:/generated/metro_profile_mapping.hpp:86:44:\x1b[31m error:\x1b[0m invalid operands to binary expression\n"
                    "clang++: error: unable to execute command: Killed\n"
                    "ninja: build stopped: subcommand failed.\n")
        self.assertEqual(r["compiler_diagnostics"],[{"file":"metro_profile_mapping.hpp","line":86,"column":44,"cause":"invalid_operand"}])
        self.assertEqual(r["build_failures"],{"memory_exhaustion":1,"build_stopped":1})
if __name__=="__main__":unittest.main()
