# XUIB v8 DATA tree and keyframes

The authored native reader accepts an external ordered class schema, decodes
inheritance-level presence masks, inline and shared property lists, nested
compound values, indexed properties, named frame slices, children and typed
animation channels. A timeline resolves its target to an element index while
retaining duplicate-target diagnostics. KEYD flags and extra fields are
retained; the decoder does not assume their interpolation semantics. CUST
references are offsets, not ordinal indices; geometry interpretation remains
a separate concern. The reader rejects unknown classes, malformed references,
unconsumed DATA bytes and count mismatches rather than creating placeholder
elements.

Format evidence: XUIHelper at c0d083036c6b0e3cdec5a3df0abfca0e58973117
(https://github.com/SGCSam/XUIHelper), and the independently documented
Metro format in https://github.com/Trinculo54/XB360_DASH at
90360fb41934574fe731559cfbde7e75ede8f498. No reference implementation or
schema is vendored; the optional audit consumes the pinned external XML
as read-only input. Its original licensing is unchanged. The schema
compiler retains declaration order and reads the 17559 extension list.

Run the original audit after building:

    python tools/verify_xui_tree.py build/native/x360_xui_tree_probe PATH_TO_V8 --strict

The CI discovery run reports incomplete coverage explicitly. It checks
resource digests and decoded image identity, counts parsed scenes, and
reports candidate header-counter disagreements separately. It does not
claim a functioning dashboard or renderer.
