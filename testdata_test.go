package cef_test

// Shared fixture constants reused across the cef_test package.

const (
	testMsgHelloWorld     = "hello world"
	testBackslashTrailing = `test\`
	testExtKeyReceiptTime = "rt"

	// Identity-pass fixtures for unescape_test.go: the unescape functions
	// must return these inputs unchanged because each contains an escape
	// sequence the respective mode treats as permissive pass-through.
	testHeaderUnknownEscape = `test\n kept`
	testExtUnknownEscape    = `test\x kept`
	testPipeNotEscaped      = "contains | pipe"
)
