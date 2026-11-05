# Security

Please report a vulnerability through GitHub's private vulnerability reporting
(the repository's Security tab), not in a public issue.

This package parses data from devices on the local network, where a camera,
or anything pretending to be one, can send it malformed frames. Those should
end in an error: a panic or unbounded memory use on such input is a bug worth
reporting.
