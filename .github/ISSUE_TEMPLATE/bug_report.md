---
name: Bug Report
about: Report a bug or unexpected behavior in @oneunit/auth
title: "[BUG] "
labels: ["bug"]
assignees: ""

---

## Describe the bug

A clear and concise description of what the bug is.

## Steps to reproduce

1. ...
2. ...
3. ...

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened.

## Environment

- **Package version**: `@oneunit/auth@x.y.z` (run `npm list @oneunit/auth`)
- **Node version**: `node --version` output
- **OS**: e.g. macOS 15, Ubuntu 24.04, Windows 11
- **Framework/adapter**: Express, Fastify, Koa, uWebSockets.js, or none
- **Persistence backend**: in-memory, Redis, PostgreSQL, or other

## Code sample

Provide a minimal, reproducible example:

```javascript
import { createAuth } from "@oneunit/auth";

const auth = createAuth({
    secret: "replace-with-secret",
});

async function repro() {
    // Your code here
}

repro().catch(console.error);
```

## Error output

Paste any error message, stack trace, or logs:

```
<paste error or stack trace here>
```

## Additional context

Add any other context about the problem here (e.g. adapter used, storage backend, OAuth provider, custom error handlers).

## Checklist

- [ ] I have read the [README](https://github.com/oneunitjs/auth/blob/main/README.md)
- [ ] I have checked existing issues for duplicates
- [ ] I am using the latest version of `@oneunit/auth`
- [ ] I have provided a minimal reproduction
