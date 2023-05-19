[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-8d59dc4de5201274e310e4c54b9627a8934c3b88527886e3b421487c677d23eb.svg)](https://classroom.github.com/a/3HFQb64m)
# Content Addressable Storage Server

![Database](https://informationage-staging.s3.amazonaws.com/uploads/2022/10/AdobeStock_54409222-1568x1045.jpeg)

## Overview

Often web content is retrieved by its location.  For example a HTTP server might serve an `index.html` file.  The key used to find the file is the name `index.html`.  Content addressable storage (CAS) systems instead use the content itself as the key.  Specifically they use the digest of the content as the key.  In this assignment you will write an HTTP server that does simple CAS storage and retrieval.  The system will have some cryptographic agility since we will allow more than one digest to be used to retrieve data.

## Learning Objectives

- Write an HTTP server in Go
- Marshal JSON
- Use cryptographic digests to build a CAS system
- Use interfaces such as `io.Reader`, `io.Writer`, and `http.Handler`

## Requirements

- Support at least the following digests: "sha256", "sha384", "sha512", "sha512-224", "sha512-256"
- Since files can be large:
  - Do not store the contents of a file more than once on disk.  You many use symbolic links or hard links to give a file many names".
  - Do not store the entire contents of a file in memory for any length of time.
- HTTP servers in Go create a goroutine for each request.  The server must be able to handle multiple simultaneous requests.  For this assignment you are not allowed to use any Go synchronization primitives.  This means channels or the "sync" for forbidden.  However, some POSIX filesystems operations are atomic (e.g, move, delete, link) so you must use those carefully to implement the server.
- Support the following handlers:
  - `POST /blob` to upload a file.  The response must include `x-digest-<name of algorithm>` headers for each digest that the server instance is supporting.
  - `GET /blob/<name of algorithm>/<hex of digest>` will retrieve the file by digest.
  - `GET /stats` returns a JSON dictionary with fields
    - `Count` is the integer number of unique files stored
    - `Mean` is the population mean (average) size of the files
    - `Stddev` is the population standard deviation of the size of the files

- You code will be graded on completeness and form.
- You must only edit `pkg/cas/cas.go` and `cmd/cas/main.go`

- Do not use any library other than the Go standard library.
- The source code must compile with the most recent version of the Go compiler.
- The program must not panic under any circumstances.
- All tests (in GitHub) must pass, otherwise you will receive no credit on this assignment.
- Make sure your code is "gofmt'd".  See "gofmt" or better use "goimports" or better yet configure IDE to do this formatting on file save.

## Hints

- Consider using `http.ServeMux` to route endpoints
- Do not forget to read the entire HTTP request body and close the the body.
- If the digests of the `testdata` files do not match the values in the unit tests then your GIT installation changed the line endings.  You need to preserve UNIX style line endings.

## Submission

- Commit and push your working code to your GIT repository.
- Ensure all tests pass otherwise you will receive no credit.
