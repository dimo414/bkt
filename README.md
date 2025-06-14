# `bkt`

[![releases](https://img.shields.io/github/v/release/dimo414/bkt?sort=semver&logo=github)](https://github.com/dimo414/bkt/releases)
[![crates.io](https://img.shields.io/crates/v/bkt?logo=rust)](https://crates.io/crates/bkt)
[![docs.rs](https://img.shields.io/docsrs/bkt?label=docs.rs)](https://docs.rs/bkt)
[![build status](https://img.shields.io/github/actions/workflow/status/dimo414/bkt/rust.yml?branch=master)](https://github.com/dimo414/bkt/actions)
[![dependencies](https://img.shields.io/deps-rs/bkt/latest)](https://deps.rs/crate/bkt)
[![issues](https://img.shields.io/github/issues/dimo414/bkt)](https://github.com/dimo414/bkt/issues)
[![license](https://img.shields.io/github/license/dimo414/bkt)](https://github.com/dimo414/bkt/blob/master/LICENSE)

`bkt` (pronounced "bucket") is a subprocess caching utility written in Rust,
inspired by [bash-cache](https://github.com/dimo414/bash-cache).
Wrapping expensive process invocations with `bkt` allows callers to reuse recent
invocations without complicating their application logic. This can be useful in
shell prompts, interactive applications such as [`fzf`](#fzf), and long-running
programs that poll other processes.

`bkt` is available as a standalone binary as well as a
[Rust library](https://crates.io/crates/bkt). See https://docs.rs/bkt/ for
library documentation. This README covers the `bkt` binary.

## Installation

Run `cargo install bkt` to compile and install `bkt` locally. You will need to
[install `cargo`](https://doc.rust-lang.org/cargo/getting-started/installation.html)
if it's not already on your system.

Pre-compiled binaries for common platforms are attached to each
[release](https://github.com/dimo414/bkt/releases) (starting with 0.5). Please
open an issue or send a PR if you would like releases to include binaries for
additional platforms.

Package manager support is being tracked
[here](https://github.com/dimo414/bkt/issues/12); volunteers are welcome.

[![Packaging status](https://repology.org/badge/vertical-allrepos/bkt.svg?columns=3)](https://repology.org/project/bkt/versions)

## Usage

```
bkt --ttl=DURATION [--stale=DURATION] [--cwd] [--env=ENV ...] [--modtime=FILE ...] [--scope=SCOPE] [--discard-failures] [--warm|--force] -- <command>...
```

`bkt` is easy to start using - simply prefix the command you intend to cache
with `bkt --ttl=[some duration] --`, for example:

```shell
# Execute and cache an invocation of 'date +%s.%N'
$ bkt --ttl=1m -- date +%s.%N
1631992417.080884000

# A subsequent invocation reuses the same cached output
$ bkt --ttl=1m -- date +%s.%N
1631992417.080884000
```

When `bkt` is passed a command it hasn't seen before (or recently) it executes
the command synchronously and caches its stdout, stderr, and exit code. Calling
`bkt` again with the same command reads the data from the cache and outputs it
as if the command had been run again.

### Cache Lifespan

Two flags, `--ttl` and `--stale`, configure how long cached data is preserved.
The TTL (Time to Live) specifies how long cached data will be used. Once the
TTL expires the cached data will be discarded and the backing command re-run.
A TTL can also be configured by setting a `BKT_TTL` environment variable.

When the data expires `bkt` has to re-execute the command synchronously, which
can introduce unexpected slowness. To avoid this, pass `--stale` with a shorter
duration than the TTL. When the cached data is older than the stale threshold
this causes `bkt` to refresh the cache in the background while still promptly
returning the cached data.

Both flags (and `BKT_TTL`) accept duration strings such as `10s` or
`1hour 30min`. The exact syntax is defined in the
[humantime](https://docs.rs/humantime/2.1.0/humantime/fn.parse_duration.html)
library.

### Execution Environment

Some commands' behavior depends on more than just the command line arguments.
It's possible to adjust how `bkt` caches such commands so that unrelated
invocations are cached separately.

#### Working Directory

For example, attempting to cache `pwd` will not work as expected by default:

```shell
$ $ bkt --ttl=1m -- pwd
/tmp/foo

$ cd ../bar

# Cached output for 'pwd' is reused even though the directory has changed
$ bkt --ttl=1m -- pwd
/tmp/foo
```

To have `bkt` key off the current working directory in addition to the command
line arguments pass `--cwd`:

```shell
$ bkt --cwd --ttl=1m -- pwd
/tmp/foo

$ cd ../bar

$ bkt --cwd --ttl=1m -- pwd
/tmp/bar
```

#### Environment Variables

Similarly, to specify one or more environment variables as relevant for the
command being cached use `--env`, such as `--env=LANG`. This flag can be
provided multiple times to key off additional variables. Invocations with
different values for any of the given variables will be cached separately.

#### File Modifications

`bkt` can also check the last-modified time of one or more files and include
this in the cache key using `--modtime`. For instance passing
`--modtime=/etc/passwd` would cause the backing command to be re-executed any
time `/etc/passwd` is modified even if the TTL has not expired.

### Refreshing Manually

It's also possible to trigger refreshes manually using `--force` or `--warm`.
The former behaves exactly as if the cached data was not found, executing the
process and caching the result. This is useful if you know the cached data
is no longer up-to-date, e.g. because something external changed.

Alternatively, it can be useful to refresh the cache asynchronously, which
`--warm` provides. This triggers a refresh in the background but immediately
ends the current process with no output. This is useful if you expect
additional invocations in the near future and want to ensure they get a cache
hit. Note that until the warming process completes concurrent calls may still
see a cache miss and trigger their own invocation.

### Setting a Cache Scope

Cached data is persisted to disk (but see [below](#cache_dir)), and is
available to any process that invokes `bkt`. Generally this is desirable, but
certain usages may want to isolate their invocations from other potential
concurrent calls.

To do so pass `--scope=...` with a sufficiently unique argument, such as a fixed
label for the calling program, the current process ID, or a timestamp.

```shell
$ bkt --ttl=1m -- date +%s.%N
1631992417.080884000

# Changing the scope causes the command to be cached separately
$ bkt --scope=foo --ttl=1m -- date +%s.%N
1631992418.010562000
```

Alternatively, define a `BKT_SCOPE` environment variable to configure a
consistent scope across invocations. This can be useful within a script to
ensure all commands share a scope.

```shell
#!/bin/bash

# Set a unique scope for this script invocation using the PID and current time
export BKT_SCOPE="my_script_$$_$(date -Ins)"
```

### Discarding Failed Invocations

By default, all invocations are cached regardless of their output or exit code.
In situations where failures should not be cached pass `--discard-failures` to
only persist successful invocations (those that return a `0` exit code).

**WARNING:** Passing this flag can cause the backing command to be invoked more
frequently than the `--ttl` would suggest, which in turn can create unexpected
load. If the backing command is failing due to an outage or bug (such as an
overloaded website) triggering additional calls can exacerbate the issue and
effectively DDoS the hampered system. It is generally safer *not* to set this
flag and instead make the client robust to occasional failures. 

<a name="cache_dir"></a>
### Changing the Cache Directory

By default, cached data is stored under your system's temporary directory
(typically `/tmp` on Linux).

You may want to use a different location for certain commands, for instance to
be able to easily delete the cached data as soon as it's no longer needed. You
can specify a custom cache directory via the `--cache-dir` flag or by defining
a `BKT_CACHE_DIR` environment variable.

Note that the choice of directory can affect `bkt`'s performance: if the cache
directory is on a [`tmpfs`](https://en.wikipedia.org/wiki/Tmpfs) or solid-state
partition it will be significantly faster than one using a spinning disk.

If your system's temporary directory is not a good choice for the default cache
location (e.g. it is not a `tmpfs`) you can specify a different location by
defining a `BKT_TMPDIR` environment variable (for example in your `.bashrc`).
These two environment variables, `BKT_TMPDIR` and `BKT_CACHE_DIR`, have similar
effects but `BKT_TMPDIR` should be used to configure the system-wide default,
and `--cache-dir`/`BKT_CACHE_DIR` used to override it.

`bkt` periodically prunes stale data from its cache, but it also assumes the
operating system will empty its temporary storage from time to time (for `/tmp`
this typically happens on reboot). If you opt to use a directory that the
system does not maintain, such as `~/.cache`, you may want to manually delete
the cache directory on occasion, such as when upgrading `bkt`.

## Security and Privacy

The default cache directory is potentially world-readable. On Unix the cache
directory is created with `700` permissions, meaning only the current user can
access it, but this is not foolproof.

You can customize the cache directory (see [above](#cache_dir)) to a location
you trust such as `~/.cache`, but note that your home directory may be slower than
the temporary directory selected by default.

In general, if you are not the only user of your system it's wise to configure
your `TMPDIR` to a location only you can access. If that is not possible use
`BKT_TMPDIR` to configure a custom temporary directory specifically for `bkt`.

## Patterns and Tips

**Please share how you're using `bkt` on the
[Discussion Board](https://github.com/dimo414/bkt/discussions/categories/show-and-tell)!**

<a name="fzf"></a>
### Speeding up `fzf` and other preview tools

`bkt` works well with interactive tools like
[`fzf`](https://github.com/junegunn/fzf) that execute other commands. Because
`fzf` executes the `--preview` command every time an element is selected it can
be slow and tedious to browse when the command takes a long time to run. Using
`bkt` allows each selection's preview to be cached. Compare:

```shell
$ printf '%s\n' 1 0.2 3 0.1 5 | \
  fzf --preview="bash -c 'sleep {}; echo {}'"

$ printf '%s\n' 1 0.2 3 0.1 5 | \
  fzf --preview="bkt --ttl=10m --stale=10s -- bash -c 'sleep {}; echo {}'"
```

You'll generally want to use a long TTL and a short stale duration so that
even if you leave `fzf` running for a while the cache remains warm and is
refreshed in the background. You may also want to set a `--scope` if it's
important to invalidate the cache on subsequent invocations.

See [this discussion](https://github.com/dimo414/bkt/discussions/29) for a more
complete example of using `bkt` with `fzf`, including warming the commands before
the user starts navigating the selector.

### Using `bkt` only if installed

You may want to distribute shell scripts that utilize `bkt` without requiring
every user also install it. By falling back to a no-op shell function when `bkt`
is not available your script can take advantage of it opportunistically without
complicating your users' workflow. Of course if they choose to install `bkt`
they'll get a faster script as a result!

```shell
# Cache commands using bkt if installed
if ! command -v bkt >&/dev/null; then
  # If bkt isn't installed skip its arguments and just execute directly.
  bkt() {
    while [[ "$1" == --* ]]; do shift; done
    "$@"
  }
  # Optionally, write a msg to stderr suggesting users install bkt.
  echo "Tip: install https://github.com/dimo414/bkt for faster performance" >&2
fi
```

### Decorating commands with `bkt` in shell scripts

It is sometimes helpful to cache _all_ invocations of a command in a shell
script or in your shell environment. You can use a decorator function pattern
similar to what bash-cache does to enable caching transparently, like so:

```shell
# This is Bash syntax, but other shells support similar syntax
expensive_cmd() {
  bkt [bkt args ...] -- expensive_cmd "$@"
}
```

Calls to `expensive_cmd` in your shell will now go through `bkt` behind the
scenes. This can be useful for brevity and consistency but obviously changing
behavior like this is a double-edged-sword, so use with caution. Should you
need to bypass the cache for a single invocation Bash provides the
[`command` builtin](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html#index-command),
so `command expensive_cmd ...` will invoke `expensive_cmd` directly. Other
shells provide similar features.
