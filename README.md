# `bkt`

`bkt` (pronounced "bucket") is a subprocess caching utility written in Rust, inspired by
[bash-cache](https://github.com/dimo414/bash-cache).
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

Pre-compiled binaries for common platforms will be posted to GitHub soon.

## Usage

```
bkt [--ttl=DURATION] [--stale=DURATION] [--cwd] [--env= ...] [--scope=SCOPE] [--warm|--force] -- <command>...
```

The easiest way to use `bkt` is to simply prefix the command you intend to
cache with `bkt --`, for example:

```shell
# Execute and cache an invocation of 'date +%s.%N'
$ bkt -- date +%s.%N
1631992417.080884000

# A subsequent invocation reuses the same cached output
$ bkt -- date +%s.%N
1631992417.080884000
```

When `bkt` is passed a command it hasn't seen before (or recently) it executes
the command synchronously and caches its stdout, stderr, and exit code. Calling
`bkt` again with the same command reads the data from the cache and outputs it
as if the command had been run again.

### Cache Lifespan

Two flags, `--ttl` and `--stale`, configure how long cached data is preserved.
By default `bkt` uses a TTL (Time to Live) of 60 seconds, meaning cached
data older than sixty seconds will be discarded and the backing command re-run.
Passing a different value, such as `--ttl=1d`, will change how long the cached
data is considered valid.

When the data expires `bkt` has to re-execute the command synchronously, which
can introduce unexpected slowness. To avoid this, pass `--stale` with a shorter
duration than the TTL. This causes `bkt` to refresh the cache in the background
when the cached data is older than the stale threshold while still returning
the old data promptly.

Both flags accept duration strings such as `10s` or `1hour 30min`. The exact
syntax is defined in the
[humantime](https://docs.rs/humantime/2.1.0/humantime/fn.parse_duration.html) library.

### Execution Environment

Some commands behavior depends on more than just the command line arguments.
It's possible to constrain the cache so these invocations are not conflated.
For example, attempting to cache `pwd` will not work as expected by default:

```shell
$ $ bkt -- pwd
/tmp/foo

$ cd ../bar

# Cached output for 'pwd' is reused even though the directory has changed
$ bkt -- pwd
/tmp/foo
```

To have `bkt` key off the current working directory in addition to the command
line arguments pass `--cwd`:

```shell
$ bkt --cwd -- pwd
/tmp/foo

$ cd ../bar

$ bkt --cwd -- pwd
/tmp/bar
```

Similarly, to include one or more environment variables in the cache key pass
`--env`, such as `--env=TMPDIR` or `--env=LANG,TERM`. The flag can also be
passed multiple times. Invocations with different values for any of the given
variables will be cached separately.

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
$ bkt -- date +%s.%N
1631992417.080884000

# Changing the scope causes the command to be cached separately
$ bkt --scope=foo -- date +%s.%N
1631992418.010562000
```

<a name="cache_dir"></a>
### Changing the Cache Directory

By default, cached data is stored under `/tmp` or a similar temporary directory,
this can be customized via the `--cache_dir` flag. Note that the choice of
directory can affect `bkt`'s performance; if the cache is stored under a
[`tmpfs`](https://en.wikipedia.org/wiki/Tmpfs) or solid-state partition it will
be significantly faster than caching to a spinning disk.

## Security and Privacy

The default cache directory is potentially world-readable. On Unix the cache
directory is created with `700` permissions, meaning only the current user can
access it, but this is not foolproof.

You can customize the `--cache_dir` to a location you trust such as `~/.bkt`,
but note that your home directory may be slower than the `TMPDIR` (see 
[above](#cache_dir)). In general, if you are not the only user of your system
it's wise to configure your `TMPDIR` to a location only you can access.

## Patterns and Tips

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
  fzf --ttl=10m --stale=10s --preview="bkt -- bash -c 'sleep {}; echo {}'"
```

You'll generally want to use a long TTL and a short stale duration so that
even if you leave `fzf` running for a while the cache remains warm and is
refreshed in the background. You may also want to set a `--scope` if it's
important to invalidate the cache on subsequent invocations.

Note: one downside to using `bkt` is, currently, `bkt` doesn't
[stream](https://github.com/junegunn/fzf/pull/2215) the backing process' output.
This means when `bkt` has a cache miss the preview will be absent until the
process completes, even if partial output could be displayed sooner.

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
