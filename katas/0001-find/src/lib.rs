//! Kata 0001-find: `vfind`, a verified, injection-safe `find` (listing only).
//! Intent: intents/0001-find.md
//!
//! Everything OUTSIDE the `<vc-helpers>` / `<vc-code>` regions is the frozen,
//! human-approved specification (hashed in specs.lock.json).
//!
//! Architecture (D3): the verified core is a step machine, `Walker`. The
//! trusted shell (src/main.rs) calls `Walker::next` in a loop and does what
//! each returned `Step` says: answer a filesystem query (`Look`, `List`),
//! write bytes (`Stdout`, `Stderr`), or exit (`Exit`). So the core decides
//! every query, every output byte and the exit status.
//!
//! The spec is stated against an abstract filesystem `FsS`: what a faithful
//! shell answers. `find_events(req, fs)` is the whole run as a sequence of
//! events; `Walker::next` must return exactly `event_step` of the next event,
//! for every filesystem consistent with the answers the shell gave so far.
#![forbid(unsafe_code)]

use vstd::prelude::*;

verus! {

/// The codec of every path and message (D13): `security_property::BackslashEscape`.
pub type B = security_property::BackslashEscape;

// ===========================================================================
// Interface (exec types) and their mathematical views
// ===========================================================================

/// What a path is, as reported by the shell (D8, D9). Without `-L` the shell
/// uses `lstat`, with `-L` `stat`; a broken symlink under `-L` is `Symlink`.
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Kind {
    Dir,
    Symlink,
    Other,
}

/// The identity of a filesystem object: (device, inode) (D10).
pub type Id = (u64, u64);

/// The shell's answer to "look at PATH".
pub enum Look {
    /// The path doesn't exist (or `stat` failed): the OS error text.
    Missing(Vec<u8>),
    /// Kind, device, inode.
    Found(Kind, u64, u64),
}

/// The shell's answer to "list directory PATH".
pub enum Listing {
    /// The directory couldn't be read: the OS error text.
    Unreadable(Vec<u8>),
    /// The raw entry names, in any order.
    Names(Vec<Vec<u8>>),
}

pub enum Answer {
    Look(Look),
    List(Listing),
}

pub struct Request {
    /// The command-line arguments after the program name, as raw bytes.
    pub args: Vec<Vec<u8>>,
}

/// What the shell must do next.
pub enum Step {
    /// Look at this path (`stat` if the flag is true, else `lstat`) and pass
    /// `Answer::Look` to the next call.
    Look(Vec<u8>, bool),
    /// List this directory and pass `Answer::List` to the next call.
    List(Vec<u8>),
    /// Write these bytes to stdout; pass `None` to the next call.
    Stdout(Vec<u8>),
    /// Write these bytes to stderr; pass `None` to the next call.
    Stderr(Vec<u8>),
    /// Exit with this status.
    Exit(u8),
}

pub enum LookS {
    Missing(Seq<u8>),
    Found(Kind, Id),
}

pub enum ListingS {
    Unreadable(Seq<u8>),
    Names(Seq<Seq<u8>>),
}

pub enum AnswerS {
    Look(LookS),
    List(ListingS),
}

pub struct RequestS {
    pub args: Seq<Seq<u8>>,
}

pub enum StepS {
    Look(Seq<u8>, bool),
    List(Seq<u8>),
    Stdout(Seq<u8>),
    Stderr(Seq<u8>),
    Exit(u8),
}

impl View for Look {
    type V = LookS;

    open spec fn view(&self) -> LookS {
        match self {
            Look::Missing(m) => LookS::Missing(m@),
            Look::Found(k, dev, ino) => LookS::Found(*k, (*dev, *ino)),
        }
    }
}

impl View for Listing {
    type V = ListingS;

    open spec fn view(&self) -> ListingS {
        match self {
            Listing::Unreadable(m) => ListingS::Unreadable(m@),
            Listing::Names(ns) => ListingS::Names(security_property::seqs_view(ns@)),
        }
    }
}

impl View for Answer {
    type V = AnswerS;

    open spec fn view(&self) -> AnswerS {
        match self {
            Answer::Look(l) => AnswerS::Look(l@),
            Answer::List(l) => AnswerS::List(l@),
        }
    }
}

impl View for Request {
    type V = RequestS;

    open spec fn view(&self) -> RequestS {
        RequestS { args: security_property::seqs_view(self.args@) }
    }
}

impl View for Step {
    type V = StepS;

    open spec fn view(&self) -> StepS {
        match self {
            Step::Look(p, f) => StepS::Look(p@, *f),
            Step::List(p) => StepS::List(p@),
            Step::Stdout(b) => StepS::Stdout(b@),
            Step::Stderr(b) => StepS::Stderr(b@),
            Step::Exit(c) => StepS::Exit(*c),
        }
    }
}

// ===========================================================================
// The filesystem model (D3, D20)
// ===========================================================================

/// The filesystem as a faithful shell answers it. Trusted (Not verified): the
/// filesystem doesn't change during the run, and the shell answers truly.
pub struct FsS {
    /// "look at PATH": `look(p, false)` is `lstat`, `look(p, true)` is `stat` (D8, D9).
    pub look: spec_fn(Seq<u8>, bool) -> LookS,
    /// "list directory PATH": the raw entry names, in any order.
    pub list: spec_fn(Seq<u8>) -> ListingS,
    /// The identities of all directories.
    pub dirs: Set<Id>,
}

/// D20: every directory the shell reports is one of `fs.dirs` (a `Set` is
/// always finite, so there are finitely many directory identities).
pub open spec fn wf_fs(fs: FsS) -> bool {
    forall|p: Seq<u8>, f: bool|
        match #[trigger] (fs.look)(p, f) {
            LookS::Found(Kind::Dir, id) => fs.dirs.contains(id),
            _ => true,
        }
}

// ===========================================================================
// Command line (D5, D19)
// ===========================================================================

/// `-L`
pub open spec fn dash_l() -> Seq<u8> {
    seq![45u8, 76u8]
}

/// `.`
pub open spec fn dot() -> Seq<u8> {
    seq![46u8]
}

/// `..`
pub open spec fn dotdot() -> Seq<u8> {
    seq![46u8, 46u8]
}

/// An argument that looks like an option: starts with `-`.
pub open spec fn is_dash_arg(a: Seq<u8>) -> bool {
    a.len() > 0 && a[0] == 45u8
}

/// D19: the number of leading `-L` arguments.
pub open spec fn leading_l(args: Seq<Seq<u8>>) -> nat
    decreases args.len(),
{
    if args.len() > 0 && args[0] == dash_l() {
        1 + leading_l(args.subrange(1, args.len() as int))
    } else {
        0
    }
}

/// D19: the first argument that starts with `-`, if any.
pub open spec fn first_dash(args: Seq<Seq<u8>>) -> Option<Seq<u8>>
    decreases args.len(),
{
    if args.len() == 0 {
        None
    } else if is_dash_arg(args[0]) {
        Some(args[0])
    } else {
        first_dash(args.subrange(1, args.len() as int))
    }
}

pub enum ArgsS {
    /// D19: a usage error caused by this argument.
    Usage(Seq<u8>),
    /// Follow symlinks (`-L`, D9), and the start paths (D5).
    Run(bool, Seq<Seq<u8>>),
}

/// D19: leading `-L`s (repeatable), then paths; any other argument starting
/// with `-` (including a `-L` after the first path) is a usage error.
/// D5: no path means `.`.
pub open spec fn parse_args(args: Seq<Seq<u8>>) -> ArgsS {
    let n = leading_l(args);
    let rest = args.subrange(n as int, args.len() as int);
    match first_dash(rest) {
        Some(a) => ArgsS::Usage(a),
        None => ArgsS::Run(n > 0, if rest.len() == 0 { seq![dot()] } else { rest }),
    }
}

// ===========================================================================
// Names, order and paths (D4, D6, D7)
// ===========================================================================

/// D4: `a` sorts strictly before `b`, bytewise; a proper prefix sorts first.
#[verifier::memoize]
pub open spec fn lex_lt(a: Seq<u8>, b: Seq<u8>) -> bool
    decreases a.len(),
{
    if b.len() == 0 {
        false
    } else if a.len() == 0 {
        true
    } else if a[0] != b[0] {
        a[0] < b[0]
    } else {
        lex_lt(a.subrange(1, a.len() as int), b.subrange(1, b.len() as int))
    }
}

/// `s` contains byte `b`.
pub open spec fn has_byte(s: Seq<u8>, b: u8) -> bool
    decreases s.len(),
{
    s.len() > 0 && (s[0] == b || has_byte(s.subrange(1, s.len() as int), b))
}

/// D6: a name the core accepts from a directory listing: non-empty, not `.`
/// or `..`, no `/`.
pub open spec fn valid_name(n: Seq<u8>) -> bool {
    &&& n.len() > 0
    &&& n != dot()
    &&& n != dotdot()
    &&& !has_byte(n, 47u8)
}

/// Insert into a strictly increasing list; an equal name is collapsed (D6).
#[verifier::memoize]
pub open spec fn insert_unique(x: Seq<u8>, s: Seq<Seq<u8>>) -> Seq<Seq<u8>>
    decreases s.len(),
{
    if s.len() == 0 {
        seq![x]
    } else if x == s[0] {
        s
    } else if lex_lt(x, s[0]) {
        seq![x] + s
    } else {
        seq![s[0]] + insert_unique(x, s.subrange(1, s.len() as int))
    }
}

/// D4, D6, D7: the valid names of a listing, each once, strictly increasing.
#[verifier::memoize]
pub open spec fn children(ns: Seq<Seq<u8>>) -> Seq<Seq<u8>>
    decreases ns.len(),
{
    if ns.len() == 0 {
        seq![]
    } else {
        let rest = children(ns.subrange(0, ns.len() - 1));
        let x = ns[ns.len() - 1];
        if valid_name(x) {
            insert_unique(x, rest)
        } else {
            rest
        }
    }
}

/// D6: parent + `/` + name, without doubling a trailing `/` of the parent.
pub open spec fn child_path(parent: Seq<u8>, name: Seq<u8>) -> Seq<u8> {
    if parent.len() > 0 && parent[parent.len() - 1] == 47u8 {
        parent + name
    } else {
        parent + seq![47u8] + name
    }
}

// ===========================================================================
// The walk (D4, D5, D8–D12, D20)
// ===========================================================================

/// One thing that happens during a run.
pub enum EventS {
    /// Query: look at a path (with `stat` iff the flag, D8/D9).
    Look(Seq<u8>, bool),
    /// Query: list a directory.
    List(Seq<u8>),
    /// A path is printed on stdout (D13).
    Print(Seq<u8>),
    /// An OS error for a path: path, message (D11, D12).
    Fail(Seq<u8>, Seq<u8>),
    /// A filesystem loop at a path (D10).
    Loop(Seq<u8>),
    /// A usage error caused by an argument (D19).
    Usage(Seq<u8>),
    /// The run ends with this exit status (D18).
    Exit(u8),
}

/// `anc` contains identity `id`.
pub open spec fn has_id(anc: Seq<Id>, id: Id) -> bool
    decreases anc.len(),
{
    anc.len() > 0 && (anc[0] == id || has_id(anc.subrange(1, anc.len() as int), id))
}

/// The walk below path `p`. `anc` holds the identities of the directories
/// entered on the way down to `p` (its ancestors, start path included).
pub open spec fn walk_path(fs: FsS, follow: bool, p: Seq<u8>, anc: Seq<Id>) -> Seq<EventS>
    decreases fs.dirs.difference(anc.to_set()).len(), 0nat, 0nat
    when wf_fs(fs)
    via walk_path_decreases
{
    seq![EventS::Look(p, follow)] + match (fs.look)(p, follow) {
        // D11: not printed, error, continue.
        LookS::Missing(msg) => seq![EventS::Fail(p, msg)],
        LookS::Found(Kind::Dir, id) => if has_id(anc, id) {
            // D10: printed, not entered, error.
            seq![EventS::Print(p), EventS::Loop(p)]
        } else {
            // D4: a directory is printed before its contents.
            seq![EventS::Print(p), EventS::List(p)] + match (fs.list)(p) {
                // D12: printed (above), contents not, error.
                ListingS::Unreadable(msg) => seq![EventS::Fail(p, msg)],
                ListingS::Names(ns) => walk_names(fs, follow, p, children(ns), anc.push(id)),
            }
        },
        // D8, D9: symlinks (without -L), broken symlinks (with -L) and
        // non-directories are printed, never entered.
        LookS::Found(_, _) => seq![EventS::Print(p)],
    }
}

/// The walk below each name of a directory `parent`, in the given order.
pub open spec fn walk_names(
    fs: FsS,
    follow: bool,
    parent: Seq<u8>,
    names: Seq<Seq<u8>>,
    anc: Seq<Id>,
) -> Seq<EventS>
    decreases fs.dirs.difference(anc.to_set()).len(), 1nat, names.len()
    when wf_fs(fs)
{
    if names.len() == 0 {
        seq![]
    } else {
        walk_path(fs, follow, child_path(parent, names[0]), anc) + walk_names(
            fs,
            follow,
            parent,
            names.subrange(1, names.len() as int),
            anc,
        )
    }
}

/// Termination of the walk (D20): entering a directory adds a new identity
/// from the finite set `fs.dirs` to the ancestors.
#[via_fn]
proof fn walk_path_decreases(fs: FsS, follow: bool, p: Seq<u8>, anc: Seq<Id>) {
    match (fs.look)(p, follow) {
        LookS::Found(Kind::Dir, id) => {
            lemma_has_id(anc, id);
            if !anc.contains(id) {
                anc.to_set_ensures();
                anc.lemma_push_to_set_commute(id);
                let s = fs.dirs.difference(anc.to_set());
                assert(fs.dirs.contains(id));
                assert(s.contains(id));
                assert(fs.dirs.difference(anc.push(id).to_set()) =~= s.remove(id));
                assert(s.remove(id).len() < s.len());
            }
        },
        _ => {},
    }
}

proof fn lemma_has_id(anc: Seq<Id>, id: Id)
    ensures
        has_id(anc, id) <==> anc.contains(id),
    decreases anc.len(),
{
    if anc.len() > 0 {
        let rest = anc.subrange(1, anc.len() as int);
        lemma_has_id(rest, id);
        if rest.contains(id) {
            let i = choose|i: int| 0 <= i < rest.len() && rest[i] == id;
            assert(anc[i + 1] == id);
        }
        if anc.contains(id) && anc[0] != id {
            let i = choose|i: int| 0 <= i < anc.len() && anc[i] == id;
            assert(rest[i - 1] == id);
        }
        if anc[0] == id {
            assert(anc[0] == id);
        }
    }
}

/// D5: the start paths in argv order, each walked from scratch.
pub open spec fn walk_starts(fs: FsS, follow: bool, paths: Seq<Seq<u8>>) -> Seq<EventS>
    decreases paths.len(),
{
    if paths.len() == 0 {
        seq![]
    } else {
        walk_path(fs, follow, paths[0], seq![]) + walk_starts(
            fs,
            follow,
            paths.subrange(1, paths.len() as int),
        )
    }
}

pub open spec fn is_error(e: EventS) -> bool {
    e is Fail || e is Loop || e is Usage
}

/// Some event is an error.
pub open spec fn any_error(es: Seq<EventS>) -> bool
    decreases es.len(),
{
    es.len() > 0 && (is_error(es[0]) || any_error(es.subrange(1, es.len() as int)))
}

/// The whole run of `vfind` with arguments `req` on filesystem `fs`.
pub open spec fn find_events(req: RequestS, fs: FsS) -> Seq<EventS> {
    match parse_args(req.args) {
        // D19: nothing listed, exit 1.
        ArgsS::Usage(a) => seq![EventS::Usage(a), EventS::Exit(1)],
        ArgsS::Run(follow, paths) => {
            let body = walk_starts(fs, follow, paths);
            // D18: 0 if no error occurred, else 1.
            body + seq![EventS::Exit(if any_error(body) { 1u8 } else { 0u8 })]
        },
    }
}

// ===========================================================================
// Output bytes (D13–D17)
// ===========================================================================

/// The escaped form of a path or message (D13).
pub open spec fn enc(s: Seq<u8>) -> Seq<u8> {
    security_property::encode::<B>(s)
}

/// A line: the bytes followed by LF.
pub open spec fn line(s: Seq<u8>) -> Seq<u8> {
    s + seq![10u8]
}

/// `vfind: `
pub open spec fn msg_prefix() -> Seq<u8> {
    seq![118u8, 102u8, 105u8, 110u8, 100u8, 58u8, 32u8]
}

/// `: `
pub open spec fn colon_space() -> Seq<u8> {
    seq![58u8, 32u8]
}

/// `filesystem loop: `
pub open spec fn msg_loop() -> Seq<u8> {
    seq![102u8, 105u8, 108u8, 101u8, 115u8, 121u8, 115u8, 116u8, 101u8, 109u8, 32u8, 108u8, 111u8, 111u8, 112u8, 58u8, 32u8]
}

/// `unknown option `
pub open spec fn msg_unknown() -> Seq<u8> {
    seq![117u8, 110u8, 107u8, 110u8, 111u8, 119u8, 110u8, 32u8, 111u8, 112u8, 116u8, 105u8, 111u8, 110u8, 32u8]
}

/// `usage: vfind [-L] [PATH...]`
pub open spec fn msg_usage() -> Seq<u8> {
    seq![117u8, 115u8, 97u8, 103u8, 101u8, 58u8, 32u8, 118u8, 102u8, 105u8, 110u8, 100u8, 32u8, 91u8, 45u8, 76u8, 93u8, 32u8, 91u8, 80u8, 65u8, 84u8, 72u8, 46u8, 46u8, 46u8, 93u8]
}

/// What the shell is told to do for an event.
pub open spec fn event_step(e: EventS) -> StepS {
    match e {
        EventS::Look(p, f) => StepS::Look(p, f),
        EventS::List(p) => StepS::List(p),
        // D13: stdout is exactly the library's record unparser.
        EventS::Print(p) => StepS::Stdout(security_property::unparse_records::<B>(seq![p])),
        // D17
        EventS::Fail(p, m) => StepS::Stderr(line(msg_prefix() + enc(p) + colon_space() + enc(m))),
        EventS::Loop(p) => StepS::Stderr(line(msg_prefix() + msg_loop() + enc(p))),
        EventS::Usage(a) => StepS::Stderr(line(msg_prefix() + msg_unknown() + enc(a)) + line(msg_usage())),
        EventS::Exit(c) => StepS::Exit(c),
    }
}

/// The paths printed, in order.
pub open spec fn printed(es: Seq<EventS>) -> Seq<Seq<u8>>
    decreases es.len(),
{
    if es.len() == 0 {
        seq![]
    } else {
        let rest = printed(es.subrange(1, es.len() as int));
        match es[0] {
            EventS::Print(p) => seq![p] + rest,
            _ => rest,
        }
    }
}

/// All bytes written to stdout.
pub open spec fn stdout_of(es: Seq<EventS>) -> Seq<u8>
    decreases es.len(),
{
    if es.len() == 0 {
        seq![]
    } else {
        let rest = stdout_of(es.subrange(1, es.len() as int));
        match event_step(es[0]) {
            StepS::Stdout(b) => b + rest,
            _ => rest,
        }
    }
}

/// All bytes written to stderr.
pub open spec fn stderr_of(es: Seq<EventS>) -> Seq<u8>
    decreases es.len(),
{
    if es.len() == 0 {
        seq![]
    } else {
        let rest = stderr_of(es.subrange(1, es.len() as int));
        match event_step(es[0]) {
            StepS::Stderr(b) => b + rest,
            _ => rest,
        }
    }
}

// ===========================================================================
// The step machine's contract (D3)
// ===========================================================================

pub open spec fn is_query(e: EventS) -> bool {
    e is Look || e is List
}

/// A faithful shell's answer to a query.
pub open spec fn answer_of(fs: FsS, e: EventS) -> AnswerS {
    match e {
        EventS::List(p) => AnswerS::List((fs.list)(p)),
        EventS::Look(p, f) => AnswerS::Look((fs.look)(p, f)),
        _ => AnswerS::Look(LookS::Missing(seq![])),  // not a query; unused
    }
}

/// A faithful shell's answers to the queries among `es`, in order.
pub open spec fn answers_for(fs: FsS, es: Seq<EventS>) -> Seq<AnswerS>
    decreases es.len(),
{
    if es.len() == 0 {
        seq![]
    } else {
        let rest = answers_for(fs, es.subrange(0, es.len() - 1));
        if is_query(es[es.len() - 1]) {
            rest.push(answer_of(fs, es[es.len() - 1]))
        } else {
            rest
        }
    }
}

/// `answers` are exactly what a shell faithful to `fs` answered to the
/// queries among the first `k` events of the run.
pub open spec fn answers_ok(fs: FsS, req: RequestS, answers: Seq<AnswerS>, k: nat) -> bool {
    let es = find_events(req, fs);
    k <= es.len() && answers == answers_for(fs, es.take(k as int))
}

pub open spec fn opt_answer(a: Option<Answer>) -> Seq<AnswerS> {
    match a {
        Some(x) => seq![x@],
        None => seq![],
    }
}

/// The verified core of `vfind`.
pub struct Walker {
    /// The request (ghost).
    pub req: Ghost<RequestS>,
    /// The answers passed in so far (ghost).
    pub answers: Ghost<Seq<AnswerS>>,
    /// The number of steps returned so far (ghost).
    pub taken: Ghost<nat>,
    /// `Exit` has been returned (ghost).
    pub finished: Ghost<bool>,
    // The implementation's own state:
    // <vc-helpers>
    // </vc-helpers>
}

impl Walker {
    /// The implementation's invariant (chosen in the vericode stage).
    pub closed spec fn inv(&self) -> bool {
        // <vc-code>
        true
        // </vc-code>
    }

    pub fn new(req: &Request) -> (w: Walker)
        ensures
            w.inv(),
            w.req@ == req@,
            w.answers@ == Seq::<AnswerS>::empty(),
            w.taken@ == 0,
            !w.finished@,
    {
        // <vc-code>
        assume(false);
        unreached()
        // </vc-code>
    }

    /// The next step. `answer` must be `Some` exactly when the previous step
    /// was `Look` or `List`, and then answer it.
    ///
    /// D3: for every finite filesystem that the shell's answers so far are
    /// faithful to, the step is the next event of `find_events`. Never
    /// panics, for any answers (D20).
    pub fn next(&mut self, answer: Option<Answer>) -> (s: Step)
        requires
            old(self).inv(),
            !old(self).finished@,
        ensures
            final(self).inv(),
            final(self).req@ == old(self).req@,
            final(self).answers@ == old(self).answers@ + opt_answer(answer),
            final(self).taken@ == old(self).taken@ + 1,
            final(self).finished@ == (s is Exit),
            forall|fs: FsS|
                wf_fs(fs) && #[trigger] answers_ok(fs, final(self).req@, final(self).answers@, old(self).taken@)
                    ==> old(self).taken@ < find_events(final(self).req@, fs).len()
                    && s@ == event_step(find_events(final(self).req@, fs)[old(self).taken@ as int]),
    {
        // <vc-code>
        assume(false);
        unreached()
        // </vc-code>
    }
}

// <vc-helpers>
// </vc-helpers>

// ===========================================================================
// Theorems (Properties P1–P7)
// ===========================================================================

/// P6, D20: every run ends with exactly one `Exit`, as its last event, so a
/// faithful shell's loop terminates.
pub proof fn theorem_run_ends(req: RequestS, fs: FsS)
    requires
        wf_fs(fs),
    ensures
        find_events(req, fs).len() > 0,
        find_events(req, fs).last() is Exit,
        forall|i: int| 0 <= i < find_events(req, fs).len() - 1 ==> !(#[trigger] find_events(req, fs)[i] is Exit),
{
    // <vc-code>
    assume(false);
    // </vc-code>
}

/// P7, D18: the exit status is 1 iff stderr is non-empty, else 0.
pub proof fn theorem_exit_iff_stderr(req: RequestS, fs: FsS)
    requires
        wf_fs(fs),
    ensures
        find_events(req, fs).last() == EventS::Exit(
            if stderr_of(find_events(req, fs)).len() > 0 { 1u8 } else { 0u8 },
        ),
{
    // <vc-code>
    assume(false);
    // </vc-code>
}

/// D13 (link to the library): stdout is exactly `unparse_records` of the
/// printed paths.
pub proof fn theorem_stdout_is_records(es: Seq<EventS>)
    ensures
        stdout_of(es) == security_property::unparse_records::<B>(printed(es)),
{
    // <vc-code>
    assume(false);
    // </vc-code>
}

/// P1, D14: exact count: LF bytes in stdout == number of printed paths.
pub proof fn theorem_exact_count(req: RequestS, fs: FsS)
    ensures
        security_property::count_byte(stdout_of(find_events(req, fs)), 10u8) == printed(
            find_events(req, fs),
        ).len(),
{
    // <vc-code>
    assume(false);
    // </vc-code>
}

/// P2, D15: no forged paths: stdout determines the list of printed paths.
pub proof fn theorem_no_forged_paths(r1: RequestS, fs1: FsS, r2: RequestS, fs2: FsS)
    requires
        stdout_of(find_events(r1, fs1)) == stdout_of(find_events(r2, fs2)),
    ensures
        printed(find_events(r1, fs1)) == printed(find_events(r2, fs2)),
{
    // <vc-code>
    assume(false);
    // </vc-code>
}

/// P3: within one start path's listing no path is printed twice.
pub proof fn theorem_no_duplicates(fs: FsS, follow: bool, p: Seq<u8>)
    requires
        wf_fs(fs),
    ensures
        printed(walk_path(fs, follow, p, seq![])).no_duplicates(),
{
    // <vc-code>
    assume(false);
    // </vc-code>
}

/// P4: pre-order: a start path's listing begins with the start path, and
/// every later path is a child of a path printed before it.
pub proof fn theorem_preorder(fs: FsS, follow: bool, p: Seq<u8>)
    requires
        wf_fs(fs),
    ensures
        ({
            let ps = printed(walk_path(fs, follow, p, seq![]));
            &&& ps.len() > 0 ==> ps[0] == p
            &&& forall|i: int|
                1 <= i < ps.len() ==> exists|j: int, n: Seq<u8>|
                    0 <= j < i && valid_name(n) && #[trigger] ps[i] == child_path(ps[j], n)
        }),
{
    // <vc-code>
    assume(false);
    // </vc-code>
}

// ===========================================================================
// Spec tests: every Example of the intent is accepted, and its plausible
// wrong answer rejected. (`by (compute)` asserts must not mention `let`
// variables: the interpreter can't see through them.)
// ===========================================================================

// ---- Fixtures -------------------------------------------------------------

/// `No such file or directory`
spec fn enoent() -> Seq<u8> { seq![78u8, 111u8, 32u8, 115u8, 117u8, 99u8, 104u8, 32u8, 102u8, 105u8, 108u8, 101u8, 32u8, 111u8, 114u8, 32u8, 100u8, 105u8, 114u8, 101u8, 99u8, 116u8, 111u8, 114u8, 121u8] }

/// `Permission denied`
spec fn eacces() -> Seq<u8> { seq![80u8, 101u8, 114u8, 109u8, 105u8, 115u8, 115u8, 105u8, 111u8, 110u8, 32u8, 100u8, 101u8, 110u8, 105u8, 101u8, 100u8] }

spec fn req(args: Seq<Seq<u8>>) -> RequestS {
    RequestS { args }
}

/// The intent's tree `t/` rooted at `root` (`t`, `t/` or `.`): files `b`,
/// `.h`, `a-c`, `a/x`; directory `a`; symlink `l -> a`; and, if `with_dead`,
/// a broken symlink `dead`.
spec fn fs_tree(root: Seq<u8>, with_dead: bool) -> FsS {
    FsS {
        look: |p: Seq<u8>, f: bool|
            if p == root {
                LookS::Found(Kind::Dir, (1u64, 1u64))
            } else if p == child_path(root, seq![97u8]) {
                LookS::Found(Kind::Dir, (1u64, 2u64))
            } else if p == child_path(root, seq![108u8]) {
                if f { LookS::Found(Kind::Dir, (1u64, 2u64)) } else { LookS::Found(Kind::Symlink, (1u64, 7u64)) }
            } else if p == child_path(child_path(root, seq![97u8]), seq![120u8]) || p == child_path(child_path(root, seq![108u8]), seq![120u8]) {
                LookS::Found(Kind::Other, (1u64, 3u64))
            } else if p == child_path(root, seq![46u8, 104u8]) {
                LookS::Found(Kind::Other, (1u64, 4u64))
            } else if p == child_path(root, seq![97u8, 45u8, 99u8]) {
                LookS::Found(Kind::Other, (1u64, 5u64))
            } else if p == child_path(root, seq![98u8]) {
                LookS::Found(Kind::Other, (1u64, 6u64))
            } else if with_dead && p == child_path(root, seq![100u8, 101u8, 97u8, 100u8]) {
                LookS::Found(Kind::Symlink, (1u64, 8u64))  // broken: `stat` reports the link too
            } else {
                LookS::Missing(enoent())
            },
        list: |p: Seq<u8>|
            if p == root {
                if with_dead {
                    ListingS::Names(seq![seq![98u8], seq![100u8, 101u8, 97u8, 100u8], seq![97u8], seq![46u8, 104u8], seq![97u8, 45u8, 99u8], seq![108u8]])
                } else {
                    ListingS::Names(seq![seq![98u8], seq![97u8], seq![46u8, 104u8], seq![97u8, 45u8, 99u8], seq![108u8]])
                }
            } else if p == child_path(root, seq![97u8]) || p == child_path(root, seq![108u8]) {
                ListingS::Names(seq![seq![120u8]])
            } else {
                ListingS::Unreadable(eacces())
            },
        dirs: set![(1u64, 1u64), (1u64, 2u64)],
    }
}

/// Tree `u/` with symlink `up -> .` (E5, E6).
spec fn fs_u() -> FsS {
    FsS {
        look: |p: Seq<u8>, f: bool|
            if p == seq![117u8] {
                LookS::Found(Kind::Dir, (2u64, 1u64))
            } else if p == seq![117u8, 47u8, 117u8, 112u8] {
                if f { LookS::Found(Kind::Dir, (2u64, 1u64)) } else { LookS::Found(Kind::Symlink, (2u64, 2u64)) }
            } else {
                LookS::Missing(enoent())
            },
        list: |p: Seq<u8>| if p == seq![117u8] { ListingS::Names(seq![seq![117u8, 112u8]]) } else { ListingS::Unreadable(eacces()) },
        dirs: set![(2u64, 1u64)],
    }
}

/// E7: directory `m` contains `b`, which has `m`'s identity (bind-mount loop).
spec fn fs_m() -> FsS {
    FsS {
        look: |p: Seq<u8>, f: bool|
            if p == seq![109u8] || p == seq![109u8, 47u8, 98u8] { LookS::Found(Kind::Dir, (3u64, 1u64)) } else { LookS::Missing(enoent()) },
        list: |p: Seq<u8>| ListingS::Names(seq![seq![98u8]]),
        dirs: set![(3u64, 1u64)],
    }
}

/// A readable directory `dir` with the given raw entry names, each a file;
/// every path not below `dir/` is an unreadable directory (E9, E10, E11,
/// E15, E16).
spec fn fs_dir(dir: Seq<u8>, names: Seq<Seq<u8>>) -> FsS {
    FsS {
        look: |p: Seq<u8>, f: bool|
            if p == dir {
                LookS::Found(Kind::Dir, (5u64, 1u64))
            } else if security_property::is_prefix(dir + seq![47u8], p) {
                LookS::Found(Kind::Other, (5u64, 2u64))  // an entry of `dir`
            } else {
                LookS::Found(Kind::Dir, (5u64, 3u64))  // unreadable (see `list`)
            },
        list: |p: Seq<u8>| if p == dir { ListingS::Names(names) } else { ListingS::Unreadable(eacces()) },
        dirs: set![(5u64, 1u64), (5u64, 3u64)],
    }
}

proof fn spec_fixtures_wf() {
    // wf_fs is satisfiable (and the fixtures are finite filesystems).
    assert(wf_fs(fs_tree(seq![116u8], false)));
    assert(wf_fs(fs_tree(seq![116u8], true)));
    assert(wf_fs(fs_tree(seq![116u8, 47u8], false)));
    assert(wf_fs(fs_tree(seq![46u8], false)));
    assert(wf_fs(fs_u()));
    assert(wf_fs(fs_m()));
    assert(wf_fs(fs_dir(seq![100u8], seq![seq![98u8]])));
}

// ---- Examples -------------------------------------------------------------

/// E1 `vfind t`
proof fn spec_e1() {
    assert(printed(find_events(req(seq![seq![116u8]]), fs_tree(seq![116u8], false))) == seq![seq![116u8], seq![116u8, 47u8, 46u8, 104u8], seq![116u8, 47u8, 97u8], seq![116u8, 47u8, 97u8, 47u8, 120u8], seq![116u8, 47u8, 97u8, 45u8, 99u8], seq![116u8, 47u8, 98u8], seq![116u8, 47u8, 108u8]]) by (compute);
    assert(find_events(req(seq![seq![116u8]]), fs_tree(seq![116u8], false)).last() == EventS::Exit(0)) by (compute);
    // reject: globally sorted instead of pre-order; `.h` missing; symlink followed
    assert(printed(find_events(req(seq![seq![116u8]]), fs_tree(seq![116u8], false))) != seq![seq![116u8], seq![116u8, 47u8, 46u8, 104u8], seq![116u8, 47u8, 97u8], seq![116u8, 47u8, 97u8, 45u8, 99u8], seq![116u8, 47u8, 97u8, 47u8, 120u8], seq![116u8, 47u8, 98u8], seq![116u8, 47u8, 108u8]]) by (compute);
    assert(printed(find_events(req(seq![seq![116u8]]), fs_tree(seq![116u8], false))) != seq![seq![116u8], seq![116u8, 47u8, 97u8], seq![116u8, 47u8, 97u8, 47u8, 120u8], seq![116u8, 47u8, 97u8, 45u8, 99u8], seq![116u8, 47u8, 98u8], seq![116u8, 47u8, 108u8]]) by (compute);
    assert(printed(find_events(req(seq![seq![116u8]]), fs_tree(seq![116u8], false))) != seq![seq![116u8], seq![116u8, 47u8, 46u8, 104u8], seq![116u8, 47u8, 97u8], seq![116u8, 47u8, 97u8, 47u8, 120u8], seq![116u8, 47u8, 97u8, 45u8, 99u8], seq![116u8, 47u8, 98u8], seq![116u8, 47u8, 108u8], seq![116u8, 47u8, 108u8, 47u8, 120u8]]) by (compute);
}

/// E2 `vfind -L t`
proof fn spec_e2() {
    assert(printed(find_events(req(seq![seq![45u8, 76u8], seq![116u8]]), fs_tree(seq![116u8], false))) == seq![seq![116u8], seq![116u8, 47u8, 46u8, 104u8], seq![116u8, 47u8, 97u8], seq![116u8, 47u8, 97u8, 47u8, 120u8], seq![116u8, 47u8, 97u8, 45u8, 99u8], seq![116u8, 47u8, 98u8], seq![116u8, 47u8, 108u8], seq![116u8, 47u8, 108u8, 47u8, 120u8]]) by (compute);
    assert(find_events(req(seq![seq![45u8, 76u8], seq![116u8]]), fs_tree(seq![116u8], false)).last() == EventS::Exit(0)) by (compute);
    // reject: `t/l/x` missing; a loop error for `t/l`
    assert(printed(find_events(req(seq![seq![45u8, 76u8], seq![116u8]]), fs_tree(seq![116u8], false))) != seq![seq![116u8], seq![116u8, 47u8, 46u8, 104u8], seq![116u8, 47u8, 97u8], seq![116u8, 47u8, 97u8, 47u8, 120u8], seq![116u8, 47u8, 97u8, 45u8, 99u8], seq![116u8, 47u8, 98u8], seq![116u8, 47u8, 108u8]]) by (compute);
    assert(stderr_of(find_events(req(seq![seq![45u8, 76u8], seq![116u8]]), fs_tree(seq![116u8], false))) =~= Seq::<u8>::empty()) by (compute);
}

/// E3 `vfind t/`: no doubled `/`
proof fn spec_e3() {
    assert(printed(find_events(req(seq![seq![116u8, 47u8]]), fs_tree(seq![116u8, 47u8], false))) == seq![seq![116u8, 47u8], seq![116u8, 47u8, 46u8, 104u8], seq![116u8, 47u8, 97u8], seq![116u8, 47u8, 97u8, 47u8, 120u8], seq![116u8, 47u8, 97u8, 45u8, 99u8], seq![116u8, 47u8, 98u8], seq![116u8, 47u8, 108u8]]) by (compute);
    assert(printed(find_events(req(seq![seq![116u8, 47u8]]), fs_tree(seq![116u8, 47u8], false)))[1] != seq![116u8, 47u8, 47u8, 46u8, 104u8]) by (compute);
}

/// E4 `vfind` in `t`: the start path `.`
proof fn spec_e4() {
    assert(printed(find_events(req(seq![]), fs_tree(seq![46u8], false))) == seq![seq![46u8], seq![46u8, 47u8, 46u8, 104u8], seq![46u8, 47u8, 97u8], seq![46u8, 47u8, 97u8, 47u8, 120u8], seq![46u8, 47u8, 97u8, 45u8, 99u8], seq![46u8, 47u8, 98u8], seq![46u8, 47u8, 108u8]]) by (compute);
    // reject: `.h` without the `./` prefix; empty output
    assert(printed(find_events(req(seq![]), fs_tree(seq![46u8], false)))[1] != seq![46u8, 104u8]) by (compute);
    assert(printed(find_events(req(seq![]), fs_tree(seq![46u8], false))).len() != 0) by (compute);
}

/// E5 `vfind -L u` with `u/up -> .`: printed, not entered, loop error, exit 1
proof fn spec_e5() {
    assert(printed(find_events(req(seq![seq![45u8, 76u8], seq![117u8]]), fs_u())) == seq![seq![117u8], seq![117u8, 47u8, 117u8, 112u8]]) by (compute);
    assert(stderr_of(find_events(req(seq![seq![45u8, 76u8], seq![117u8]]), fs_u())) =~= seq![118u8, 102u8, 105u8, 110u8, 100u8, 58u8, 32u8, 102u8, 105u8, 108u8, 101u8, 115u8, 121u8, 115u8, 116u8, 101u8, 109u8, 32u8, 108u8, 111u8, 111u8, 112u8, 58u8, 32u8, 117u8, 47u8, 117u8, 112u8, 10u8]) by (compute);
    assert(find_events(req(seq![seq![45u8, 76u8], seq![117u8]]), fs_u()).last() == EventS::Exit(1)) by (compute);
    // reject: descending; omitting `u/up`; exit 0
    assert(printed(find_events(req(seq![seq![45u8, 76u8], seq![117u8]]), fs_u())) != seq![seq![117u8], seq![117u8, 47u8, 117u8, 112u8], seq![117u8, 47u8, 117u8, 112u8, 47u8, 117u8, 112u8]]) by (compute);
    assert(printed(find_events(req(seq![seq![45u8, 76u8], seq![117u8]]), fs_u())) != seq![seq![117u8]]) by (compute);
    assert(find_events(req(seq![seq![45u8, 76u8], seq![117u8]]), fs_u()).last() != EventS::Exit(0)) by (compute);
}

/// E6 `vfind u`: the symlink isn't followed, so no loop
proof fn spec_e6() {
    assert(printed(find_events(req(seq![seq![117u8]]), fs_u())) == seq![seq![117u8], seq![117u8, 47u8, 117u8, 112u8]]) by (compute);
    assert(stderr_of(find_events(req(seq![seq![117u8]]), fs_u())) =~= Seq::<u8>::empty()) by (compute);
    assert(find_events(req(seq![seq![117u8]]), fs_u()).last() == EventS::Exit(0)) by (compute);
}

/// E7 bind-mount loop without `-L`
proof fn spec_e7() {
    assert(printed(find_events(req(seq![seq![109u8]]), fs_m())) == seq![seq![109u8], seq![109u8, 47u8, 98u8]]) by (compute);
    assert(stderr_of(find_events(req(seq![seq![109u8]]), fs_m())) =~= seq![118u8, 102u8, 105u8, 110u8, 100u8, 58u8, 32u8, 102u8, 105u8, 108u8, 101u8, 115u8, 121u8, 115u8, 116u8, 101u8, 109u8, 32u8, 108u8, 111u8, 111u8, 112u8, 58u8, 32u8, 109u8, 47u8, 98u8, 10u8]) by (compute);
    assert(find_events(req(seq![seq![109u8]]), fs_m()).last() == EventS::Exit(1)) by (compute);
    // reject: entering `m/b`
    assert(printed(find_events(req(seq![seq![109u8]]), fs_m())) != seq![seq![109u8], seq![109u8, 47u8, 98u8], seq![109u8, 47u8, 98u8, 47u8, 98u8]]) by (compute);
}

/// E8 `vfind t missing t/b`
proof fn spec_e8() {
    assert(printed(find_events(req(seq![seq![116u8], seq![109u8, 105u8, 115u8, 115u8, 105u8, 110u8, 103u8], seq![116u8, 47u8, 98u8]]), fs_tree(seq![116u8], false))) == seq![seq![116u8], seq![116u8, 47u8, 46u8, 104u8], seq![116u8, 47u8, 97u8], seq![116u8, 47u8, 97u8, 47u8, 120u8], seq![116u8, 47u8, 97u8, 45u8, 99u8], seq![116u8, 47u8, 98u8], seq![116u8, 47u8, 108u8], seq![116u8, 47u8, 98u8]]) by (compute);
    assert(stderr_of(find_events(req(seq![seq![116u8], seq![109u8, 105u8, 115u8, 115u8, 105u8, 110u8, 103u8], seq![116u8, 47u8, 98u8]]), fs_tree(seq![116u8], false))) =~= seq![118u8, 102u8, 105u8, 110u8, 100u8, 58u8, 32u8, 109u8, 105u8, 115u8, 115u8, 105u8, 110u8, 103u8, 58u8, 32u8, 78u8, 111u8, 32u8, 115u8, 117u8, 99u8, 104u8, 32u8, 102u8, 105u8, 108u8, 101u8, 32u8, 111u8, 114u8, 32u8, 100u8, 105u8, 114u8, 101u8, 99u8, 116u8, 111u8, 114u8, 121u8, 10u8]) by (compute);
    assert(find_events(req(seq![seq![116u8], seq![109u8, 105u8, 115u8, 115u8, 105u8, 110u8, 103u8], seq![116u8, 47u8, 98u8]]), fs_tree(seq![116u8], false)).last() == EventS::Exit(1)) by (compute);
    // reject: exit 0; stopping at `missing`
    assert(find_events(req(seq![seq![116u8], seq![109u8, 105u8, 115u8, 115u8, 105u8, 110u8, 103u8], seq![116u8, 47u8, 98u8]]), fs_tree(seq![116u8], false)).last() != EventS::Exit(0)) by (compute);
    assert(printed(find_events(req(seq![seq![116u8], seq![109u8, 105u8, 115u8, 115u8, 105u8, 110u8, 103u8], seq![116u8, 47u8, 98u8]]), fs_tree(seq![116u8], false))) != seq![seq![116u8], seq![116u8, 47u8, 46u8, 104u8], seq![116u8, 47u8, 97u8], seq![116u8, 47u8, 97u8, 47u8, 120u8], seq![116u8, 47u8, 97u8, 45u8, 99u8], seq![116u8, 47u8, 98u8], seq![116u8, 47u8, 108u8]]) by (compute);
}

/// E9 unreadable directory `r`
proof fn spec_e9() {
    assert(printed(find_events(req(seq![seq![114u8]]), fs_dir(seq![100u8], seq![]))) == seq![seq![114u8]]) by (compute);
    assert(stderr_of(find_events(req(seq![seq![114u8]]), fs_dir(seq![100u8], seq![]))) =~= seq![118u8, 102u8, 105u8, 110u8, 100u8, 58u8, 32u8, 114u8, 58u8, 32u8, 80u8, 101u8, 114u8, 109u8, 105u8, 115u8, 115u8, 105u8, 111u8, 110u8, 32u8, 100u8, 101u8, 110u8, 105u8, 101u8, 100u8, 10u8]) by (compute);
    assert(find_events(req(seq![seq![114u8]]), fs_dir(seq![100u8], seq![])).last() == EventS::Exit(1)) by (compute);
    // reject: `r` not printed
    assert(printed(find_events(req(seq![seq![114u8]]), fs_dir(seq![100u8], seq![]))) != Seq::<Seq<u8>>::empty()) by (compute);
}

/// E10 a newline in a name: 2 lines for 2 paths
proof fn spec_e10() {
    assert(stdout_of(find_events(req(seq![seq![100u8]]), fs_dir(seq![100u8], seq![seq![97u8, 10u8, 98u8]]))) =~= seq![100u8, 10u8, 100u8, 47u8, 97u8, 92u8, 110u8, 98u8, 10u8]) by (compute);
    // reject: a forged third path `b`
    assert(stdout_of(find_events(req(seq![seq![100u8]]), fs_dir(seq![100u8], seq![seq![97u8, 10u8, 98u8]]))) != seq![100u8, 10u8, 100u8, 47u8, 97u8, 10u8, 98u8, 10u8]) by (compute);
}

/// E11 escaping of `:`, `\` and non-ASCII; sorted on raw bytes (`x:` < `x;`,
/// but escaped `x\:` > `x;`)
proof fn spec_e11() {
    assert(stdout_of(find_events(req(seq![seq![100u8]]), fs_dir(seq![100u8], seq![seq![120u8, 59u8], seq![120u8, 58u8], seq![98u8, 97u8, 99u8, 107u8, 92u8, 115u8, 108u8, 97u8, 115u8, 104u8], seq![99u8, 97u8, 102u8, 195u8, 169u8]]))) =~= seq![100u8, 10u8, 100u8, 47u8, 98u8, 97u8, 99u8, 107u8, 92u8, 92u8, 115u8, 108u8, 97u8, 115u8, 104u8, 10u8, 100u8, 47u8, 99u8, 97u8, 102u8, 92u8, 120u8, 99u8, 51u8, 92u8, 120u8, 97u8, 57u8, 10u8, 100u8, 47u8, 120u8, 92u8, 58u8, 10u8, 100u8, 47u8, 120u8, 59u8, 10u8]) by (compute);
}

/// E11 reject: the marker `:` left unescaped (a forged header)
proof fn spec_e11_reject_marker() {
    assert(stdout_of(find_events(req(seq![seq![100u8]]), fs_dir(seq![100u8], seq![seq![120u8, 59u8], seq![120u8, 58u8], seq![98u8, 97u8, 99u8, 107u8, 92u8, 115u8, 108u8, 97u8, 115u8, 104u8], seq![99u8, 97u8, 102u8, 195u8, 169u8]]))) != seq![100u8, 10u8, 100u8, 47u8, 98u8, 97u8, 99u8, 107u8, 92u8, 92u8, 115u8, 108u8, 97u8, 115u8, 104u8, 10u8, 100u8, 47u8, 99u8, 97u8, 102u8, 92u8, 120u8, 99u8, 51u8, 92u8, 120u8, 97u8, 57u8, 10u8, 100u8, 47u8, 120u8, 58u8, 10u8, 100u8, 47u8, 120u8, 59u8, 10u8]) by (compute);
}

/// E11 reject: `\` left unescaped (collides with an escape)
proof fn spec_e11_reject_backslash() {
    assert(stdout_of(find_events(req(seq![seq![100u8]]), fs_dir(seq![100u8], seq![seq![120u8, 59u8], seq![120u8, 58u8], seq![98u8, 97u8, 99u8, 107u8, 92u8, 115u8, 108u8, 97u8, 115u8, 104u8], seq![99u8, 97u8, 102u8, 195u8, 169u8]]))) != seq![100u8, 10u8, 100u8, 47u8, 98u8, 97u8, 99u8, 107u8, 92u8, 115u8, 108u8, 97u8, 115u8, 104u8, 10u8, 100u8, 47u8, 99u8, 97u8, 102u8, 92u8, 120u8, 99u8, 51u8, 92u8, 120u8, 97u8, 57u8, 10u8, 100u8, 47u8, 120u8, 92u8, 58u8, 10u8, 100u8, 47u8, 120u8, 59u8, 10u8]) by (compute);
}

/// E11 reject: sorted after escaping
proof fn spec_e11_reject_escaped_order() {
    assert(stdout_of(find_events(req(seq![seq![100u8]]), fs_dir(seq![100u8], seq![seq![120u8, 59u8], seq![120u8, 58u8], seq![98u8, 97u8, 99u8, 107u8, 92u8, 115u8, 108u8, 97u8, 115u8, 104u8], seq![99u8, 97u8, 102u8, 195u8, 169u8]]))) != seq![100u8, 10u8, 100u8, 47u8, 98u8, 97u8, 99u8, 107u8, 92u8, 92u8, 115u8, 108u8, 97u8, 115u8, 104u8, 10u8, 100u8, 47u8, 99u8, 97u8, 102u8, 92u8, 120u8, 99u8, 51u8, 92u8, 120u8, 97u8, 57u8, 10u8, 100u8, 47u8, 120u8, 59u8, 10u8, 100u8, 47u8, 120u8, 92u8, 58u8, 10u8]) by (compute);
}

/// E12 `vfind -L t` with a broken symlink `t/dead`: printed, no error
proof fn spec_e12() {
    assert(printed(find_events(req(seq![seq![45u8, 76u8], seq![116u8]]), fs_tree(seq![116u8], true))) == seq![seq![116u8], seq![116u8, 47u8, 46u8, 104u8], seq![116u8, 47u8, 97u8], seq![116u8, 47u8, 97u8, 47u8, 120u8], seq![116u8, 47u8, 97u8, 45u8, 99u8], seq![116u8, 47u8, 98u8], seq![116u8, 47u8, 100u8, 101u8, 97u8, 100u8], seq![116u8, 47u8, 108u8], seq![116u8, 47u8, 108u8, 47u8, 120u8]]) by (compute);
    assert(find_events(req(seq![seq![45u8, 76u8], seq![116u8]]), fs_tree(seq![116u8], true)).last() == EventS::Exit(0)) by (compute);
    assert(stderr_of(find_events(req(seq![seq![45u8, 76u8], seq![116u8]]), fs_tree(seq![116u8], true))) =~= Seq::<u8>::empty()) by (compute);
}

/// E13 usage errors; also `-L` after a path (D19)
proof fn spec_e13() {
    assert(find_events(req(seq![seq![45u8, 120u8], seq![116u8]]), fs_tree(seq![116u8], false)) == seq![EventS::Usage(seq![45u8, 120u8]), EventS::Exit(1)]) by (compute);
    assert(stderr_of(find_events(req(seq![seq![45u8, 120u8], seq![116u8]]), fs_tree(seq![116u8], false))) =~= seq![118u8, 102u8, 105u8, 110u8, 100u8, 58u8, 32u8, 117u8, 110u8, 107u8, 110u8, 111u8, 119u8, 110u8, 32u8, 111u8, 112u8, 116u8, 105u8, 111u8, 110u8, 32u8, 45u8, 120u8, 10u8, 117u8, 115u8, 97u8, 103u8, 101u8, 58u8, 32u8, 118u8, 102u8, 105u8, 110u8, 100u8, 32u8, 91u8, 45u8, 76u8, 93u8, 32u8, 91u8, 80u8, 65u8, 84u8, 72u8, 46u8, 46u8, 46u8, 93u8, 10u8]) by (compute);
    assert(find_events(req(seq![seq![116u8], seq![45u8, 110u8, 97u8, 109u8, 101u8], seq![97u8]]), fs_tree(seq![116u8], false)) == seq![EventS::Usage(seq![45u8, 110u8, 97u8, 109u8, 101u8]), EventS::Exit(1)]) by (compute);
    assert(find_events(req(seq![seq![45u8, 76u8], seq![45u8, 76u8], seq![116u8], seq![45u8, 76u8]]), fs_tree(seq![116u8], false)) == seq![EventS::Usage(seq![45u8, 76u8]), EventS::Exit(1)]) by (compute);
    // reject: listing `t` anyway
    assert(printed(find_events(req(seq![seq![116u8], seq![45u8, 110u8, 97u8, 109u8, 101u8], seq![97u8]]), fs_tree(seq![116u8], false))) == Seq::<Seq<u8>>::empty()) by (compute);
}

/// E14 `vfind t t/a`: duplicates are walked again
proof fn spec_e14() {
    assert(printed(find_events(req(seq![seq![116u8], seq![116u8, 47u8, 97u8]]), fs_tree(seq![116u8], false))) == seq![seq![116u8], seq![116u8, 47u8, 46u8, 104u8], seq![116u8, 47u8, 97u8], seq![116u8, 47u8, 97u8, 47u8, 120u8], seq![116u8, 47u8, 97u8, 45u8, 99u8], seq![116u8, 47u8, 98u8], seq![116u8, 47u8, 108u8], seq![116u8, 47u8, 97u8], seq![116u8, 47u8, 97u8, 47u8, 120u8]]) by (compute);
}

/// E15 robust core: empty, `.`, `..`, `/`-containing and duplicate names
proof fn spec_e15() {
    assert(printed(find_events(req(seq![seq![100u8]]), fs_dir(seq![100u8], seq![seq![98u8], Seq::<u8>::empty(), seq![46u8], seq![46u8, 46u8], seq![98u8], seq![120u8, 47u8, 121u8]]))) == seq![seq![100u8], seq![100u8, 47u8, 98u8]]) by (compute);
    // reject: `d/b` twice; a forged deeper path; an empty name
    assert(printed(find_events(req(seq![seq![100u8]]), fs_dir(seq![100u8], seq![seq![98u8], Seq::<u8>::empty(), seq![46u8], seq![46u8, 46u8], seq![98u8], seq![120u8, 47u8, 121u8]]))) != seq![seq![100u8], seq![100u8, 47u8, 98u8], seq![100u8, 47u8, 98u8]]) by (compute);
    assert(printed(find_events(req(seq![seq![100u8]]), fs_dir(seq![100u8], seq![seq![98u8], Seq::<u8>::empty(), seq![46u8], seq![46u8, 46u8], seq![98u8], seq![120u8, 47u8, 121u8]]))) != seq![seq![100u8], seq![100u8, 47u8, 98u8], seq![100u8, 47u8, 120u8, 47u8, 121u8]]) by (compute);
    assert(printed(find_events(req(seq![seq![100u8]]), fs_dir(seq![100u8], seq![seq![98u8], Seq::<u8>::empty(), seq![46u8], seq![46u8, 46u8], seq![98u8], seq![120u8, 47u8, 121u8]]))) != seq![seq![100u8], seq![100u8, 47u8], seq![100u8, 47u8, 98u8]]) by (compute);
}

/// E16 the path in an error message is escaped
proof fn spec_e16() {
    assert(stderr_of(find_events(req(seq![seq![97u8, 58u8, 32u8, 98u8]]), fs_dir(seq![100u8], seq![]))) =~= seq![118u8, 102u8, 105u8, 110u8, 100u8, 58u8, 32u8, 97u8, 92u8, 58u8, 32u8, 98u8, 58u8, 32u8, 80u8, 101u8, 114u8, 109u8, 105u8, 115u8, 115u8, 105u8, 111u8, 110u8, 32u8, 100u8, 101u8, 110u8, 105u8, 101u8, 100u8, 10u8]) by (compute);
    assert(stderr_of(find_events(req(seq![seq![97u8, 58u8, 32u8, 98u8]]), fs_dir(seq![100u8], seq![]))) != seq![118u8, 102u8, 105u8, 110u8, 100u8, 58u8, 32u8, 97u8, 58u8, 32u8, 98u8, 58u8, 32u8, 80u8, 101u8, 114u8, 109u8, 105u8, 115u8, 115u8, 105u8, 111u8, 110u8, 32u8, 100u8, 101u8, 110u8, 105u8, 101u8, 100u8, 10u8]) by (compute);
}

/// E17 the codec without its `:` rule violates C4.
proof fn spec_e17() {
    let pre = |b: u8| if b == 58u8 { seq![58u8] } else { <B as security_property::Codec>::code(b) };
    assert(!security_property::codec_conditions(pre, 10u8, 58u8)) by {
        assert(pre(58u8)[0] == 58u8);
    }
}

// ---- The step protocol ----------------------------------------------------

/// E1's first events and a faithful shell's answers; `answers_ok` is
/// satisfiable at every step count.
proof fn spec_protocol() {
    assert(find_events(req(seq![seq![116u8]]), fs_tree(seq![116u8], false)).take(3) == seq![
        EventS::Look(seq![116u8], false),
        EventS::Print(seq![116u8]),
        EventS::List(seq![116u8]),
    ]) by (compute);
    assert(answers_ok(fs_tree(seq![116u8], false), req(seq![seq![116u8]]), seq![], 0)) by (compute);
    assert(answers_ok(
        fs_tree(seq![116u8], false),
        req(seq![seq![116u8]]),
        seq![AnswerS::Look(LookS::Found(Kind::Dir, (1u64, 1u64)))],
        2,
    )) by (compute);
    assert(answers_ok(
        fs_tree(seq![116u8], false),
        req(seq![seq![116u8]]),
        seq![
            AnswerS::Look(LookS::Found(Kind::Dir, (1u64, 1u64))),
            AnswerS::List(ListingS::Names(seq![seq![98u8], seq![97u8], seq![46u8, 104u8], seq![97u8, 45u8, 99u8], seq![108u8]])),
        ],
        3,
    )) by (compute);
    // reject: the 4th event is the query `Look(t/.h)`, so after 4 steps a
    // third answer is due
    assert(!answers_ok(
        fs_tree(seq![116u8], false),
        req(seq![seq![116u8]]),
        seq![
            AnswerS::Look(LookS::Found(Kind::Dir, (1u64, 1u64))),
            AnswerS::List(ListingS::Names(seq![seq![98u8], seq![97u8], seq![46u8, 104u8], seq![97u8, 45u8, 99u8], seq![108u8]])),
        ],
        4,
    )) by (compute);
    // reject: an unfaithful answer
    assert(!answers_ok(
        fs_tree(seq![116u8], false),
        req(seq![seq![116u8]]),
        seq![AnswerS::Look(LookS::Missing(enoent()))],
        2,
    )) by (compute);
    // 17 events: 3 for `t`, 2 for each of `.h`, `a-c`, `b`, `l`, 3 for `t/a`,
    // 2 for `t/a/x`, then `Exit`
    assert(find_events(req(seq![seq![116u8]]), fs_tree(seq![116u8], false)).len() == 17) by (compute);
}

} // verus!

// ===========================================================================
// Runtime tests: the intent's Examples against the implementation, driven
// like the shell drives it (run once the kata is implemented).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const ENOENT: &[u8] = b"No such file or directory";
    const EACCES: &[u8] = b"Permission denied";

    /// Drive a Walker like the shell does; panics if it doesn't exit.
    fn run(
        args: &[&[u8]],
        look: &dyn Fn(&[u8], bool) -> Look,
        list: &dyn Fn(&[u8]) -> Listing,
    ) -> (Vec<u8>, Vec<u8>, u8) {
        let mut w = Walker::new(&Request { args: args.iter().map(|a| a.to_vec()).collect() });
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut answer = None;
        for _ in 0..100_000 {
            match w.next(answer.take()) {
                Step::Look(p, f) => answer = Some(Answer::Look(look(&p, f))),
                Step::List(p) => answer = Some(Answer::List(list(&p))),
                Step::Stdout(b) => out.extend_from_slice(&b),
                Step::Stderr(b) => err.extend_from_slice(&b),
                Step::Exit(c) => return (out, err, c),
            }
        }
        panic!("no Exit after 100000 steps");
    }

    fn join(p: &[u8], n: &[u8]) -> Vec<u8> {
        if p.last() == Some(&b'/') { [p, n].concat() } else { [p, b"/", n].concat() }
    }

    /// The intent's tree `t/` rooted at `root`.
    fn tree(root: &[u8], dead: bool) -> (impl Fn(&[u8], bool) -> Look + '_, impl Fn(&[u8]) -> Listing + '_) {
        let look = move |p: &[u8], f: bool| {
            let j = |n: &[u8]| join(root, n);
            if p == root {
                Look::Found(Kind::Dir, 1, 1)
            } else if p == j(b"a") {
                Look::Found(Kind::Dir, 1, 2)
            } else if p == j(b"l") {
                if f { Look::Found(Kind::Dir, 1, 2) } else { Look::Found(Kind::Symlink, 1, 7) }
            } else if p == join(&j(b"a"), b"x") || p == join(&j(b"l"), b"x") {
                Look::Found(Kind::Other, 1, 3)
            } else if p == j(b".h") || p == j(b"a-c") || p == j(b"b") {
                Look::Found(Kind::Other, 1, 4)
            } else if dead && p == j(b"dead") {
                Look::Found(Kind::Symlink, 1, 8)
            } else {
                Look::Missing(ENOENT.to_vec())
            }
        };
        let list = move |p: &[u8]| {
            if p == root {
                let mut ns: Vec<Vec<u8>> = vec![b"b".to_vec(), b"a".to_vec(), b".h".to_vec(), b"a-c".to_vec(), b"l".to_vec()];
                if dead {
                    ns.push(b"dead".to_vec());
                }
                Listing::Names(ns)
            } else if p == join(root, b"a") || p == join(root, b"l") {
                Listing::Names(vec![b"x".to_vec()])
            } else {
                Listing::Unreadable(EACCES.to_vec())
            }
        };
        (look, list)
    }

    /// Directory `d` with the given entries (files); other paths are
    /// unreadable directories.
    fn dir<'a>(names: &'a [&'a [u8]]) -> (impl Fn(&[u8], bool) -> Look, impl Fn(&[u8]) -> Listing + 'a) {
        let look = |p: &[u8], _f: bool| {
            if p == b"d" {
                Look::Found(Kind::Dir, 5, 1)
            } else if p.starts_with(b"d/") {
                Look::Found(Kind::Other, 5, 2)
            } else {
                Look::Found(Kind::Dir, 5, 3)
            }
        };
        let list = move |p: &[u8]| {
            if p == b"d" {
                Listing::Names(names.iter().map(|n| n.to_vec()).collect())
            } else {
                Listing::Unreadable(EACCES.to_vec())
            }
        };
        (look, list)
    }

    const E1: &[u8] = b"t\nt/.h\nt/a\nt/a/x\nt/a-c\nt/b\nt/l\n";

    #[test]
    fn e1_preorder_bytewise() {
        let (look, list) = tree(b"t", false);
        assert_eq!(run(&[b"t"], &look, &list), (E1.to_vec(), vec![], 0));
    }

    #[test]
    fn e2_follow() {
        let (look, list) = tree(b"t", false);
        let out = b"t\nt/.h\nt/a\nt/a/x\nt/a-c\nt/b\nt/l\nt/l/x\n".to_vec();
        assert_eq!(run(&[b"-L", b"t"], &look, &list), (out, vec![], 0));
    }

    #[test]
    fn e3_trailing_slash() {
        let (look, list) = tree(b"t/", false);
        let out = b"t/\nt/.h\nt/a\nt/a/x\nt/a-c\nt/b\nt/l\n".to_vec();
        assert_eq!(run(&[b"t/"], &look, &list), (out, vec![], 0));
    }

    #[test]
    fn e4_default_dot() {
        let (look, list) = tree(b".", false);
        let out = b".\n./.h\n./a\n./a/x\n./a-c\n./b\n./l\n".to_vec();
        assert_eq!(run(&[], &look, &list), (out, vec![], 0));
    }

    fn u_look(p: &[u8], f: bool) -> Look {
        match (p, f) {
            (b"u", _) | (b"u/up", true) => Look::Found(Kind::Dir, 2, 1),
            (b"u/up", false) => Look::Found(Kind::Symlink, 2, 2),
            _ => Look::Missing(ENOENT.to_vec()),
        }
    }

    fn u_list(p: &[u8]) -> Listing {
        if p == b"u" { Listing::Names(vec![b"up".to_vec()]) } else { Listing::Unreadable(EACCES.to_vec()) }
    }

    #[test]
    fn e5_symlink_loop() {
        let r = run(&[b"-L", b"u"], &u_look, &u_list);
        assert_eq!(r, (b"u\nu/up\n".to_vec(), b"vfind: filesystem loop: u/up\n".to_vec(), 1));
    }

    #[test]
    fn e6_symlink_not_followed() {
        assert_eq!(run(&[b"u"], &u_look, &u_list), (b"u\nu/up\n".to_vec(), vec![], 0));
    }

    #[test]
    fn e7_bind_mount_loop() {
        let look = |p: &[u8], _f: bool| {
            if p == b"m" || p == b"m/b" { Look::Found(Kind::Dir, 3, 1) } else { Look::Missing(ENOENT.to_vec()) }
        };
        let list = |_p: &[u8]| Listing::Names(vec![b"b".to_vec()]);
        let r = run(&[b"m"], &look, &list);
        assert_eq!(r, (b"m\nm/b\n".to_vec(), b"vfind: filesystem loop: m/b\n".to_vec(), 1));
    }

    #[test]
    fn e8_missing_start_path() {
        let (look, list) = tree(b"t", false);
        let r = run(&[b"t", b"missing", b"t/b"], &look, &list);
        let out = [E1, b"t/b\n"].concat();
        assert_eq!(r, (out, b"vfind: missing: No such file or directory\n".to_vec(), 1));
    }

    #[test]
    fn e9_unreadable_dir() {
        let (look, list) = dir(&[]);
        assert_eq!(run(&[b"r"], &look, &list), (b"r\n".to_vec(), b"vfind: r: Permission denied\n".to_vec(), 1));
    }

    #[test]
    fn e10_newline_in_name() {
        let (look, list) = dir(&[b"a\nb"]);
        let (out, err, code) = run(&[b"d"], &look, &list);
        assert_eq!((out.as_slice(), err.as_slice(), code), (&b"d\nd/a\\nb\n"[..], &b""[..], 0));
        assert_eq!(out.iter().filter(|&&c| c == b'\n').count(), 2);
    }

    #[test]
    fn e11_escaping_and_raw_order() {
        let names: [&[u8]; 4] = [b"x;", b"x:", b"back\\slash", "café".as_bytes()];
        let (look, list) = dir(&names);
        let out = b"d\nd/back\\\\slash\nd/caf\\xc3\\xa9\nd/x\\:\nd/x;\n".to_vec();
        assert_eq!(run(&[b"d"], &look, &list), (out, vec![], 0));
    }

    #[test]
    fn e12_broken_symlink_under_follow() {
        let (look, list) = tree(b"t", true);
        let out = b"t\nt/.h\nt/a\nt/a/x\nt/a-c\nt/b\nt/dead\nt/l\nt/l/x\n".to_vec();
        assert_eq!(run(&[b"-L", b"t"], &look, &list), (out, vec![], 0));
    }

    #[test]
    fn e13_usage() {
        let (look, list) = tree(b"t", false);
        let usage = b"usage: vfind [-L] [PATH...]\n";
        assert_eq!(run(&[b"-x", b"t"], &look, &list), (vec![], [&b"vfind: unknown option -x\n"[..], usage].concat(), 1));
        assert_eq!(run(&[b"t", b"-name", b"a"], &look, &list), (vec![], [&b"vfind: unknown option -name\n"[..], usage].concat(), 1));
        assert_eq!(run(&[b"t", b"-L"], &look, &list), (vec![], [&b"vfind: unknown option -L\n"[..], usage].concat(), 1));
    }

    #[test]
    fn e14_duplicate_start_paths() {
        let (look, list) = tree(b"t", false);
        let out = [E1, b"t/a\nt/a/x\n"].concat();
        assert_eq!(run(&[b"t", b"t/a"], &look, &list), (out, vec![], 0));
    }

    #[test]
    fn e15_robust_names() {
        let (look, list) = dir(&[b"b", b"", b".", b"..", b"b", b"x/y"]);
        assert_eq!(run(&[b"d"], &look, &list), (b"d\nd/b\n".to_vec(), vec![], 0));
    }

    #[test]
    fn e16_escaped_error_path() {
        let (look, list) = dir(&[]);
        let r = run(&[b"a: b"], &look, &list);
        assert_eq!(r, (b"a\\: b\n".to_vec(), b"vfind: a\\: b: Permission denied\n".to_vec(), 1));
    }
}
