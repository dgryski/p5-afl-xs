
This blog post will walk through the steps required to fuzz a Perl XS module
with American Fuzzy Lop, the coverage-based fuzzing tool.

At Booking.com, we use Perl.  A lot.  Perl has a lot of upsides for us (which I
won't go into), and it has been a large factor in our success.  For many,
though, the biggest downside can be its speed.  Being an interpreted language,
it runs 10x-100x slower for CPU intensive tasks.  When Perl isn't fast
enough, the most common thing to do is write XS modules.  But XS modules are in
C, and writing safe, secure C is hard. (Side note: one of my coworkers gave a
[presentation](https://www.youtube.com/watch?v=GwS8eDOYz_U) on [writing XS
modules in Rust](https://github.com/vickenty/perl-xs) ) Most of the time we can
get away with unit tests and code review.  But for parsers, you need to go one
step further: fuzzing.

A few years ago, we decided to create our own serialization format.
[Sereal](http://github.com/Sereal/Sereal) grew out of our dissatisfaction with
existing Perl serialization options.  (More details can be found in the
original
[announcement](http://blog.booking.com/sereal-a-binary-data-serialization-format.html)
.) While Sereal is geared towards dynamic languages (and Perl in particular),
there are now high-quality Go and Java implementations to match our more
diverse tech stack.

Fuzzing is mostly used in computer security industry to find exploits.  I
wasn't expecting our Sereal decoders to be attack vectors, but rather I wanted
to be able to handle errors from corrupted data.  Errors happen all the time at
scale.  We joke that a "one in a million" problem is happening 20 times a day.
And there are real reasons why our deserialization code will need to handle bad
data.  Maybe a data packet will get truncated in a database column because it's
too big.  Maybe it will pass through a system which adds utf8 encoding.  In all
these cases, it's much better to return an error to the user than to segfault.

So, how do you get bad data?  Well, the easiest way is to start with a corpus
of good data and change it slightly.  Then, you see if your change had any
effect.  If the new input causes a crash, great! You just found a bug.  If the
new input caused the program to hit new code paths, it's marked as
"interesting" and added back to the corpus.

This is called "coverage guided fuzzing".  For the Go implementation, I was
able to use the excellent [go-fuzz](http://github.com/dvyukov/go-fuzz) package
from Dmitry Vyukov.  The Perl module, being an XS module which is loaded into
the Perl executable at runtime was a bit trickier.  However, it can be done
using [American Fuzzy Lop](http://lcamtuf.coredump.cx/afl/).  (The strange name
comes from a species of particularly [fuzzy
bunnies](https://en.wikipedia.org/wiki/American_Fuzzy_Lop).)

AFL is normally used for C libraries where it's easy to write a small program
to feed corrupted input directly into the function you want to test.  Fuzzing
an interpreter is a bit more complicated.  First, we have to build the perl
binary with AFL.  Then we need to build the Sereal XS module with AFL.  Then we
need to write a perl script that the instrumented perl binary runs that will
load the instrumented XS module and pass in our fuzzed input.  Phew.

This took me a few tries to get every detail correctly sorted out.

First, build the latest release of AFL.  We're going to be using the LLVM mode,
which means you need to have a recent LLVM install on your machine.  My Ubuntu
install has 3.8, so that's what I used.  When you read this, the version number
of AFL might be different.

```
curl http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
tar xf afl-latest.tgz
cd afl-2.32b
make
cd llvm_mode
LLVM_CONFIG=llvm-config-3.8 make
```

Next, clone the Perl source code and build that with AFL

```
git clone git://perl5.git.perl.org/perl.git perl
```

Or from the GitHub mirror:
```
git clone https://github.com/Perl/perl5
```

Next, configure Perl to use AFL as the compiler and install it in a custom perl-afl directory.

```
sh Configure -des -Dusedevel \
    -Dcc=/home/dgryski/src/afl-2.32b/afl-clang-fast
    -Dprefix=/home/dgryski/src/perl-afl \
    -Dld=/home/dgryski/src/afl-2.32b/afl-clang-fast \
    -Dloclibpth=' '
```

In order to AFL to recognize that we want to use persistent mode while fuzzing
(more below), we need to insert a tiny patch at the start of Perl's main
function.  The perl build system is pretty hairy, but edit
`ext/ExtUtils-Miniperl/lib/ExtUtils/Miniperl.pm` and add the following line as
a declaration before `main()`: This magic constant is detected by AFL.

```
volatile char *__afl_persistent_sig = "##SIG_AFL_PERSISTENT##";
```

This will add sufficient magic for AFL's detection to work.

Now, build and install perl.  The binaries that are installed will have the
Perl version number attached to them.  By the time you read this, the perl
version might be different, so you'll need to adjust the instructions.

```
make
make install
```

Next we need a target to fuzz.  I've created a small XS module to make this
easier.  All it does it check if the input starts with `ABCD` and crashes if it
does.

First, generate all the boilerplate we need for the module:

```
~/src/perl-afl/bin/h2xs5.25.5 -A -n Fuzz
```

Then add the following to `Fuzz.xs`

```
void
fuzzme(input)
    char *input
    CODE:
        if (strlen(input) < 4) {
            return ;
        }

        if (input[0] == 'A') {
            if (input[1] == 'B') {
                if (input[2] == 'C') {
                    if (input[3] == 'D') {
                        abort();
                    }
                }
            }
        }
```

Finally, we need to add a routine to our fuzzing module to call back into AFL's persistent mode handler:

```
int
afl_persistent_loop(count)
    unsigned int count;
    CODE:
        extern int __afl_persistent_loop(unsigned int);
        RETVAL = __afl_persistent_loop(count);
    OUTPUT:
        RETVAL
```

Now, build the module.  Perl will automatically use the compiler it was built with, which in our case is AFL.

```
~/src/perl-afl/bin/perl5.25.5 Makefile.PL
make
```

Next, our perl script that will feed the input from STDIN (where AFL will put
it ) to our buggy XS module.  Note this script is using AFL's [persistent
mode](https://lcamtuf.blogspot.nl/2015/06/new-in-afl-persistent-mode.html) to
avoid spawning the perl interpreter for every test case.

Here's our test script, `afl.pl`:
```
use blib "Fuzz/blib";
use Fuzz;

while(Fuzz::afl_persistent_loop(1000)) {
    my $input;
    sysread(STDIN, $input, 1024);
    Fuzz::fuzzme($input);
}
```

And we'll test that we correctly have a broken module:

```
bash$ echo "ABCD" | ~/src/perl-afl/bin/perl5.25.4 afl.pl
Aborted (core dumped)
bash$ echo "1234" | ~/src/perl-afl/bin/perl5.25.4 afl.pl
bash$
```

Create input corpus:
```
mkdir corpus && echo 1234 > corpus/input
```

Finally, start the fuzzing!

```
~/src/afl-2.32b/afl-fuzz \
    -i ./corpus/ \
    -o ./crashers/ \
    -- \
    ~/src/perl-afl/bin/perl5.25.5 afl.pl
```

Now we wait.  On my laptop I get ~50 execs per second per core, which is slow. :(

I'm not going to explain how to read afl's status screen -- there are lots of
resources online for that.  However, know that inputs that cause the program to
crash will be found in the `./crashers/crashes` directory.

Another environment variable we can set when building perl is `AFL_USE_ASAN=1`.
This links the perl binary against Google's [Address
Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer) plugin.
This will unfortunately slow down AFL to about half of what it's running now,
but it catches a larger class of bugs that don't necessarily trigger a crash,
only an out-of-bounds memory read.  You will also need to build the XS module
with `AFL_USE_ASAN=1` set.
