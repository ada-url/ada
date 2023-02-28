
#include <cstdlib>
#include <iostream>

#include "ada.h"


/**
 * Node.js has a function called url.pathToFileURL(path).
 * https://nodejs.org/api/url.html#urlpathtofileurlpath
 *
 * It is explained as follows...
 *
 * This function ensures that path is resolved absolutely,
 * and that the URL control characters are correctly encoded when converting into a File URL.
 *
 * new URL('/foo#1', 'file:');           // Incorrect: file:///foo#1
 * pathToFileURL('/foo#1');              // Correct:   file:///foo%231 (POSIX)
 *
 * new URL('/some/path%.c', 'file:');    // Incorrect: file:///some/path%.c
 * pathToFileURL('/some/path%.c');       // Correct:   file:///some/path%25.c (POSIX)
 *
 * It is unclear why node states that 'file:///some/path%.c' is incorrect. Any path part of URL should
 * be percent decoded prior to intepreting it as a path. Yet both /some/path%.c and /some/path%25.c
 * should, after percent decoding, become /some/path%.c. Maybe the intention is that the path are to be
 * treated verbatim?
 *
 * For reference, the path percent-encode set is:
 *
 * U+0020 SPACE, U+0022 ("), U+0023 (#), U+003C (<), and U+003E (>), U+003F (?), U+0060 (`), U+007B ({), and U+007D (}).
 * C0 controls:  range U+0000 NULL to U+001F INFORMATION SEPARATOR ONE, inclusive.
 * and all code points greater than U+007E (~).
 *
 * Thus '%' is allowed as a path character in a URL.
 * 
 * What does the reference to POSIX means?
 *
 * Under many operating systems, including common Linux distributions and macos,
 * both file names path%.c and path%25.c are allowed as one can easily check.
 *
 * Type the following commands in a shell:
 *
 * touch path%.c
 * touch path%25.c
 * ls path*
 *
 * You can distinguish between the two in path if you use percent encoding: path%25.c and path%2525.c.
 *
 * Which path names are legal typically does not just depend on the operating system, it also depends
 * critical on the file system.
 */
bool check_path_setters() {
    // It seems that the spec allows '%' without two Hex next to it, as long as it is not part
    // of a setter.
    ada::result url_direct1 = ada::parse("file:///some/path%.c");
    if(url_direct1->get_href() != "file:///some/path%.c") { return false; }

    // This is the equivalent:
    ada::result url_direct2 = ada::parse("file:///some/path%25.c");
    if(url_direct2->get_href() != "file:///some/path%25.c") { return false; }

    // Are url_direct1 and url_direct2 the same URL?



    ada::result url = ada::parse("file://");
    if(!url->set_pathname("/foo#1")) { return false; }
    if(url->get_href() != "file:///foo%231") { return false; }

    url->set_pathname("/some/path%25.c");
    if(url->get_href() != "file:///some/path%25.c") {
        std::cerr << url->get_href() << std::endl;
        return false;
    }

    /**
     * https://url.spec.whatwg.org/#path-state
     * If c is U+0025 (%) and remaining does not start with two ASCII hex digits, invalid-URL-unit validation error.
     * A validation error indicates a mismatch between input and valid input. User agents, especially conformance checkers, 
     * are encouraged to report them somewhere.
     * A validation error does not mean that the parser terminates. Termination of a parser is always stated explicitly, 
     * e.g., through a return statement.
     */
    if(url->set_pathname("/some/path%.c")) {
        std::cerr << "A percent character in 'set_pathname' should be followed by two ASCII hex digits." << std::endl;
    }
    if(url->get_href() != "file:///some/path%.c") {
        std::cerr << url->get_href() << std::endl;
        return false;
    }
    return true;
}

int main() {
    return check_path_setters() ? EXIT_SUCCESS : EXIT_FAILURE;
}
