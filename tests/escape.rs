use filesan::{Mode, escape_str, replace_escape};

#[test]
fn esc() {
    assert_eq!(
        escape_str("\x00hello/the_re.txt:.", '_', Mode::NONE),
        "\x00hello/the_5Fre.txt:."
    );
    assert_eq!(
        escape_str("\x00hello/the_re.txt:.", '_', Mode::UNIX),
        "_00hello_2Fthe_5Fre.txt:."
    );
    assert_eq!(
        escape_str("\x00hello/the_re.txt:.", '_', Mode::WINDOWS),
        "_00hello_2Fthe_5Fre.txt_3A_2E"
    );
    assert_eq!(
        escape_str("\x00hello/the_re.txt:.", '_', Mode::MAC),
        "_00hello_2Fthe_5Fre.txt_3A."
    );

    assert_eq!(escape_str("..", '_', Mode::UNIX), "_2E.");
    assert_eq!(escape_str("..", '_', Mode::WINDOWS), "._2E");
    assert_eq!(escape_str("..", '_', Mode::MAC), "_2E.");
    assert_eq!(escape_str("..", '_', Mode::UNIX | Mode::WINDOWS), "_2E_2E");

    assert_eq!(escape_str("...txt", '_', Mode::UNIX), "...txt");
    assert_eq!(escape_str("...txt", '_', Mode::WINDOWS), "...txt");
    assert_eq!(escape_str("...txt", '_', Mode::MAC), "...txt");

    assert_eq!(escape_str("NUL", '_', Mode::UNIX), "NUL");
    assert_eq!(escape_str("NUL", '_', Mode::WINDOWS), "_4EUL");
    assert_eq!(escape_str("NUL", '_', Mode::MAC), "NUL");

    assert_eq!(escape_str("NUL.txt", '_', Mode::UNIX), "NUL.txt");
    assert_eq!(escape_str("NUL.txt", '_', Mode::WINDOWS), "_4EUL.txt");
    assert_eq!(escape_str("NUL.txt", '_', Mode::MAC), "NUL.txt");
}

#[test]
fn replace() {
    assert_eq!(
        replace_escape("\x00hello/the_re.txt:.", '_', Mode::NONE),
        "\x00hello/the_re.txt:."
    );
    assert_eq!(
        replace_escape("\x00hello/the_re.txt:.", '_', Mode::UNIX),
        "_hello_the_re.txt:."
    );
    assert_eq!(
        replace_escape("\x00hello/the_re.txt:.", '_', Mode::WINDOWS),
        "_hello_the_re.txt__"
    );
    assert_eq!(
        replace_escape("\x00hello/the_re.txt:.", '_', Mode::MAC),
        "_hello_the_re.txt_."
    );
    assert_eq!(
        replace_escape("\x00hello/the_re.txt:.", '_', Mode::ALL),
        "_hello_the_re.txt__"
    );

    assert_eq!(replace_escape("..", '_', Mode::UNIX), "_.");
    assert_eq!(replace_escape("..", '_', Mode::WINDOWS), "._");
    assert_eq!(replace_escape("..", '_', Mode::MAC), "_.");
    assert_eq!(replace_escape("..", '_', Mode::UNIX | Mode::WINDOWS), "__");

    assert_eq!(replace_escape("...txt", '_', Mode::UNIX), "...txt");
    assert_eq!(replace_escape("...txt", '_', Mode::WINDOWS), "...txt");
    assert_eq!(replace_escape("...txt", '_', Mode::MAC), "...txt");

    assert_eq!(replace_escape("NUL", '_', Mode::UNIX), "NUL");
    assert_eq!(replace_escape("NUL", '_', Mode::WINDOWS), "_UL");
    assert_eq!(replace_escape("NUL", '_', Mode::MAC), "NUL");

    assert_eq!(replace_escape("NUL.txt", '_', Mode::UNIX), "NUL.txt");
    assert_eq!(replace_escape("NUL.txt", '_', Mode::WINDOWS), "_UL.txt");
    assert_eq!(replace_escape("NUL.txt", '_', Mode::MAC), "NUL.txt");
}
