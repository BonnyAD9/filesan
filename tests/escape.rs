use filesan::{Mode, escape_str};

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

    assert_eq!(escape_str("..", '_', Mode::UNIX), "_..");
    assert_eq!(escape_str("..", '_', Mode::WINDOWS), "._2E");
    assert_eq!(escape_str("..", '_', Mode::MAC), "_..");

    assert_eq!(escape_str("...txt", '_', Mode::UNIX), "...txt");
    assert_eq!(escape_str("...txt", '_', Mode::WINDOWS), "...txt");
    assert_eq!(escape_str("...txt", '_', Mode::MAC), "...txt");

    assert_eq!(escape_str("NUL", '_', Mode::UNIX), "NUL");
    assert_eq!(escape_str("NUL", '_', Mode::WINDOWS), "_NUL");
    assert_eq!(escape_str("NUL", '_', Mode::MAC), "NUL");

    assert_eq!(escape_str("NUL.txt", '_', Mode::UNIX), "NUL.txt");
    assert_eq!(escape_str("NUL.txt", '_', Mode::WINDOWS), "_NUL.txt");
    assert_eq!(escape_str("NUL.txt", '_', Mode::MAC), "NUL.txt");
}
