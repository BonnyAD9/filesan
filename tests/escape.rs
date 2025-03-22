use filesan::{CharFlags, escape_str};

#[test]
fn esc() {
    assert_eq!(
        escape_str("\x00hello/the_re.txt:.", '_', CharFlags::NONE),
        "\x00hello/the_5Fre.txt:."
    );
    assert_eq!(
        escape_str("\x00hello/the_re.txt:.", '_', CharFlags::UNIX),
        "_00hello_2Fthe_5Fre.txt:."
    );
    assert_eq!(
        escape_str("\x00hello/the_re.txt:.", '_', CharFlags::WINDOWS),
        "_00hello_2Fthe_5Fre.txt_3A_2E"
    );
    assert_eq!(
        escape_str("\x00hello/the_re.txt:.", '_', CharFlags::MAC),
        "_00hello_2Fthe_5Fre.txt_3A."
    );

    assert_eq!(escape_str("..", '_', CharFlags::UNIX), "_..");
    assert_eq!(escape_str("..", '_', CharFlags::WINDOWS), "._2E");
    assert_eq!(escape_str("..", '_', CharFlags::MAC), "_..");

    assert_eq!(escape_str("...txt", '_', CharFlags::UNIX), "...txt");
    assert_eq!(escape_str("...txt", '_', CharFlags::WINDOWS), "...txt");
    assert_eq!(escape_str("...txt", '_', CharFlags::MAC), "...txt");

    assert_eq!(escape_str("NUL", '_', CharFlags::UNIX), "NUL");
    assert_eq!(escape_str("NUL", '_', CharFlags::WINDOWS), "_NUL");
    assert_eq!(escape_str("NUL", '_', CharFlags::MAC), "NUL");

    assert_eq!(escape_str("NUL.txt", '_', CharFlags::UNIX), "NUL.txt");
    assert_eq!(escape_str("NUL.txt", '_', CharFlags::WINDOWS), "_NUL.txt");
    assert_eq!(escape_str("NUL.txt", '_', CharFlags::MAC), "NUL.txt");
}
