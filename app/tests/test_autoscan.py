from types import SimpleNamespace as NS

from telethon.tl.types import (InlineButtonTypeUrl, KeyboardInlineButton, KeyboardInlineButtonRow,
                               MessageEntityTextUrl, ReplyInlineMarkup)

from tgviewer import autoscan
from tgviewer.config import settings


def test_message_urls_finds_visible_hidden_and_button_links():
    msg = NS(message="Invoice: https://pay.example.com/i/1 and www.other.example (see https://pay.example.com/i/1)",
             entities=[MessageEntityTextUrl(offset=0, length=7, url="https://hidden.example/x")],
             reply_markup=ReplyInlineMarkup(rows=[KeyboardInlineButtonRow(buttons=[
                 KeyboardInlineButton(text="Open", type=InlineButtonTypeUrl(url="https://button.example/go"))])]))
    assert autoscan.message_urls(msg) == [
        "https://pay.example.com/i/1", "www.other.example", "https://hidden.example/x", "https://button.example/go"]


def test_message_urls_empty_and_limited():
    assert autoscan.message_urls(NS(message=None, entities=None, reply_markup=None)) == []
    many = " ".join(f"https://e{i}.example/" for i in range(50))
    assert len(autoscan.message_urls(NS(message=many, entities=None, reply_markup=None))) == autoscan.MAX_LINKS_PER_MESSAGE


def test_should_scan_file_rules():
    mb = 2**20
    assert autoscan.should_scan_file("private", 1 * mb, False) == (True, "")
    assert autoscan.should_scan_file("group", 1 * mb, False)[0]
    assert not autoscan.should_scan_file("channel", 1 * mb, False)[0]  # off by default
    assert not autoscan.should_scan_file("private", (settings.auto_scan_max_mb + 1) * mb, False)[0]
    assert not autoscan.should_scan_file("private", 1 * mb, True)[0]  # own outgoing message
