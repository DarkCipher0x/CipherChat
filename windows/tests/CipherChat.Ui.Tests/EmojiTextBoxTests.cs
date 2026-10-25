using System.Windows.Controls;
using System.Windows.Documents;
using CipherChat.Ui;

namespace CipherChat.Ui.Tests;

/// <summary>The message box: plain text in and out, emoji shown as colour pictures, nothing lost or changed.</summary>
public class EmojiTextBoxTests
{
    private static void Sta(Action a)
    {
        Exception? error = null;
        var t = new Thread(() => { try { a(); } catch (Exception e) { error = e; } });
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join();
        if (error is not null) throw new Xunit.Sdk.XunitException(error.ToString());
    }

    private static int Pictures(EmojiTextBox b) =>
        b.Document.Blocks.OfType<Paragraph>().SelectMany(p => p.Inlines).OfType<InlineUIContainer>().Count();

    [Theory]
    [InlineData("hello")]
    [InlineData("hi 👋 there ❤️!")]
    [InlineData("👨‍👩‍👧 family, 👍🏽 tone, 🇬🇧 flag, 1️⃣ keycap")]
    [InlineData("line one\nline two 🎉\n\nline four")]
    [InlineData("terminal glyphs ☺ ↩ ✎ stay text")]
    public void Text_round_trips_exactly(string s) => Sta(() =>
    {
        var b = new EmojiTextBox { Text = s };
        Assert.Equal(s, b.Text);
    });

    [Fact]
    public void Emoji_become_colour_pictures() => Sta(() =>
    {
        var b = new EmojiTextBox { Text = "ok 👍 and ❤️ but not ☺" };
        Assert.Equal(2, Pictures(b));
    });

    [Fact]
    public void Picker_inserts_at_the_caret() => Sta(() =>
    {
        var b = new EmojiTextBox { Text = "ab" };
        b.CaretPosition = b.Document.ContentStart.GetPositionAtOffset(3) ?? b.CaretPosition;    // between a and b
        b.InsertAtCaret("🎉");
        Assert.Equal("a🎉b", b.Text);
        Assert.Equal(1, Pictures(b));
        b.InsertAtCaret("🔥");
        Assert.Equal("a🎉🔥b", b.Text);
    });

    [Fact]
    public void Clear_empties_it() => Sta(() =>
    {
        var b = new EmojiTextBox { Text = "x 🎉" };
        b.Clear();
        Assert.Equal("", b.Text);
        Assert.Equal(0, Pictures(b));
    });

    [Fact]
    public void Typed_text_is_converted() => Sta(() =>
    {
        var b = new EmojiTextBox();
        b.CaretPosition.InsertTextInRun("typed 🚀 here");        // what typing or the Win+. panel does
        Assert.Equal("typed 🚀 here", b.Text);
        Assert.Equal(1, Pictures(b));
    });
}
