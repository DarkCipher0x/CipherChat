using CipherChat.Ui;

namespace CipherChat.Ui.Tests;

/// <summary>Colour emoji: which text counts as emoji (whole sequences), and that Windows draws them in colour.</summary>
public class ColorEmojiTests
{
    [Theory]
    [InlineData("😀")]
    [InlineData("❤️")]                          // a text-default heart made emoji by VS16
    [InlineData("👍🏽")]                          // skin tone
    [InlineData("👨‍👩‍👧")]                       // ZWJ family: one emoji
    [InlineData("🇬🇧")]                          // flag (two regional indicators)
    [InlineData("1️⃣")]                          // keycap
    [InlineData("✅")]                           // BMP, emoji by default
    public void Emoji_sequences_are_one_emoji(string e)
    {
        var parts = ColorEmoji.Split(e).ToList();
        Assert.Single(parts);
        Assert.True(parts[0].IsEmoji);
        Assert.Equal(e, parts[0].Text);
    }

    [Theory]
    [InlineData("☺")]                           // the terminal's own glyphs stay text
    [InlineData("↩")]
    [InlineData("✎")]
    [InlineData("©")]
    [InlineData("plain text")]
    public void Text_symbols_stay_text(string s) => Assert.False(ColorEmoji.HasEmoji(s));

    [Fact]
    public void Split_keeps_the_text_and_order()
    {
        var parts = ColorEmoji.Split("hi 👋 there ❤️!").ToList();
        Assert.Equal(["hi ", "👋", " there ", "❤️", "!"], parts.Select(p => p.Text));
        Assert.Equal([false, true, false, true, false], parts.Select(p => p.IsEmoji));
        Assert.Equal("hi 👋 there ❤️!", string.Concat(parts.Select(p => p.Text)));
    }

    [Theory]
    [InlineData("👍", true)]
    [InlineData("🎉 🔥", true)]
    [InlineData("👍👍👍", true)]
    [InlineData("👍👍👍👍", false)]
    [InlineData("ok 👍", false)]
    [InlineData("", false)]
    public void Jumbo_is_one_to_three_emoji_only(string s, bool jumbo) => Assert.Equal(jumbo, ColorEmoji.IsJumbo(s));

    [Fact]
    public void Windows_draws_emoji_in_colour()
    {
        Exception? error = null;
        var t = new Thread(() =>
        {
            try
            {
                var bmp = ColorEmoji.Bitmap("❤️");
                Assert.NotNull(bmp);
                var px = new byte[bmp.PixelWidth * bmp.PixelHeight * 4];
                bmp.CopyPixels(px, bmp.PixelWidth * 4, 0);
                // a colour glyph: some opaque pixel whose red clearly exceeds its green and blue (a flat outline is grey)
                var coloured = false;
                for (var i = 0; i < px.Length; i += 4)
                    if (px[i + 3] > 200 && px[i + 2] > px[i + 1] + 60 && px[i + 2] > px[i] + 60) { coloured = true; break; }
                Assert.True(coloured, "the heart came out without colour");
            }
            catch (Exception e) { error = e; }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join();
        if (error is not null) throw new Xunit.Sdk.XunitException(error.ToString());
    }
}
