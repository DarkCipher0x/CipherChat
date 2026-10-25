using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;

namespace CipherChat.Ui;

/// <summary>
/// A plain-text input that shows emoji in colour as you type, like the web chat. A WPF TextBox can only draw emoji as
/// flat outlines, so this is a RichTextBox holding plain text only: every emoji typed, pasted or picked is turned into
/// the colour picture from <see cref="ColorEmoji"/>, and <see cref="Text"/> gives the plain text back (each picture as
/// its emoji characters). Formatting commands and rich paste are refused; pasted text arrives as plain Unicode text.
/// </summary>
public class EmojiTextBox : RichTextBox
{
    private bool _busy;

    public int MaxLength { get; set; } = 8000;

    public EmojiTextBox()
    {
        AcceptsReturn = true;
        AcceptsTab = false;
        IsDocumentEnabled = true;
        Document = new FlowDocument(new Paragraph()) { PagePadding = new Thickness(0) };
        DataObject.AddPastingHandler(this, OnPasting);
        foreach (var c in new ICommand[] { EditingCommands.ToggleBold, EditingCommands.ToggleItalic, EditingCommands.ToggleUnderline,
                                           EditingCommands.IncreaseFontSize, EditingCommands.DecreaseFontSize, EditingCommands.ToggleBullets,
                                           EditingCommands.ToggleNumbering, EditingCommands.AlignCenter, EditingCommands.AlignRight,
                                           EditingCommands.AlignJustify, EditingCommands.IncreaseIndentation, EditingCommands.DecreaseIndentation })
            CommandBindings.Add(new CommandBinding(c, (_, e) => e.Handled = true, (_, e) => { e.CanExecute = false; e.Handled = true; }));
        CommandBindings.Add(new CommandBinding(ApplicationCommands.Copy, (_, e) => { CopySelection(); e.Handled = true; }));
        CommandBindings.Add(new CommandBinding(ApplicationCommands.Cut, (_, e) => { CopySelection(); Selection.Text = ""; e.Handled = true; }, (_, e) => { e.CanExecute = !Selection.IsEmpty; e.Handled = true; }));
    }

    /// <summary>The plain text: paragraphs and line breaks as "\n", emoji pictures as their characters.</summary>
    public string Text
    {
        get => PlainText(Document.ContentStart, Document.ContentEnd);
        set
        {
            _busy = true;
            try
            {
                var p = new Paragraph();
                p.Inlines.AddRange(ColorEmoji.Inlines(value ?? "").ToList());
                Document.Blocks.Clear();
                Document.Blocks.Add(p);
                CaretPosition = Document.ContentEnd;
            }
            finally { _busy = false; }
        }
    }

    public void Clear() => Text = "";

    /// <summary>Puts text (an emoji from the picker) at the caret, replacing any selection.</summary>
    public void InsertAtCaret(string s)
    {
        Selection.Text = "";
        CaretPosition.InsertTextInRun(s);
        Convert();
    }

    protected override void OnTextChanged(TextChangedEventArgs e)
    {
        base.OnTextChanged(e);
        if (!_busy) Convert();
    }

    // Turns emoji in the text runs into colour pictures, keeping the caret where it was in the plain text.
    private void Convert()
    {
        var runs = new List<Run>();
        foreach (var b in Document.Blocks.OfType<Paragraph>()) Collect(b.Inlines, runs);
        runs = runs.Where(r => ColorEmoji.HasEmoji(r.Text)).ToList();
        if (runs.Count == 0) return;
        _busy = true;
        try
        {
            var caret = PlainText(Document.ContentStart, CaretPosition).Length;
            BeginChange();
            foreach (var r in runs)
            {
                if (r.Parent is not Paragraph and not Span) continue;
                var siblings = r.Parent is Paragraph pp ? pp.Inlines : ((Span)r.Parent).Inlines;
                Inline anchor = r;
                foreach (var part in ColorEmoji.Inlines(r.Text).ToList())
                {
                    siblings.InsertAfter(anchor, part);
                    anchor = part;
                }
                siblings.Remove(r);
            }
            EndChange();
            CaretPosition = PointerAt(caret);
        }
        finally { _busy = false; }
    }

    private static void Collect(InlineCollection inlines, List<Run> into)
    {
        foreach (var i in inlines)
        {
            if (i is Run r) into.Add(r);
            else if (i is Span s) Collect(s.Inlines, into);
        }
    }

    private string PlainText(TextPointer from, TextPointer to)
    {
        var sb = new StringBuilder();
        var first = true;
        for (var p = from; p is not null && p.CompareTo(to) < 0; p = p.GetNextContextPosition(LogicalDirection.Forward))
        {
            switch (p.GetPointerContext(LogicalDirection.Forward))
            {
                case TextPointerContext.Text:
                    var run = p.GetTextInRun(LogicalDirection.Forward);
                    var max = p.GetOffsetToPosition(to);
                    sb.Append(run.Length > max ? run[..max] : run);
                    break;
                case TextPointerContext.EmbeddedElement:
                    if (p.GetAdjacentElement(LogicalDirection.Forward) is FrameworkElement { Tag: string t }) sb.Append(t);
                    break;
                case TextPointerContext.ElementStart:
                    var el = p.GetAdjacentElement(LogicalDirection.Forward);
                    if (el is LineBreak) sb.Append('\n');
                    else if (el is Paragraph) { if (!first) sb.Append('\n'); first = false; }
                    break;
            }
        }
        return sb.ToString();
    }

    // The position after the first n characters of the plain text.
    private TextPointer PointerAt(int n)
    {
        var count = 0;
        var first = true;
        for (var p = Document.ContentStart; p is not null; p = p.GetNextContextPosition(LogicalDirection.Forward))
        {
            switch (p.GetPointerContext(LogicalDirection.Forward))
            {
                case TextPointerContext.Text:
                    var len = p.GetTextRunLength(LogicalDirection.Forward);
                    if (count + len >= n) return p.GetPositionAtOffset(n - count) ?? p;
                    count += len;
                    break;
                case TextPointerContext.EmbeddedElement:
                    if (p.GetAdjacentElement(LogicalDirection.Forward) is FrameworkElement { Tag: string t })
                    {
                        if (count + t.Length > n) return p;
                        count += t.Length;
                    }
                    break;
                case TextPointerContext.ElementStart:
                    var el = p.GetAdjacentElement(LogicalDirection.Forward);
                    if (el is LineBreak || (el is Paragraph && !first)) { if (count >= n) return p; count++; }
                    if (el is Paragraph) first = false;
                    break;
                case TextPointerContext.None:
                    return Document.ContentEnd;
            }
        }
        return Document.ContentEnd;
    }

    private void CopySelection()
    {
        if (Selection.IsEmpty) return;
        Clipboard.SetText(PlainText(Selection.Start, Selection.End));
    }

    // Paste and drop: plain Unicode text only (no RTF, HTML or pictures inside the text); a paste that would pass the
    // length limit is refused. Attachments are handled by the chat before this runs.
    private void OnPasting(object sender, DataObjectPastingEventArgs e)
    {
        if (!e.SourceDataObject.GetDataPresent(DataFormats.UnicodeText, true)) { e.CancelCommand(); return; }
        var t = e.SourceDataObject.GetData(DataFormats.UnicodeText, true) as string ?? "";
        if (Text.Length + t.Length > MaxLength) { e.CancelCommand(); return; }
        e.DataObject = new DataObject(DataFormats.UnicodeText, t);
        e.FormatToApply = DataFormats.UnicodeText;
    }

    protected override void OnPreviewTextInput(TextCompositionEventArgs e)
    {
        if (Text.Length + e.Text.Length > MaxLength) { e.Handled = true; return; }
        base.OnPreviewTextInput(e);
    }
}
