using System.IO;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;

namespace CipherChat.App.Shell;

/// <summary>
/// Animated GIFs for WPF, which on its own shows only a GIF's first frame. The frames are decoded with Windows' own GIF
/// decoder, composed the way browsers do (each frame drawn at its offset over the previous picture, honouring the
/// "restore to background" and "restore to previous" disposal modes) and played on the Image, looping. Everything is in
/// memory; nothing is written to disk.
/// </summary>
public static class GifPlayer
{
    private const long MaxPixels = 24_000_000;             // all frames together (about 96 MB of pixels); bigger stays still

    /// <summary>Plays the GIF on the Image; false (and the Image unchanged) when it isn't an animated GIF we can show.</summary>
    public static bool Play(Image img, byte[] bytes)
    {
        var frames = Compose(bytes, out var delays);
        if (frames is null) return false;
        var anim = new ObjectAnimationUsingKeyFrames { RepeatBehavior = RepeatBehavior.Forever };
        var t = TimeSpan.Zero;
        for (var i = 0; i < frames.Count; i++)
        {
            anim.KeyFrames.Add(new DiscreteObjectKeyFrame(frames[i], KeyTime.FromTimeSpan(t)));
            t += delays[i];
        }
        anim.Duration = t;
        anim.Freeze();
        img.Source = frames[0];
        img.BeginAnimation(Image.SourceProperty, anim);
        return true;
    }

    /// <summary>The first frame, for still previews (the GIF picker).</summary>
    public static BitmapSource? Still(byte[] bytes, int width)
    {
        try
        {
            var bmp = new BitmapImage();
            bmp.BeginInit();
            bmp.CacheOption = BitmapCacheOption.OnLoad;
            bmp.DecodePixelWidth = width;
            bmp.StreamSource = new MemoryStream(bytes, writable: false);
            bmp.EndInit();
            bmp.Freeze();
            return bmp;
        }
        catch (Exception e) when (e is NotSupportedException or FileFormatException or ArgumentException or InvalidOperationException) { return null; }
    }

    private static List<BitmapSource>? Compose(byte[] bytes, out List<TimeSpan> delays)
    {
        delays = [];
        GifBitmapDecoder dec;
        try { dec = new GifBitmapDecoder(new MemoryStream(bytes, writable: false), BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad); }
        catch (Exception e) when (e is NotSupportedException or FileFormatException or ArgumentException) { return null; }
        if (dec.Frames.Count < 2) return null;
        int w = Query<ushort>(dec.Metadata, "/logscrdesc/Width") is var lw and > 0 ? lw : dec.Frames[0].PixelWidth;
        int h = Query<ushort>(dec.Metadata, "/logscrdesc/Height") is var lh and > 0 ? lh : dec.Frames[0].PixelHeight;
        if (w <= 0 || h <= 0 || (long)w * h * dec.Frames.Count > MaxPixels) return null;

        var result = new List<BitmapSource>(dec.Frames.Count);
        BitmapSource? current = null;          // the composed picture so far
        foreach (var f in dec.Frames)
        {
            var before = current;                                                               // for "restore to previous"
            var md = f.Metadata as BitmapMetadata;
            var left = Query<ushort>(md, "/imgdesc/Left");
            var top = Query<ushort>(md, "/imgdesc/Top");
            var delay = Query<ushort>(md, "/grctlext/Delay");
            var disposal = Query<byte>(md, "/grctlext/Disposal");
            var rect = new System.Windows.Rect(left, top, f.PixelWidth, f.PixelHeight);

            var v = new DrawingVisual();
            using (var dc = v.RenderOpen())
            {
                dc.DrawRectangle(Brushes.Transparent, null, new System.Windows.Rect(0, 0, w, h));     // keep the full size
                if (current is not null) dc.DrawImage(current, new System.Windows.Rect(0, 0, w, h));
                dc.DrawImage(f, rect);
            }
            var frame = Render(v, w, h);
            result.Add(frame);
            delays.Add(TimeSpan.FromMilliseconds(delay < 2 ? 100 : delay * 10));            // like browsers: tiny delays mean 100 ms

            // what the next frame is drawn over
            switch (disposal)
            {
                case 2:                                                                         // restore to background: clear this frame's area
                    var c = new DrawingVisual();
                    using (var dc = c.RenderOpen())
                    {
                        dc.DrawRectangle(Brushes.Transparent, null, new System.Windows.Rect(0, 0, w, h));
                        dc.PushClip(new CombinedGeometry(GeometryCombineMode.Exclude, new RectangleGeometry(new System.Windows.Rect(0, 0, w, h)), new RectangleGeometry(rect)));
                        dc.DrawImage(frame, new System.Windows.Rect(0, 0, w, h));
                        dc.Pop();
                    }
                    current = Render(c, w, h);
                    break;
                case 3:                                                                         // restore to previous
                    current = before;
                    break;
                default:
                    current = frame;
                    break;
            }
        }
        return result;
    }

    private static BitmapSource Render(Visual v, int w, int h)
    {
        var rtb = new RenderTargetBitmap(w, h, 96, 96, PixelFormats.Pbgra32);
        rtb.Render(v);
        rtb.Freeze();
        return rtb;
    }

    private static T Query<T>(ImageMetadata? md, string path) where T : struct
    {
        try { return md is BitmapMetadata b && b.GetQuery(path) is T v ? v : default; }
        catch (Exception e) when (e is NotSupportedException or ArgumentException or InvalidOperationException) { return default; }
    }
}
